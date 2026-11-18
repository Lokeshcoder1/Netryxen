"""
Background worker service for asynchronous flow detection and alert evaluation.
Consumes scheduled jobs from the transactional outbox (`detection_jobs` table),
claims them safely (with SKIP LOCKED on PostgreSQL), and runs DetectionService.
"""
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from sqlalchemy import and_, or_, select, text, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import logger
from app.models.detection import DetectionJob, DetectionJobStatus


class DetectionWorker:
    """
    Background worker that continuously claims and processes pending detection jobs.
    Uses independent DB sessions per batch to ensure strict isolation from request threads.
    """

    def __init__(
        self,
        interval_seconds: float = 1.0,
        batch_size: int = 50,
        max_retries: int = 3,
        stuck_timeout_seconds: int = 300,
        session_factory: Optional[Callable[[], Session]] = None,
    ) -> None:
        self.interval_seconds = interval_seconds
        self.batch_size = batch_size
        self.max_retries = max_retries
        self.stuck_timeout_seconds = stuck_timeout_seconds
        self._session_factory = session_factory

        self._lock = threading.Lock()
        self.worker_id = f"detection-worker-{uuid.uuid4().hex}"
        self._is_running: bool = False
        self._stop_event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # Observability metrics
        self._total_processed: int = 0
        self._total_errors: int = 0
        self._last_run_at: Optional[datetime] = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def _get_db(self) -> Session:
        if self._session_factory:
            return self._session_factory()
        from app.db.session import SessionLocal
        return SessionLocal()

    def start(self) -> None:
        """Starts the background worker thread."""
        with self._lock:
            if self._is_running:
                return
            self._is_running = True
            self._stop_event.clear()
            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="DetectionWorker",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info("DetectionWorker background thread started.")

    def stop(self, timeout: float = 10.0) -> None:
        """Gracefully stops the worker thread, waiting for in-flight jobs to complete."""
        with self._lock:
            worker_thread = self._worker_thread
            if not self._is_running and worker_thread is None:
                return
            self._is_running = False
            self._stop_event.set()

        if worker_thread and worker_thread.is_alive():
            worker_thread.join(timeout=timeout)
        with self._lock:
            terminated = worker_thread is None or not worker_thread.is_alive()
            if terminated:
                self._worker_thread = None
        if terminated:
            logger.info("DetectionWorker background thread stopped.")
        else:
            logger.error("DetectionWorker thread did not terminate within the shutdown timeout.")
            raise RuntimeError("DetectionWorker shutdown timeout")

    def reclaim_stuck_jobs(self, db: Session, timeout_seconds: Optional[int] = None) -> int:
        """
        Reclaims jobs stranded in 'PROCESSING' state from previous process crashes or ungraceful exits.
        Resets them to 'PENDING'.
        """
        timeout = timeout_seconds or self.stuck_timeout_seconds
        now = datetime.now(timezone.utc)
        stuck_cutoff = now - timedelta(seconds=timeout)

        stuck_stmt = (
            select(DetectionJob)
            .where(
                and_(
                    DetectionJob.status == DetectionJobStatus.PROCESSING.value,
                    or_(
                        DetectionJob.lease_expires_at <= now,
                        and_(
                            DetectionJob.lease_expires_at.is_(None),
                            or_(
                                DetectionJob.started_at.is_(None),
                                DetectionJob.started_at <= stuck_cutoff,
                            ),
                        ),
                    ),
                )
            )
            .with_for_update(skip_locked=True)
        )
        stuck_jobs = list(db.execute(stuck_stmt).scalars().all())
        for job in stuck_jobs:
            job.status = DetectionJobStatus.PENDING.value
            job.started_at = None
            job.worker_id = None
            job.heartbeat_at = None
            job.lease_expires_at = None
            job.error_message = "Reclaimed from stuck PROCESSING state."
        if stuck_jobs:
            db.commit()
            logger.warning(f"DetectionWorker reclaimed {len(stuck_jobs)} stuck jobs.")
        return len(stuck_jobs)

    def _claim_batch(self, db: Session) -> List[uuid.UUID]:
        """
        Claims up to batch_size eligible jobs atomically.
        Uses SELECT FOR UPDATE SKIP LOCKED on PostgreSQL, or standard locking on SQLite.
        """
        now = datetime.now(timezone.utc)
        dialect = db.bind.dialect.name if db.bind else "sqlite"

        base_query = (
            select(DetectionJob)
            .where(
                or_(
                    and_(
                        DetectionJob.status == DetectionJobStatus.PENDING.value,
                        DetectionJob.scheduled_at <= now,
                    ),
                    and_(
                        DetectionJob.status == DetectionJobStatus.FAILED.value,
                        DetectionJob.retry_count < DetectionJob.max_retries,
                        DetectionJob.scheduled_at <= now,
                    ),
                )
            )
            .order_by(DetectionJob.scheduled_at.asc(), DetectionJob.created_at.asc())
            .limit(self.batch_size)
        )

        if dialect == "postgresql":
            # Concurrency-safe atomic claim without lock blocking
            query = base_query.with_for_update(skip_locked=True)
        else:
            query = base_query

        jobs = list(db.execute(query).scalars().all())
        claimed_ids: List[uuid.UUID] = []

        for job in jobs:
            job.status = DetectionJobStatus.PROCESSING.value
            job.started_at = now
            if job.max_retries != self.max_retries:
                job.max_retries = self.max_retries
            job.worker_id = self.worker_id
            job.heartbeat_at = now
            job.lease_expires_at = now + timedelta(seconds=self.stuck_timeout_seconds)
            claimed_ids.append(job.id)

        if claimed_ids:
            db.commit()

        return claimed_ids

    def process_job(self, db: Session, job_id: uuid.UUID) -> bool:
        """
        Executes ML detection and rule evaluation for a single claimed job.
        Handles idempotency: if prediction already exists, completes immediately.
        """
        job = db.execute(select(DetectionJob).where(DetectionJob.id == job_id)).scalar_one_or_none()
        if not job:
            return False
        if job.status == DetectionJobStatus.COMPLETED.value:
            return True
        now = datetime.now(timezone.utc)
        if job.status != DetectionJobStatus.PROCESSING.value or job.worker_id != self.worker_id:
            return False
        lease = job.lease_expires_at
        if lease is not None and lease.tzinfo is None:
            lease = lease.replace(tzinfo=timezone.utc)
        if lease is not None and lease <= datetime.now(timezone.utc):
            return False

        heartbeat = self._start_heartbeat(db, job_id)
        try:
            from app.services.detection_service import DetectionService

            # Evaluate flow (runs ML inference, behavioral rules, and alert deduplication)
            DetectionService.predict_flow(db=db, flow_id=job.flow_id)
            self._stop_heartbeat(heartbeat)
            owned = db.execute(
                update(DetectionJob)
                .where(
                    DetectionJob.id == job_id,
                    DetectionJob.status == DetectionJobStatus.PROCESSING.value,
                    DetectionJob.worker_id == self.worker_id,
                )
                .values(
                    status=DetectionJobStatus.COMPLETED.value,
                    completed_at=now,
                    error_message=None,
                    worker_id=None,
                    heartbeat_at=now,
                    lease_expires_at=None,
                )
            )
            if owned.rowcount != 1:
                raise RuntimeError(f"Detection job {job_id} is no longer owned by this worker")
            db.commit()
            with self._lock:
                self._total_processed += 1
            return True

        except Exception as exc:
            self._stop_heartbeat(heartbeat)
            db.rollback()
            job = db.execute(select(DetectionJob).where(DetectionJob.id == job_id)).scalar_one_or_none()
            if job:
                if job.worker_id not in (None, self.worker_id):
                    return False
                job.worker_id = self.worker_id
                job.retry_count += 1
                job.error_message = str(exc)[:1000]
                job.status = DetectionJobStatus.FAILED.value
                job.worker_id = None
                job.heartbeat_at = None
                job.lease_expires_at = None
                if job.retry_count < job.max_retries:
                    job.scheduled_at = now + timedelta(seconds=2 ** job.retry_count)
                db.commit()

            with self._lock:
                self._total_errors += 1
            logger.error(
                f"Error processing detection job {job_id} "
                f"(flow {job.flow_id if job else 'unknown'}): {exc}"
            )
            return False

    def _start_heartbeat(
        self,
        db: Session,
        job_id: uuid.UUID,
    ) -> Optional[tuple[threading.Event, threading.Thread]]:
        probe = self._get_db()
        if probe is db:
            return None
        probe.close()
        stop_event = threading.Event()
        thread = threading.Thread(
            target=self._heartbeat_loop,
            args=(job_id, stop_event),
            name=f"DetectionHeartbeat-{job_id}",
            daemon=True,
        )
        thread.start()
        return stop_event, thread

    def _heartbeat_loop(self, job_id: uuid.UUID, stop_event: threading.Event) -> None:
        interval = max(1.0, self.stuck_timeout_seconds / 3)
        while not stop_event.wait(interval):
            db = self._get_db()
            now = datetime.now(timezone.utc)
            try:
                result = db.execute(
                    update(DetectionJob)
                    .where(
                        DetectionJob.id == job_id,
                        DetectionJob.status == DetectionJobStatus.PROCESSING.value,
                        DetectionJob.worker_id == self.worker_id,
                    )
                    .values(
                        heartbeat_at=now,
                        lease_expires_at=now + timedelta(seconds=self.stuck_timeout_seconds),
                    )
                )
                db.commit()
                if result.rowcount != 1:
                    logger.warning(f"DetectionWorker lost ownership of job {job_id}.")
                    return
            except Exception as exc:
                db.rollback()
                logger.warning(f"Could not renew lease for detection job {job_id}: {exc}")
            finally:
                db.close()

    @staticmethod
    def _stop_heartbeat(
        heartbeat: Optional[tuple[threading.Event, threading.Thread]],
    ) -> None:
        if heartbeat:
            stop_event, thread = heartbeat
            stop_event.set()
            thread.join(timeout=2.0)

    def _worker_loop(self) -> None:
        """Main continuous background processing loop."""
        # Clean up any leftover stuck jobs on startup
        try:
            db = self._get_db()
            try:
                self.reclaim_stuck_jobs(db)
            finally:
                db.close()
        except Exception as exc:
            logger.warning(f"Error reclaiming stuck jobs on startup: {exc}")

        last_stuck_check = time.monotonic()

        while not self._stop_event.is_set():
            processed_count = 0
            try:
                db = self._get_db()
                try:
                    # Periodically check for stuck jobs every 60 seconds
                    now_mono = time.monotonic()
                    if now_mono - last_stuck_check >= 60.0:
                        last_stuck_check = now_mono
                        self.reclaim_stuck_jobs(db)

                    claimed_ids = self._claim_batch(db)
                    for index, job_id in enumerate(claimed_ids):
                        if self._stop_event.is_set():
                            self._release_claimed_jobs(db, claimed_ids[index:])
                            break
                        self.process_job(db, job_id)
                        processed_count += 1

                    with self._lock:
                        self._last_run_at = datetime.now(timezone.utc)
                finally:
                    db.close()

            except Exception as exc:
                with self._lock:
                    self._total_errors += 1
                logger.error(f"DetectionWorker loop error: {exc}")

            # If no jobs were ready, sleep until interval or stop signal
            if processed_count == 0:
                self._stop_event.wait(timeout=self.interval_seconds)

    def _release_claimed_jobs(self, db: Session, job_ids: List[uuid.UUID]) -> None:
        if not job_ids:
            return
        jobs = list(
            db.execute(
                select(DetectionJob).where(
                    DetectionJob.id.in_(job_ids),
                    DetectionJob.status == DetectionJobStatus.PROCESSING.value,
                    DetectionJob.worker_id == self.worker_id,
                )
            ).scalars()
        )
        for job in jobs:
            job.status = DetectionJobStatus.PENDING.value
            job.started_at = None
            job.worker_id = None
            job.heartbeat_at = None
            job.lease_expires_at = None
        if jobs:
            db.commit()

    def get_stats(self) -> Dict[str, Any]:
        """Returns runtime statistics of the worker."""
        with self._lock:
            return {
                "is_running": self._is_running,
                "total_processed": self._total_processed,
                "total_errors": self._total_errors,
                "last_run_at": self._last_run_at.isoformat() if self._last_run_at else None,
            }


# Global singleton instance
detection_worker = DetectionWorker(
    interval_seconds=settings.DETECTION_WORKER_INTERVAL_SECONDS,
    batch_size=settings.DETECTION_WORKER_BATCH_SIZE,
    max_retries=settings.DETECTION_WORKER_MAX_RETRIES,
    stuck_timeout_seconds=settings.DETECTION_JOB_STUCK_TIMEOUT_SECONDS,
)
