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

from sqlalchemy import and_, or_, select, text
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
            if not self._is_running:
                return
            self._is_running = False
            self._stop_event.set()

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)

        with self._lock:
            self._worker_thread = None
        logger.info("DetectionWorker background thread stopped.")

    def reclaim_stuck_jobs(self, db: Session, timeout_seconds: Optional[int] = None) -> int:
        """
        Reclaims jobs stranded in 'PROCESSING' state from previous process crashes or ungraceful exits.
        Resets them to 'PENDING'.
        """
        timeout = timeout_seconds or self.stuck_timeout_seconds
        stuck_cutoff = datetime.now(timezone.utc) - timedelta(seconds=timeout)

        stuck_stmt = (
            select(DetectionJob)
            .where(
                and_(
                    DetectionJob.status == DetectionJobStatus.PROCESSING.value,
                    DetectionJob.started_at <= stuck_cutoff,
                )
            )
        )
        stuck_jobs = list(db.execute(stuck_stmt).scalars().all())
        for job in stuck_jobs:
            job.status = DetectionJobStatus.PENDING.value
            job.started_at = None
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
                    DetectionJob.status == DetectionJobStatus.PENDING.value,
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

        now = datetime.now(timezone.utc)
        try:
            from app.services.detection_service import DetectionService

            # Evaluate flow (runs ML inference, behavioral rules, and alert deduplication)
            DetectionService.predict_flow(db=db, flow_id=job.flow_id)

            job.status = DetectionJobStatus.COMPLETED.value
            job.completed_at = now
            job.error_message = None
            db.commit()
            with self._lock:
                self._total_processed += 1
            return True

        except Exception as exc:
            db.rollback()
            # Fetch fresh job instance after rollback
            job = db.execute(select(DetectionJob).where(DetectionJob.id == job_id)).scalar_one_or_none()
            if job:
                job.retry_count += 1
                job.error_message = str(exc)[:1000]
                if job.retry_count >= job.max_retries:
                    job.status = DetectionJobStatus.FAILED.value
                else:
                    job.status = DetectionJobStatus.FAILED.value
                    backoff = 2 ** job.retry_count
                    job.scheduled_at = now + timedelta(seconds=backoff)
                db.commit()

            with self._lock:
                self._total_errors += 1
            logger.error(f"Error processing detection job {job_id} (flow {job.flow_id if job else 'unknown'}): {exc}")
            return False

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
                    for job_id in claimed_ids:
                        if self._stop_event.is_set():
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
