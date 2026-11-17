from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy.orm import Session

from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.detection import DetectionJob, DetectionJobStatus, Prediction
from app.models.flow_record import FlowRecord
from app.repositories.flow_repository import FlowRepository
from app.services.detection_worker import DetectionWorker


def test_outbox_job_creation_on_flow_insert(db_session: Session):
    session_id = uuid.uuid4()
    cap = CaptureSession(
        id=session_id,
        interface_id="eth0",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.STOPPED.value,
    )
    db_session.add(cap)
    db_session.commit()

    now = datetime.now(timezone.utc)
    flow = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_id,
        window_start=now,
        window_end=now + timedelta(seconds=10),
        flow_key="TCP:192.168.1.1:1234<->192.168.1.2:80",
        src_ip="192.168.1.1",
        dst_ip="192.168.1.2",
        src_port=1234,
        dst_port=80,
        protocol="TCP",
        packet_count=10,
        byte_count=1500,
        fwd_packets=5,
        rev_packets=5,
        fwd_bytes=750,
        rev_bytes=750,
        first_seen=now,
        last_seen=now + timedelta(seconds=5),
        duration_seconds=5.0,
        features={"packet_count": 10},
    )

    count = FlowRepository.create_batch(db_session, [flow], create_jobs=True)
    assert count == 1

    # Check job in detection_jobs table
    job = db_session.query(DetectionJob).filter(DetectionJob.flow_id == flow.id).one()
    assert job.status == DetectionJobStatus.PENDING.value
    assert job.retry_count == 0
    assert job.max_retries == 3


def test_detection_worker_process_single_job(db_session: Session):
    session_id = uuid.uuid4()
    cap = CaptureSession(
        id=session_id,
        interface_id="eth0",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.STOPPED.value,
    )
    db_session.add(cap)
    db_session.commit()

    now = datetime.now(timezone.utc)
    flow = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_id,
        window_start=now,
        window_end=now + timedelta(seconds=10),
        flow_key="TCP:10.0.0.1:5000<->10.0.0.2:443",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=5000,
        dst_port=443,
        protocol="TCP",
        packet_count=20,
        byte_count=2000,
        first_seen=now,
        last_seen=now + timedelta(seconds=2),
        duration_seconds=2.0,
        features={},
    )
    FlowRepository.create_batch(db_session, [flow], create_jobs=True)
    job = db_session.query(DetectionJob).filter(DetectionJob.flow_id == flow.id).one()

    worker = DetectionWorker(session_factory=lambda: db_session)
    success = worker.process_job(db_session, job.id)
    assert success is True

    db_session.refresh(job)
    assert job.status == DetectionJobStatus.COMPLETED.value
    assert job.completed_at is not None
    assert job.error_message is None

    # Idempotent re-run
    success_rerun = worker.process_job(db_session, job.id)
    assert success_rerun is True
    assert job.status == DetectionJobStatus.COMPLETED.value


def test_detection_worker_retry_and_failure(db_session: Session):
    # Job pointing to nonexistent flow_id will fail
    fake_flow_id = uuid.uuid4()
    job = DetectionJob(
        id=uuid.uuid4(),
        flow_id=fake_flow_id,
        status=DetectionJobStatus.PENDING.value,
        max_retries=2,
        retry_count=0,
    )
    db_session.add(job)
    db_session.commit()

    worker = DetectionWorker(session_factory=lambda: db_session)

    # First attempt -> fail, retry_count becomes 1
    success = worker.process_job(db_session, job.id)
    assert success is False
    db_session.refresh(job)
    assert job.retry_count == 1
    assert job.status == DetectionJobStatus.FAILED.value
    assert job.error_message is not None

    # Second attempt -> fail, retry_count becomes 2 == max_retries -> terminal FAILED
    success = worker.process_job(db_session, job.id)
    assert success is False
    db_session.refresh(job)
    assert job.retry_count == 2
    assert job.status == DetectionJobStatus.FAILED.value


def test_detection_worker_reclaim_stuck_jobs(db_session: Session):
    stuck_time = datetime.now(timezone.utc) - timedelta(seconds=600)
    job = DetectionJob(
        id=uuid.uuid4(),
        flow_id=uuid.uuid4(),
        status=DetectionJobStatus.PROCESSING.value,
        started_at=stuck_time,
    )
    db_session.add(job)
    db_session.commit()

    worker = DetectionWorker(stuck_timeout_seconds=300)
    reclaimed = worker.reclaim_stuck_jobs(db_session, timeout_seconds=300)
    assert reclaimed == 1

    db_session.refresh(job)
    assert job.status == DetectionJobStatus.PENDING.value
    assert job.started_at is None
