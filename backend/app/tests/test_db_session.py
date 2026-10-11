from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.exc import IntegrityError

from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.repositories.capture_repository import CaptureRepository


def test_create_and_query_capture_session(db_session):
    session_id = uuid.uuid4()
    session_obj = CaptureSession(
        id=session_id,
        interface_id="Wi-Fi",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.RUNNING.value,
        started_at=datetime.now(timezone.utc),
        packets_seen=100,
        packets_enqueued=95,
        packets_dropped=5,
    )
    created = CaptureRepository.create(db_session, session_obj)
    assert created.id == session_id
    assert created.interface_id == "Wi-Fi"
    assert created.packets_seen == 100

    fetched = CaptureRepository.get_by_id(db_session, session_id)
    assert fetched is not None
    assert fetched.packets_dropped == 5

    # Test completing session
    completed = CaptureRepository.complete_session(
        db=db_session,
        session_id=session_id,
        status=CaptureStatus.STOPPED,
        stats={
            "packets_seen": 250,
            "packets_enqueued": 240,
            "packets_dropped": 10,
        },
    )
    assert completed is not None
    assert completed.status == CaptureStatus.STOPPED.value
    assert completed.stopped_at is not None
    assert completed.packets_seen == 250
    assert completed.packets_enqueued == 240
    assert completed.packets_dropped == 10


def test_invalid_session_mode_check_constraint(db_session):
    invalid_session = CaptureSession(
        id=uuid.uuid4(),
        interface_id="Ethernet",
        session_mode="INVALID_MODE",
        status=CaptureStatus.RUNNING.value,
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(invalid_session)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_invalid_status_check_constraint(db_session):
    invalid_session = CaptureSession(
        id=uuid.uuid4(),
        interface_id="Ethernet",
        session_mode=SessionMode.BASELINE.value,
        status="INVALID_STATUS",
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(invalid_session)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
