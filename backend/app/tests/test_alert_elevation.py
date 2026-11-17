from datetime import datetime, timezone
import uuid
import pytest
from sqlalchemy.orm import Session

from app.models.detection import (
    Alert,
    AlertSeverity,
    AlertStatus,
    DetectionSource,
    PredictionStatus,
)
from app.models.flow_record import FlowRecord
from app.rules.rule_engine import RuleFinding
from app.services.alert_service import AlertService


def test_alert_severity_elevation(db_session: Session):
    flow = FlowRecord(
        id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        dst_port=80,
        protocol="TCP",
    )

    # 1. First event: Low severity rule finding
    finding_low = RuleFinding(
        rule_id="RULE_TEST",
        title="Test Alert Initial",
        description="Initial low finding",
        severity=AlertSeverity.LOW,
        evidence={"sample": 1},
    )
    alerts1 = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=0.1,
        model_version="v1",
        rule_findings=[finding_low],
    )
    assert len(alerts1) == 1
    alert_obj = alerts1[0]
    assert alert_obj.severity == AlertSeverity.LOW.value
    assert alert_obj.occurrence_count == 1

    # 2. Second event: Higher severity rule finding for same fingerprint
    finding_high = RuleFinding(
        rule_id="RULE_TEST",
        title="Test Alert Elevated",
        description="Elevated high finding",
        severity=AlertSeverity.HIGH,
        evidence={"sample": 2, "extra": "info"},
    )
    alerts2 = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=0.1,
        model_version="v1",
        rule_findings=[finding_high],
    )
    assert len(alerts2) == 1
    elevated = alerts2[0]
    assert elevated.id == alert_obj.id
    assert elevated.severity == AlertSeverity.HIGH.value
    assert elevated.occurrence_count == 2
    assert elevated.rule_evidence["sample"] == 2
    assert elevated.rule_evidence["extra"] == "info"

    # 3. Third event: Weaker (MEDIUM) severity finding arrives -> DO NOT DOWNGRADE!
    finding_med = RuleFinding(
        rule_id="RULE_TEST",
        title="Test Alert Weaker",
        description="Weaker finding",
        severity=AlertSeverity.MEDIUM,
        evidence={"sample": 3},
    )
    alerts3 = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=0.1,
        model_version="v1",
        rule_findings=[finding_med],
    )
    assert len(alerts3) == 1
    not_downgraded = alerts3[0]
    assert not_downgraded.id == alert_obj.id
    # Must remain HIGH!
    assert not_downgraded.severity == AlertSeverity.HIGH.value
    assert not_downgraded.occurrence_count == 3


def test_alert_lifecycle_status_transitions(db_session: Session):
    flow = FlowRecord(
        id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        src_ip="192.168.1.10",
        dst_ip="10.0.0.5",
        dst_port=443,
        protocol="TCP",
    )
    finding = RuleFinding(
        rule_id="RULE_TEST_LIFECYCLE",
        title="Lifecycle Alert",
        description="Testing lifecycle transitions",
        severity=AlertSeverity.MEDIUM,
    )
    alerts = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=0.0,
        model_version="v1",
        rule_findings=[finding],
    )
    alert = alerts[0]
    assert alert.status == AlertStatus.OPEN.value
    assert alert.resolved_at is None

    # Transition to ACKNOWLEDGED
    ack_alert = AlertService.update_alert_status(
        db=db_session,
        alert_id=alert.id,
        target_status=AlertStatus.ACKNOWLEDGED.value,
        notes="Analyst investigating",
    )
    assert ack_alert.status == AlertStatus.ACKNOWLEDGED.value
    assert ack_alert.resolved_at is None
    assert ack_alert.rule_evidence.get("analyst_notes") == "Analyst investigating"

    # Transition to FALSE_POSITIVE
    fp_alert = AlertService.update_alert_status(
        db=db_session,
        alert_id=alert.id,
        target_status=AlertStatus.FALSE_POSITIVE.value,
        notes="Legitimate network backup traffic",
    )
    assert fp_alert.status == AlertStatus.FALSE_POSITIVE.value
    assert fp_alert.resolved_at is not None

    # Invalid status raises ValueError
    with pytest.raises(ValueError):
        AlertService.update_alert_status(
            db=db_session,
            alert_id=alert.id,
            target_status="INVALID_STATUS",
        )
