from datetime import datetime, timedelta, timezone
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
from app.services.alert_service import AlertService, generate_alert_fingerprint


def make_test_flow(
    src_ip: str = "192.168.1.50",
    dst_ip: str = "93.184.216.34",
    dst_port: int = 443,
    protocol: str = "TCP",
) -> FlowRecord:
    now = datetime.now(timezone.utc)
    return FlowRecord(
        id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        window_start=now,
        window_end=now,
        flow_key=f"{protocol}:{src_ip}:50000<->{dst_ip}:{dst_port}",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=50000,
        dst_port=dst_port,
        protocol=protocol,
        protocol_num=6,
        first_seen=now,
        last_seen=now,
        duration_seconds=1.0,
        packet_count=10,
        byte_count=1000,
        fwd_packets=5,
        rev_packets=5,
        fwd_bytes=500,
        rev_bytes=500,
        packets_per_second=10.0,
        bytes_per_second=1000.0,
        min_packet_size=60,
        max_packet_size=150,
        avg_packet_size=100.0,
        tcp_syn_count=1,
        tcp_ack_count=9,
        tcp_fin_count=0,
        tcp_rst_count=0,
        tcp_psh_count=0,
        dns_query_count=0,
        dns_unique_query_count=0,
        upload_bytes=500,
        download_bytes=500,
        upload_ratio=0.5,
        is_local=True,
        is_broadcast=False,
        is_multicast=False,
        features={},
        feature_schema_version="1.0",
    )


def test_alert_policy_no_alert_when_normal(db_session: Session):
    flow = make_test_flow()
    alerts = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=0.15,
        model_version="v1",
        rule_findings=[],
    )
    assert len(alerts) == 0


def test_alert_policy_ml_anomaly_only(db_session: Session):
    flow = make_test_flow()
    # Mild negative score -> LOW
    alerts_low = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.ANOMALY,
        ml_score=-0.08,
        model_version="v1",
        rule_findings=[],
    )
    assert len(alerts_low) == 1
    assert alerts_low[0].detection_source == DetectionSource.ML.value
    assert alerts_low[0].severity == AlertSeverity.LOW.value

    # Strongly negative score -> MEDIUM
    flow2 = make_test_flow(src_ip="192.168.1.99")
    alerts_med = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow2,
        ml_status=PredictionStatus.ANOMALY,
        ml_score=-0.25,
        model_version="v1",
        rule_findings=[],
    )
    assert len(alerts_med) == 1
    assert alerts_med[0].severity == AlertSeverity.MEDIUM.value


def test_alert_policy_rule_only(db_session: Session):
    flow = make_test_flow()
    finding = RuleFinding(
        rule_id="RULE_SYN_HEAVY",
        title="SYN Heavy Test",
        description="Testing rule only",
        severity=AlertSeverity.MEDIUM,
        evidence={"syn": 20},
    )
    alerts = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=0.1,
        model_version=None,
        rule_findings=[finding],
    )
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detection_source == DetectionSource.RULE.value
    assert alert.severity == AlertSeverity.MEDIUM.value
    assert alert.rule_id == "RULE_SYN_HEAVY"


def test_alert_policy_corroborated_elevation(db_session: Session):
    flow = make_test_flow()
    finding = RuleFinding(
        rule_id="RULE_PORT_SCAN",
        title="Port Scan Test",
        description="Testing combined alert",
        severity=AlertSeverity.HIGH,
        evidence={"ports": 15},
    )
    # Both ML anomaly AND Rule trigger -> elevated severity HIGH -> CRITICAL
    alerts = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.ANOMALY,
        ml_score=-0.22,
        model_version="v1.0",
        rule_findings=[finding],
    )
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.detection_source == DetectionSource.COMBINED.value
    assert alert.severity == AlertSeverity.CRITICAL.value
    assert "Corroborated Anomaly" in alert.title


def test_alert_deduplication_and_cooldown(db_session: Session):
    flow = make_test_flow(src_ip="10.0.0.5", dst_ip="1.1.1.1", dst_port=53)
    finding = RuleFinding(
        rule_id="RULE_HIGH_DNS",
        title="High DNS",
        description="High DNS test",
        severity=AlertSeverity.MEDIUM,
        evidence={},
    )

    # 1. First trigger -> creates alert with occurrence_count = 1
    alerts1 = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=None,
        model_version=None,
        rule_findings=[finding],
        cooldown_seconds=300,
    )
    assert len(alerts1) == 1
    alert1 = alerts1[0]
    assert alert1.occurrence_count == 1
    first_seen = alert1.first_seen

    # 2. Immediate second trigger (same flow & rule) within cooldown
    # -> updates existing alert occurrence_count to 2, does NOT insert a new row!
    alerts2 = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=None,
        model_version=None,
        rule_findings=[finding],
        cooldown_seconds=300,
    )
    assert len(alerts2) == 1
    assert alerts2[0].id == alert1.id
    assert alerts2[0].occurrence_count == 2
    assert alerts2[0].first_seen == first_seen

    # Total alerts in DB should still be exactly 1!
    count = db_session.query(Alert).count()
    assert count == 1


def test_alert_resolution(db_session: Session):
    flow = make_test_flow()
    finding = RuleFinding(
        rule_id="RULE_UNCOMMON_PORT",
        title="Uncommon Port",
        description="Port test",
        severity=AlertSeverity.MEDIUM,
        evidence={},
    )
    alerts = AlertService.evaluate_and_alert(
        db=db_session,
        flow=flow,
        ml_status=PredictionStatus.NORMAL,
        ml_score=None,
        model_version=None,
        rule_findings=[finding],
    )
    alert = alerts[0]
    assert alert.status == AlertStatus.OPEN.value
    assert alert.resolved_at is None

    resolved = AlertService.resolve_alert(db=db_session, alert_id=alert.id)
    assert resolved is not None
    assert resolved.status == AlertStatus.RESOLVED.value
    assert resolved.resolved_at is not None
