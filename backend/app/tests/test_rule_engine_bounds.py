from datetime import datetime, timedelta, timezone
import uuid
import pytest
from sqlalchemy.orm import Session

from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.flow_record import FlowRecord
from app.repositories.detection_repository import DetectionRepository
from app.repositories.flow_repository import FlowRepository
from app.rules.rule_engine import RuleEngine, rule_engine


def test_historical_flows_time_and_session_bounding(db_session: Session):
    session_a = uuid.uuid4()
    session_b = uuid.uuid4()

    for s_id in (session_a, session_b):
        db_session.add(
            CaptureSession(
                id=s_id,
                interface_id="eth0",
                session_mode=SessionMode.MONITORING.value,
                status=CaptureStatus.STOPPED.value,
            )
        )
    db_session.commit()

    base_time = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)

    # Flow 1: Session A, 30s ago
    f1 = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_a,
        flow_key="TCP:192.168.1.100:1000<->10.0.0.1:80",
        src_ip="192.168.1.100",
        window_start=base_time - timedelta(seconds=30),
        window_end=base_time - timedelta(seconds=20),
        first_seen=base_time - timedelta(seconds=30),
        last_seen=base_time - timedelta(seconds=20),
        protocol="TCP",
        features={},
    )
    # Flow 2: Session A, exactly at current flow window_start
    current_flow_id = uuid.uuid4()
    f_current = FlowRecord(
        id=current_flow_id,
        session_id=session_a,
        flow_key="TCP:192.168.1.100:1001<->10.0.0.1:80",
        src_ip="192.168.1.100",
        window_start=base_time,
        window_end=base_time + timedelta(seconds=10),
        first_seen=base_time,
        last_seen=base_time + timedelta(seconds=5),
        protocol="TCP",
        features={},
    )
    # Flow 3: Session A, FUTURE flow (50s after base_time)
    f3_future = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_a,
        flow_key="TCP:192.168.1.100:1002<->10.0.0.1:80",
        src_ip="192.168.1.100",
        window_start=base_time + timedelta(seconds=50),
        window_end=base_time + timedelta(seconds=60),
        first_seen=base_time + timedelta(seconds=50),
        last_seen=base_time + timedelta(seconds=60),
        protocol="TCP",
        features={},
    )
    # Flow 4: Session B (DIFFERENT session!), 30s ago
    f4_other_session = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_b,
        flow_key="TCP:192.168.1.100:1003<->10.0.0.1:80",
        src_ip="192.168.1.100",
        window_start=base_time - timedelta(seconds=30),
        window_end=base_time - timedelta(seconds=20),
        first_seen=base_time - timedelta(seconds=30),
        last_seen=base_time - timedelta(seconds=20),
        protocol="TCP",
        features={},
    )

    FlowRepository.create_batch(db_session, [f1, f_current, f3_future, f4_other_session], create_jobs=False)

    # Query recent flows for Session A
    cutoff = base_time - timedelta(seconds=60)
    history = DetectionRepository.get_recent_flows_for_src_ip(
        db=db_session,
        src_ip="192.168.1.100",
        session_id=session_a,
        cutoff_time=cutoff,
        upper_time=f_current.window_start,
        exclude_flow_id=current_flow_id,
    )

    history_ids = {f.id for f in history}
    # Must contain f1 (past flow in same session)
    assert f1.id in history_ids
    # Must NOT contain current flow itself
    assert current_flow_id not in history_ids
    # Must NOT contain future flow
    assert f3_future.id not in history_ids
    # Must NOT contain flow from Session B
    assert f4_other_session.id not in history_ids


def test_port_scan_requires_distinct_ports():
    engine = RuleEngine(port_scan_distinct_ports=5, port_scan_window_seconds=60)
    now = datetime.now(timezone.utc)

    # Case A: 10 flows but all hitting the SAME port (e.g. port 80) -> NOT a port scan!
    duplicate_port_history = [
        FlowRecord(
            id=uuid.uuid4(),
            src_ip="10.0.0.99",
            dst_port=80,
            last_seen=now - timedelta(seconds=i * 2),
            features={},
        )
        for i in range(10)
    ]
    current_flow_dup = FlowRecord(
        id=uuid.uuid4(),
        src_ip="10.0.0.99",
        dst_port=80,
        last_seen=now,
        features={},
    )
    findings_dup = engine.evaluate_flow(current_flow_dup, flow_history=duplicate_port_history)
    scan_finding = next((f for f in findings_dup if f.rule_id == "RULE_PORT_SCAN"), None)
    assert scan_finding is None

    # Case B: 6 flows hitting 6 DISTINCT ports -> TRIGGER port scan!
    distinct_port_history = [
        FlowRecord(
            id=uuid.uuid4(),
            src_ip="10.0.0.99",
            dst_port=20 + i,
            last_seen=now - timedelta(seconds=i * 2),
            features={},
        )
        for i in range(5)
    ]
    current_flow_distinct = FlowRecord(
        id=uuid.uuid4(),
        src_ip="10.0.0.99",
        dst_port=999,
        last_seen=now,
        features={},
    )
    findings_distinct = engine.evaluate_flow(current_flow_distinct, flow_history=distinct_port_history)
    scan_finding = next((f for f in findings_distinct if f.rule_id == "RULE_PORT_SCAN"), None)
    assert scan_finding is not None
    assert scan_finding.evidence["distinct_ports_count"] == 6


def test_beaconing_regular_vs_irregular_intervals():
    engine = RuleEngine(beacon_min_intervals=4, beacon_max_packets_per_flow=10)
    base = datetime(2026, 11, 10, 10, 0, 0, tzinfo=timezone.utc)

    # Case A: Regular intervals (every 10 seconds: 0s, 10s, 20s, 30s, 40s)
    regular_history = [
        FlowRecord(
            id=uuid.uuid4(),
            src_ip="192.168.1.5",
            dst_ip="1.2.3.4",
            dst_port=4444,
            packet_count=3,
            window_start=base + timedelta(seconds=i * 10),
            first_seen=base + timedelta(seconds=i * 10),
            features={},
        )
        for i in range(4)
    ]
    current_regular = FlowRecord(
        id=uuid.uuid4(),
        src_ip="192.168.1.5",
        dst_ip="1.2.3.4",
        dst_port=4444,
        packet_count=3,
        window_start=base + timedelta(seconds=40),
        first_seen=base + timedelta(seconds=40),
        features={},
    )
    findings_reg = engine.evaluate_flow(current_regular, flow_history=regular_history)
    beacon_finding = next((f for f in findings_reg if f.rule_id == "RULE_BEACONING"), None)
    assert beacon_finding is not None
    assert beacon_finding.evidence["flow_count"] == 5

    # Case B: Irregular / random burst intervals (e.g. 1s, 45s, 3s, 120s) -> High jitter, no beacon alert
    irregular_offsets = [0, 1, 46, 49, 169]
    irregular_history = [
        FlowRecord(
            id=uuid.uuid4(),
            src_ip="192.168.1.5",
            dst_ip="1.2.3.4",
            dst_port=4444,
            packet_count=3,
            window_start=base + timedelta(seconds=irregular_offsets[i]),
            first_seen=base + timedelta(seconds=irregular_offsets[i]),
            features={},
        )
        for i in range(4)
    ]
    current_irreg = FlowRecord(
        id=uuid.uuid4(),
        src_ip="192.168.1.5",
        dst_ip="1.2.3.4",
        dst_port=4444,
        packet_count=3,
        window_start=base + timedelta(seconds=irregular_offsets[4]),
        first_seen=base + timedelta(seconds=irregular_offsets[4]),
        features={},
    )
    findings_irreg = engine.evaluate_flow(current_irreg, flow_history=irregular_history)
    beacon_irreg = next((f for f in findings_irreg if f.rule_id == "RULE_BEACONING"), None)
    assert beacon_irreg is None
