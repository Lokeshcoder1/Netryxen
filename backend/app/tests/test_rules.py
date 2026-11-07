from datetime import datetime, timedelta, timezone
import uuid
import pytest

from app.models.detection import AlertSeverity
from app.models.flow_record import FlowRecord
from app.rules.rule_engine import RuleEngine, rule_engine


def make_test_flow(
    protocol: str = "TCP",
    syn_count: int = 0,
    ack_count: int = 0,
    rst_count: int = 0,
    pps: float = 10.0,
    bps: float = 1000.0,
    dns_query_count: int = 0,
    dns_unique_count: int = 0,
    dst_port: int = 80,
    is_broadcast: bool = False,
    is_multicast: bool = False,
    packet_count: int = 10,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "93.184.216.34",
    last_seen: datetime = None,
) -> FlowRecord:
    now = last_seen or datetime.now(timezone.utc)
    return FlowRecord(
        id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        window_start=now,
        window_end=now,
        flow_key="KEY",
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=54321,
        dst_port=dst_port,
        protocol=protocol,
        protocol_num=6 if protocol == "TCP" else (17 if protocol == "UDP" else 1),
        first_seen=now,
        last_seen=now,
        duration_seconds=1.0,
        packet_count=packet_count,
        byte_count=packet_count * 100,
        fwd_packets=packet_count,
        rev_packets=0,
        fwd_bytes=packet_count * 100,
        rev_bytes=0,
        packets_per_second=pps,
        bytes_per_second=bps,
        min_packet_size=60,
        max_packet_size=150,
        avg_packet_size=100.0,
        tcp_syn_count=syn_count,
        tcp_ack_count=ack_count,
        tcp_fin_count=0,
        tcp_rst_count=rst_count,
        tcp_psh_count=0,
        dns_query_count=dns_query_count,
        dns_unique_query_count=dns_unique_count,
        upload_bytes=packet_count * 100,
        download_bytes=0,
        upload_ratio=1.0,
        is_local=True,
        is_broadcast=is_broadcast,
        is_multicast=is_multicast,
        features={},
        feature_schema_version="1.0",
    )


# -----------------------------------------------------------------------------
# 1. SYN-heavy
# -----------------------------------------------------------------------------

def test_rule_syn_heavy_positive():
    engine = RuleEngine()
    flow = make_test_flow(protocol="TCP", syn_count=12, ack_count=0)
    findings = engine.evaluate_flow(flow)
    assert any(f.rule_id == "RULE_SYN_HEAVY" for f in findings)


def test_rule_syn_heavy_negative():
    engine = RuleEngine()
    flow = make_test_flow(protocol="TCP", syn_count=5, ack_count=10)
    findings = engine.evaluate_flow(flow)
    assert not any(f.rule_id == "RULE_SYN_HEAVY" for f in findings)


# -----------------------------------------------------------------------------
# 2. High Rates
# -----------------------------------------------------------------------------

def test_rule_high_rate_positive_pps():
    engine = RuleEngine(high_pps_threshold=500.0)
    flow = make_test_flow(pps=600.0, bps=1000.0)
    findings = engine.evaluate_flow(flow)
    assert any(f.rule_id == "RULE_HIGH_RATE" for f in findings)


def test_rule_high_rate_positive_bps():
    engine = RuleEngine(high_bps_threshold=5_000_000.0)
    flow = make_test_flow(pps=100.0, bps=6_000_000.0)
    findings = engine.evaluate_flow(flow)
    assert any(f.rule_id == "RULE_HIGH_RATE" for f in findings)


def test_rule_high_rate_negative():
    engine = RuleEngine()
    flow = make_test_flow(pps=50.0, bps=100_000.0)
    findings = engine.evaluate_flow(flow)
    assert not any(f.rule_id == "RULE_HIGH_RATE" for f in findings)


# -----------------------------------------------------------------------------
# 3. Excessive RST
# -----------------------------------------------------------------------------

def test_rule_excessive_rst_positive():
    engine = RuleEngine()
    flow = make_test_flow(protocol="TCP", rst_count=6, packet_count=10)
    findings = engine.evaluate_flow(flow)
    assert any(f.rule_id == "RULE_EXCESSIVE_RST" for f in findings)


def test_rule_excessive_rst_negative():
    engine = RuleEngine()
    flow = make_test_flow(protocol="TCP", rst_count=1, packet_count=50)
    findings = engine.evaluate_flow(flow)
    assert not any(f.rule_id == "RULE_EXCESSIVE_RST" for f in findings)


# -----------------------------------------------------------------------------
# 4. High DNS
# -----------------------------------------------------------------------------

def test_rule_high_dns_positive():
    engine = RuleEngine(high_dns_query_threshold=25)
    flow = make_test_flow(protocol="UDP", dns_query_count=30, dns_unique_count=20)
    findings = engine.evaluate_flow(flow)
    assert any(f.rule_id == "RULE_HIGH_DNS" for f in findings)


def test_rule_high_dns_negative():
    engine = RuleEngine()
    flow = make_test_flow(protocol="UDP", dns_query_count=2, dns_unique_count=1)
    findings = engine.evaluate_flow(flow)
    assert not any(f.rule_id == "RULE_HIGH_DNS" for f in findings)


# -----------------------------------------------------------------------------
# 5. Uncommon / High-risk Ports
# -----------------------------------------------------------------------------

def test_rule_uncommon_port_positive():
    engine = RuleEngine()
    flow = make_test_flow(dst_port=4444)  # Metasploit default
    findings = engine.evaluate_flow(flow)
    assert any(f.rule_id == "RULE_UNCOMMON_PORT" for f in findings)

    flow2 = make_test_flow(dst_port=31337)  # Back Orifice
    findings2 = engine.evaluate_flow(flow2)
    assert any(f.rule_id == "RULE_UNCOMMON_PORT" for f in findings2)


def test_rule_uncommon_port_negative():
    engine = RuleEngine()
    flow = make_test_flow(dst_port=443)  # Standard HTTPS
    findings = engine.evaluate_flow(flow)
    assert not any(f.rule_id == "RULE_UNCOMMON_PORT" for f in findings)


# -----------------------------------------------------------------------------
# 6. Broadcast / Multicast
# -----------------------------------------------------------------------------

def test_rule_broadcast_positive():
    engine = RuleEngine()
    flow = make_test_flow(is_broadcast=True, packet_count=60, pps=60.0)
    findings = engine.evaluate_flow(flow)
    assert any(f.rule_id == "RULE_HIGH_BROADCAST_MULTICAST" for f in findings)


def test_rule_broadcast_negative():
    engine = RuleEngine()
    flow = make_test_flow(is_broadcast=True, packet_count=5, pps=5.0)
    findings = engine.evaluate_flow(flow)
    assert not any(f.rule_id == "RULE_HIGH_BROADCAST_MULTICAST" for f in findings)


# -----------------------------------------------------------------------------
# 7. Multi-flow: Port Scan
# -----------------------------------------------------------------------------

def test_rule_port_scan_positive():
    engine = RuleEngine(port_scan_distinct_ports=10, port_scan_window_seconds=60)
    now = datetime.now(timezone.utc)
    src_ip = "10.0.0.99"

    # 9 prior flows across distinct ports
    history = [
        make_test_flow(src_ip=src_ip, dst_port=1000 + i, last_seen=now - timedelta(seconds=i * 2))
        for i in range(9)
    ]
    # Current flow on port 1010 (10th distinct port)
    current = make_test_flow(src_ip=src_ip, dst_port=1010, last_seen=now)

    findings = engine.evaluate_flow(current, flow_history=history)
    assert any(f.rule_id == "RULE_PORT_SCAN" for f in findings)
    scan_finding = next(f for f in findings if f.rule_id == "RULE_PORT_SCAN")
    assert scan_finding.severity == AlertSeverity.HIGH


def test_rule_port_scan_negative():
    engine = RuleEngine(port_scan_distinct_ports=10, port_scan_window_seconds=60)
    now = datetime.now(timezone.utc)
    src_ip = "10.0.0.99"

    # Only 3 distinct ports
    history = [
        make_test_flow(src_ip=src_ip, dst_port=80, last_seen=now - timedelta(seconds=i * 2))
        for i in range(5)
    ]
    current = make_test_flow(src_ip=src_ip, dst_port=443, last_seen=now)

    findings = engine.evaluate_flow(current, flow_history=history)
    assert not any(f.rule_id == "RULE_PORT_SCAN" for f in findings)


# -----------------------------------------------------------------------------
# 8. Multi-flow: Beaconing
# -----------------------------------------------------------------------------

def test_rule_beaconing_positive():
    engine = RuleEngine(beacon_min_intervals=4, beacon_max_packets_per_flow=10)
    now = datetime.now(timezone.utc)
    src = "192.168.1.77"
    dst = "203.0.113.5"
    port = 8080

    # 4 flows spaced exactly 10 seconds apart with 2 packets each
    history = [
        make_test_flow(
            src_ip=src, dst_ip=dst, dst_port=port, packet_count=2,
            last_seen=now - timedelta(seconds=30)
        ),
        make_test_flow(
            src_ip=src, dst_ip=dst, dst_port=port, packet_count=2,
            last_seen=now - timedelta(seconds=20)
        ),
        make_test_flow(
            src_ip=src, dst_ip=dst, dst_port=port, packet_count=2,
            last_seen=now - timedelta(seconds=10)
        ),
    ]
    current = make_test_flow(
        src_ip=src, dst_ip=dst, dst_port=port, packet_count=2, last_seen=now
    )

    findings = engine.evaluate_flow(current, flow_history=history)
    assert any(f.rule_id == "RULE_BEACONING" for f in findings)
    beacon_finding = next(f for f in findings if f.rule_id == "RULE_BEACONING")
    assert beacon_finding.severity == AlertSeverity.HIGH


def test_rule_beaconing_negative_high_volume():
    # If flows carry high packet volume (e.g. 50 pkts), it's not lightweight beaconing
    engine = RuleEngine(beacon_min_intervals=4, beacon_max_packets_per_flow=10)
    now = datetime.now(timezone.utc)
    src = "192.168.1.77"
    dst = "203.0.113.5"
    port = 8080

    history = [
        make_test_flow(src_ip=src, dst_ip=dst, dst_port=port, packet_count=100, last_seen=now - timedelta(seconds=i * 10))
        for i in range(1, 4)
    ]
    current = make_test_flow(src_ip=src, dst_ip=dst, dst_port=port, packet_count=100, last_seen=now)
    findings = engine.evaluate_flow(current, flow_history=history)
    assert not any(f.rule_id == "RULE_BEACONING" for f in findings)
