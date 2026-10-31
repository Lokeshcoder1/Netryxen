from datetime import datetime, timedelta, timezone
from typing import List, Optional
import uuid

import pytest
from sqlalchemy.orm import Session

from app.capture.flow_aggregator import (
    FlowAccumulator,
    FlowAggregator,
    generate_canonical_flow_key,
)
from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.flow_record import FlowRecord
from app.schemas.packet import PacketEventSchema


def make_packet(
    src_ip: str = "192.168.1.50",
    dst_ip: str = "93.184.216.34",
    src_port: Optional[int] = 54321,
    dst_port: Optional[int] = 443,
    protocol_name: str = "TCP",
    protocol_num: int = 6,
    tcp_flags: Optional[List[str]] = None,
    length: int = 60,
    timestamp: Optional[datetime] = None,
    dns_query_count: int = 0,
    dns_unique_query_count: int = 0,
    is_local: bool = False,
    is_broadcast: bool = False,
    is_multicast: bool = False,
) -> PacketEventSchema:
    if timestamp is None:
        timestamp = datetime(2026, 10, 12, 12, 0, 1, tzinfo=timezone.utc)
    return PacketEventSchema(
        timestamp=timestamp,
        ip_version=4,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol_name=protocol_name,
        protocol_num=protocol_num,
        tcp_flags=tcp_flags,
        ttl=64,
        length=length,
        is_local=is_local,
        is_broadcast=is_broadcast,
        is_multicast=is_multicast,
        dns_query_count=dns_query_count,
        dns_unique_query_count=dns_unique_query_count,
    )


def test_canonical_flow_key_symmetry():
    # Forward packet
    key_fwd = generate_canonical_flow_key(
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
    )
    # Reverse packet
    key_rev = generate_canonical_flow_key(
        src_ip="93.184.216.34",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=54321,
        protocol="TCP",
    )
    assert key_fwd == key_rev
    assert "TCP" in key_fwd


def test_canonical_flow_key_protocol_separation():
    key_tcp = generate_canonical_flow_key(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=80, dst_port=80, protocol="TCP"
    )
    key_udp = generate_canonical_flow_key(
        src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=80, dst_port=80, protocol="UDP"
    )
    assert key_tcp != key_udp


def test_canonical_flow_key_non_transport():
    # ICMP has no ports
    key_icmp = generate_canonical_flow_key(
        src_ip="192.168.1.1", dst_ip="192.168.1.2", src_port=None, dst_port=None, protocol="ICMP"
    )
    key_icmp_rev = generate_canonical_flow_key(
        src_ip="192.168.1.2", dst_ip="192.168.1.1", src_port=None, dst_port=None, protocol="ICMP"
    )
    assert key_icmp == key_icmp_rev
    assert "ICMP" in key_icmp


def test_bidirectional_flow_aggregation():
    session_id = uuid.uuid4()
    w_start = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    w_end = w_start + timedelta(seconds=10)
    local_ips = {"192.168.1.50"}

    # Packet 1 (Forward, SYN, from local IP)
    p1 = make_packet(
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=50000,
        dst_port=443,
        tcp_flags=["SYN"],
        length=74,
        timestamp=w_start + timedelta(seconds=1),
    )
    flow_key = generate_canonical_flow_key(
        p1.src_ip, p1.dst_ip, p1.src_port, p1.dst_port, p1.protocol_name
    )

    acc = FlowAccumulator(
        session_id=session_id,
        flow_key=flow_key,
        window_start=w_start,
        window_end=w_end,
        first_packet=p1,
        local_ips=local_ips,
    )

    # Packet 2 (Reverse, SYN-ACK, to local IP)
    p2 = make_packet(
        src_ip="93.184.216.34",
        dst_ip="192.168.1.50",
        src_port=443,
        dst_port=50000,
        tcp_flags=["SYN", "ACK"],
        length=74,
        timestamp=w_start + timedelta(seconds=2),
    )
    acc.add_packet(p2)

    # Packet 3 (Forward, ACK, from local IP)
    p3 = make_packet(
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=50000,
        dst_port=443,
        tcp_flags=["ACK"],
        length=66,
        timestamp=w_start + timedelta(seconds=3),
    )
    acc.add_packet(p3)

    record = acc.to_flow_record()

    assert record.packet_count == 3
    assert record.byte_count == 74 + 74 + 66
    assert record.fwd_packets == 2
    assert record.rev_packets == 1
    assert record.fwd_bytes == 74 + 66
    assert record.rev_bytes == 74
    assert record.tcp_syn_count == 2
    assert record.tcp_ack_count == 2
    assert record.min_packet_size == 66
    assert record.max_packet_size == 74
    assert record.duration_seconds == 2.0  # seconds 1 to 3
    assert record.upload_bytes == 74 + 66
    assert record.download_bytes == 74
    assert record.upload_ratio == round(140 / (140 + 74), 4)


def test_rate_calculation_safeguards_zero_duration():
    session_id = uuid.uuid4()
    w_start = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    w_end = w_start + timedelta(seconds=10)

    # Single packet: duration = 0.0s
    p1 = make_packet(timestamp=w_start + timedelta(seconds=1), length=100)
    acc = FlowAccumulator(
        session_id=session_id,
        flow_key="KEY",
        window_start=w_start,
        window_end=w_end,
        first_packet=p1,
        local_ips=set(),
    )

    record = acc.to_flow_record()
    assert record.duration_seconds == 0.0
    # Effective duration clamped to min 1.0s to avoid div-by-zero or infinite rates
    assert record.packets_per_second == 1.0
    assert record.bytes_per_second == 100.0


def test_dns_and_non_tcp_counters():
    session_id = uuid.uuid4()
    w_start = datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    w_end = w_start + timedelta(seconds=10)

    p1 = make_packet(
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        src_port=53535,
        dst_port=53,
        protocol_name="UDP",
        protocol_num=17,
        tcp_flags=None,
        dns_query_count=2,
        dns_unique_query_count=1,
        length=85,
    )
    acc = FlowAccumulator(
        session_id=session_id,
        flow_key="UDP_KEY",
        window_start=w_start,
        window_end=w_end,
        first_packet=p1,
        local_ips={"192.168.1.50"},
    )
    record = acc.to_flow_record()
    assert record.protocol == "UDP"
    assert record.tcp_syn_count == 0
    assert record.dns_query_count == 2
    assert record.dns_unique_query_count == 1
    assert "upload_bytes" in record.features


def test_flow_aggregator_flush_to_db(db_session: Session):
    # Create capture session in db
    session_id = uuid.uuid4()
    cap_session = CaptureSession(
        id=session_id,
        interface_id="Test-Iface",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.RUNNING.value,
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(cap_session)
    db_session.commit()

    # Create dummy queue
    from app.capture.packet_queue import BoundedPacketQueue
    test_queue = BoundedPacketQueue(capacity=100)

    # Push 2 packets (same flow) into queue
    test_queue.push(
        make_packet(
            src_ip="192.168.1.10",
            dst_ip="142.250.190.46",
            src_port=44444,
            dst_port=443,
            length=120,
        )
    )
    test_queue.push(
        make_packet(
            src_ip="142.250.190.46",
            dst_ip="192.168.1.10",
            src_port=443,
            dst_port=44444,
            length=250,
        )
    )

    aggregator = FlowAggregator(
        window_size_seconds=10,
        worker_interval=0.5,
        session_factory=lambda: db_session,
    )
    aggregator.start(
        session_id=session_id,
        packet_queue=test_queue,
        local_ips=["192.168.1.10"],
    )

    # Stop and flush immediately
    flushed = aggregator.stop_and_flush()
    assert flushed == 1

    # Check record in DB
    records = db_session.query(FlowRecord).filter(FlowRecord.session_id == session_id).all()
    assert len(records) == 1
    flow = records[0]
    assert flow.packet_count == 2
    assert flow.byte_count == 370
    assert flow.fwd_packets == 1
    assert flow.rev_packets == 1


def test_multiple_time_windows_separation(db_session: Session):
    session_id = uuid.uuid4()
    cap_session = CaptureSession(
        id=session_id,
        interface_id="Test-Iface",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.RUNNING.value,
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(cap_session)
    db_session.commit()

    from app.capture.packet_queue import BoundedPacketQueue
    test_queue = BoundedPacketQueue(capacity=100)

    # Window 1 packet (e.g. at 12:00:02)
    t1 = datetime(2026, 10, 12, 12, 0, 2, tzinfo=timezone.utc)
    test_queue.push(
        make_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, timestamp=t1
        )
    )

    # Window 2 packet (e.g. at 12:00:15 -> falls into 12:00:10-12:00:20 window)
    t2 = datetime(2026, 10, 12, 12, 0, 15, tzinfo=timezone.utc)
    test_queue.push(
        make_packet(
            src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1000, dst_port=80, timestamp=t2
        )
    )

    aggregator = FlowAggregator(
        window_size_seconds=10,
        worker_interval=0.5,
        session_factory=lambda: db_session,
    )
    aggregator.start(
        session_id=session_id,
        packet_queue=test_queue,
    )
    flushed = aggregator.stop_and_flush()
    assert flushed == 2

    records = (
        db_session.query(FlowRecord)
        .filter(FlowRecord.session_id == session_id)
        .order_by(FlowRecord.window_start)
        .all()
    )
    assert len(records) == 2
    assert records[0].window_start.replace(tzinfo=timezone.utc) == datetime(2026, 10, 12, 12, 0, 0, tzinfo=timezone.utc)
    assert records[1].window_start.replace(tzinfo=timezone.utc) == datetime(2026, 10, 12, 12, 0, 10, tzinfo=timezone.utc)
    assert records[0].packet_count == 1
    assert records[1].packet_count == 1


def test_unrelated_connections_separation(db_session: Session):
    session_id = uuid.uuid4()
    cap_session = CaptureSession(
        id=session_id,
        interface_id="Test-Iface",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.RUNNING.value,
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(cap_session)
    db_session.commit()

    from app.capture.packet_queue import BoundedPacketQueue
    test_queue = BoundedPacketQueue(capacity=100)

    t = datetime(2026, 10, 12, 12, 0, 5, tzinfo=timezone.utc)
    # Connection A
    test_queue.push(
        make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=1111, dst_port=80, timestamp=t)
    )
    # Connection B
    test_queue.push(
        make_packet(src_ip="10.0.0.1", dst_ip="10.0.0.3", src_port=2222, dst_port=443, timestamp=t)
    )

    aggregator = FlowAggregator(
        window_size_seconds=10,
        worker_interval=0.5,
        session_factory=lambda: db_session,
    )
    aggregator.start(
        session_id=session_id,
        packet_queue=test_queue,
    )
    flushed = aggregator.stop_and_flush()
    assert flushed == 2

    records = db_session.query(FlowRecord).filter(FlowRecord.session_id == session_id).all()
    assert len(records) == 2
    keys = {r.flow_key for r in records}
    assert len(keys) == 2

