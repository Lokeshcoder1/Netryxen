from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch
import uuid
import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from sqlalchemy.orm import Session

from app.capture.capture_manager import CaptureManager
from app.capture.flow_aggregator import FlowAggregator
from app.capture.packet_parser import PacketParser
from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.flow_record import FlowRecord
from app.repositories.flow_repository import FlowRepository
from app.schemas.packet import PacketEventSchema


def test_packet_parser_dns_query_vs_response():
    # DNS Query: qr == 0
    query_pkt = IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=50000, dport=53) / DNS(
        qr=0, qdcount=1, qd=DNSQR(qname="malicious.example.com")
    )
    parsed_query = PacketParser.parse(query_pkt)
    assert parsed_query is not None
    assert parsed_query.dns_query_count == 1
    assert parsed_query.dns_unique_query_count == 1

    # DNS Response: qr == 1
    resp_pkt = IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=50000) / DNS(
        qr=1, qdcount=1, qd=DNSQR(qname="malicious.example.com"), an=DNSRR(rrname="malicious.example.com", rdata="1.2.3.4")
    )
    parsed_resp = PacketParser.parse(resp_pkt)
    assert parsed_resp is not None
    # DNS responses must NOT be counted as outbound queries!
    assert parsed_resp.dns_query_count == 0
    assert parsed_resp.dns_unique_query_count == 0


def test_capture_manager_startup_rollback_on_aggregator_failure():
    mgr = CaptureManager()
    session_id = uuid.uuid4()

    with patch("app.capture.interface_discovery.InterfaceDiscoveryService.get_interface_by_id") as mock_iface:
        mock_iface.return_value = MagicMock(id="eth0", ip_addresses=["192.168.1.10"])

        with patch("scapy.sendrecv.AsyncSniffer.start") as mock_sniffer_start:
            mock_sniffer_start.return_value = None

            with patch("app.capture.flow_aggregator.flow_aggregator.start") as mock_agg_start:
                mock_agg_start.side_effect = RuntimeError("Aggregator disk full error")

                with pytest.raises(RuntimeError, match="Capture startup failed"):
                    mgr.start_capture(
                        interface_id="eth0",
                        session_id=session_id,
                    )

                # Verify clean rollback: manager must NOT remain running!
                assert mgr.is_running is False
                assert mgr._sniffer is None
                assert mgr._active_session_id is None


def test_flow_aggregator_late_packet_policy():
    aggregator = FlowAggregator(window_size_seconds=10, worker_interval=0.1)
    session_id = uuid.uuid4()
    mock_queue = MagicMock()
    mock_queue.pop.return_value = None

    aggregator.start(session_id=session_id, packet_queue=mock_queue)

    base_time = datetime(2026, 11, 10, 12, 0, 0, tzinfo=timezone.utc)
    pkt1 = PacketEventSchema(
        timestamp=base_time,
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1000,
        dst_port=80,
        protocol_name="TCP",
        length=100,
    )
    aggregator._process_packet(pkt1)
    assert len(aggregator._accumulators) == 1

    # Finalize all open windows
    with patch("app.repositories.flow_repository.FlowRepository.create_batch") as mock_save:
        mock_save.return_value = 1
        aggregator._finalize_windows(force_all=True)

    assert len(aggregator._accumulators) == 0

    # Now a late packet arrives for the finalized window
    late_pkt = PacketEventSchema(
        timestamp=base_time + timedelta(seconds=2),
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=1000,
        dst_port=80,
        protocol_name="TCP",
        length=200,
    )
    aggregator._process_packet(late_pkt)

    # Must be dropped to prevent duplicate DB record
    assert len(aggregator._accumulators) == 0
    stats = aggregator.get_stats()
    assert stats["late_packets_dropped"] == 1

    aggregator.stop_and_flush()


def test_dashboard_directional_top_talkers(db_session: Session):
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
    # Host A (10.0.0.1) contacts Host B (10.0.0.2):
    # Host A sent 1000 bytes (fwd), Host B sent 5000 bytes (rev)
    flow1 = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_id,
        flow_key="TCP:10.0.0.1:50000<->10.0.0.2:80",
        src_ip="10.0.0.1",
        dst_ip="10.0.0.2",
        src_port=50000,
        dst_port=80,
        protocol="TCP",
        packet_count=10,
        byte_count=6000,
        fwd_packets=2,
        rev_packets=8,
        fwd_bytes=1000,
        rev_bytes=5000,
        window_start=now,
        window_end=now + timedelta(seconds=10),
        first_seen=now,
        last_seen=now + timedelta(seconds=10),
        features={},
    )
    FlowRepository.create_batch(db_session, [flow1], create_jobs=False)

    stats = FlowRepository.get_dashboard_stats(db_session)
    talkers = {t["ip"]: t for t in stats["top_talkers"]}

    assert "10.0.0.1" in talkers
    assert "10.0.0.2" in talkers

    # 10.0.0.1 sent 1000 bytes, received 5000 bytes
    assert talkers["10.0.0.1"]["bytes_sent"] == 1000
    assert talkers["10.0.0.1"]["bytes_recv"] == 5000
    assert talkers["10.0.0.1"]["bytes"] == 6000

    # 10.0.0.2 sent 5000 bytes, received 1000 bytes
    assert talkers["10.0.0.2"]["bytes_sent"] == 5000
    assert talkers["10.0.0.2"]["bytes_recv"] == 1000
    assert talkers["10.0.0.2"]["bytes"] == 6000
