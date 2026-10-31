from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.flow_record import FlowRecord


@pytest.fixture
def sample_flow_data(db_session: Session):
    session_id = uuid.uuid4()
    cap_session = CaptureSession(
        id=session_id,
        interface_id="Test-Iface",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.STOPPED.value,
        started_at=datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc),
        stopped_at=datetime(2026, 10, 12, 10, 5, 0, tzinfo=timezone.utc),
    )
    db_session.add(cap_session)

    flow1 = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_id,
        window_start=datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 10, 12, 10, 0, 10, tzinfo=timezone.utc),
        flow_key="TCP:192.168.1.50:54321<->93.184.216.34:443",
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=54321,
        dst_port=443,
        protocol="TCP",
        protocol_num=6,
        first_seen=datetime(2026, 10, 12, 10, 0, 1, tzinfo=timezone.utc),
        last_seen=datetime(2026, 10, 12, 10, 0, 3, tzinfo=timezone.utc),
        duration_seconds=2.0,
        packet_count=15,
        byte_count=1500,
        fwd_packets=10,
        rev_packets=5,
        fwd_bytes=1000,
        rev_bytes=500,
        packets_per_second=7.5,
        bytes_per_second=750.0,
        min_packet_size=60,
        max_packet_size=150,
        avg_packet_size=100.0,
        tcp_syn_count=1,
        tcp_ack_count=14,
        tcp_fin_count=0,
        tcp_rst_count=0,
        tcp_psh_count=2,
        dns_query_count=0,
        dns_unique_query_count=0,
        upload_bytes=1000,
        download_bytes=500,
        upload_ratio=0.6667,
        is_local=True,
        is_broadcast=False,
        is_multicast=False,
        features={"packet_count": 15, "byte_count": 1500},
        feature_schema_version="1.0",
    )

    flow2 = FlowRecord(
        id=uuid.uuid4(),
        session_id=session_id,
        window_start=datetime(2026, 10, 12, 10, 0, 0, tzinfo=timezone.utc),
        window_end=datetime(2026, 10, 12, 10, 0, 10, tzinfo=timezone.utc),
        flow_key="UDP:192.168.1.50:53535<->8.8.8.8:53",
        src_ip="192.168.1.50",
        dst_ip="8.8.8.8",
        src_port=53535,
        dst_port=53,
        protocol="UDP",
        protocol_num=17,
        first_seen=datetime(2026, 10, 12, 10, 0, 2, tzinfo=timezone.utc),
        last_seen=datetime(2026, 10, 12, 10, 0, 2, tzinfo=timezone.utc),
        duration_seconds=0.0,
        packet_count=2,
        byte_count=160,
        fwd_packets=1,
        rev_packets=1,
        fwd_bytes=80,
        rev_bytes=80,
        packets_per_second=2.0,
        bytes_per_second=160.0,
        min_packet_size=80,
        max_packet_size=80,
        avg_packet_size=80.0,
        tcp_syn_count=0,
        tcp_ack_count=0,
        tcp_fin_count=0,
        tcp_rst_count=0,
        tcp_psh_count=0,
        dns_query_count=1,
        dns_unique_query_count=1,
        upload_bytes=80,
        download_bytes=80,
        upload_ratio=0.5,
        is_local=True,
        is_broadcast=False,
        is_multicast=False,
        features={"packet_count": 2, "byte_count": 160},
        feature_schema_version="1.0",
    )

    db_session.add_all([flow1, flow2])
    db_session.commit()
    return {"session_id": session_id, "flow1_id": flow1.id, "flow2_id": flow2.id}


def test_api_list_flows_empty(client: TestClient):
    response = client.get("/api/v1/flows")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 0
    assert data["items"] == []


def test_api_list_flows_populated(client: TestClient, sample_flow_data):
    response = client.get("/api/v1/flows")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 2
    assert len(data["items"]) == 2


def test_api_list_flows_filter_protocol(client: TestClient, sample_flow_data):
    response = client.get("/api/v1/flows?protocol=TCP")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["protocol"] == "TCP"


def test_api_list_flows_filter_ip(client: TestClient, sample_flow_data):
    response = client.get("/api/v1/flows?ip=8.8.8.8")
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["items"][0]["dst_ip"] == "8.8.8.8"


def test_api_get_flow_by_id(client: TestClient, sample_flow_data):
    flow_id = sample_flow_data["flow1_id"]
    response = client.get(f"/api/v1/flows/{flow_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(flow_id)
    assert data["protocol"] == "TCP"
    assert data["packet_count"] == 15
    assert data["fwd_packets"] == 10
    assert data["rev_packets"] == 5


def test_api_get_flow_not_found(client: TestClient):
    random_id = uuid.uuid4()
    response = client.get(f"/api/v1/flows/{random_id}")
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_dashboard_summary(client: TestClient, sample_flow_data):
    response = client.get("/api/v1/dashboard/summary")
    assert response.status_code == 200
    data = response.json()
    assert "capture_status" in data
    assert data["total_sessions"] == 1
    assert data["total_flows"] == 2
    assert data["total_packets"] == 17
    assert data["total_bytes"] == 1660
    assert "TCP" in data["protocol_distribution"]
    assert "UDP" in data["protocol_distribution"]
    assert len(data["top_talkers"]) >= 1
    assert len(data["recent_flows"]) == 2
