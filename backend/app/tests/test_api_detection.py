from datetime import datetime, timezone
import uuid
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.ml.model_manager import model_manager
from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.detection import Alert, AlertSeverity, AlertStatus, ModelRegistry, ModelStatus, Prediction
from app.models.flow_record import FlowRecord


@pytest.fixture
def baseline_session_with_flows(db_session: Session):
    sess_id = uuid.uuid4()
    cap_sess = CaptureSession(
        id=sess_id,
        interface_id="Test-Iface",
        session_mode=SessionMode.BASELINE.value,
        status=CaptureStatus.STOPPED.value,
        started_at=datetime.now(timezone.utc),
        stopped_at=datetime.now(timezone.utc),
        packets_seen=600,
        packets_enqueued=600,
        packets_dropped=0,
    )
    db_session.add(cap_sess)

    # Add 55 flows to satisfy default minimum sample requirements
    flows = []
    for i in range(55):
        now = datetime.now(timezone.utc)
        f = FlowRecord(
            id=uuid.uuid4(),
            session_id=sess_id,
            window_start=now,
            window_end=now,
            flow_key=f"TCP:192.168.1.50:{50000+i}<->93.184.216.34:443",
            src_ip="192.168.1.50",
            dst_ip="93.184.216.34",
            src_port=50000 + i,
            dst_port=443,
            protocol="TCP",
            protocol_num=6,
            first_seen=now,
            last_seen=now,
            duration_seconds=1.5,
            packet_count=10 + (i % 3),
            byte_count=1000 + (i * 10),
            fwd_packets=5,
            rev_packets=5,
            fwd_bytes=500,
            rev_bytes=500,
            packets_per_second=6.0,
            bytes_per_second=600.0,
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
        flows.append(f)

    db_session.add_all(flows)
    db_session.commit()
    return {"session_id": sess_id, "flows": flows}


def test_api_model_status_initially_empty(client: TestClient):
    model_manager.reset()
    res = client.get("/api/v1/models/status")
    assert res.status_code == 200
    data = res.json()
    assert "is_ready" in data


def test_api_train_baseline_invalid_session_mode(client: TestClient, db_session: Session):
    # Session in MONITORING mode, not BASELINE
    sess_id = uuid.uuid4()
    mon_sess = CaptureSession(
        id=sess_id,
        interface_id="Test-Iface",
        session_mode=SessionMode.MONITORING.value,
        status=CaptureStatus.STOPPED.value,
        started_at=datetime.now(timezone.utc),
    )
    db_session.add(mon_sess)
    db_session.commit()

    res = client.post(
        "/api/v1/models/train-baseline",
        json={"session_id": str(sess_id)},
    )
    assert res.status_code == 400
    assert "BASELINE" in res.json()["detail"]


def test_api_train_baseline_success(client: TestClient, baseline_session_with_flows):
    sess_id = baseline_session_with_flows["session_id"]
    res = client.post(
        "/api/v1/models/train-baseline",
        json={
            "session_id": str(sess_id),
            "model_name": "Test_API_Model",
            "min_samples": 50,
        },
    )
    assert res.status_code == 201
    data = res.json()
    assert data["name"] == "Test_API_Model"
    assert data["status"] == "READY"
    assert data["training_sample_count"] == 55
    assert len(data["feature_names"]) == 22
    assert "score_mean" in data["evaluation_info"]

    # Verify model status endpoint reflects ready model
    res_status = client.get("/api/v1/models/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["is_ready"] is True
    assert status_data["active_model"]["id"] == data["id"]


def test_api_predict_flow_normal(client: TestClient, baseline_session_with_flows):
    flow = baseline_session_with_flows["flows"][0]
    res = client.post(f"/api/v1/predictions/{flow.id}")
    assert res.status_code == 200
    data = res.json()
    assert data["flow_id"] == str(flow.id)
    assert data["status"] in ("NORMAL", "ANOMALY")
    assert data["raw_score"] is not None
    assert data["raw_prediction"] is not None


def test_api_predict_flow_anomalous_with_alerts(client: TestClient, db_session: Session):
    # Create a flow that violates rules and diverges from baseline
    now = datetime.now(timezone.utc)
    anom_flow = FlowRecord(
        id=uuid.uuid4(),
        session_id=uuid.uuid4(),
        window_start=now,
        window_end=now,
        flow_key="TCP:192.168.1.99:50000<->10.0.0.1:4444",
        src_ip="192.168.1.99",
        dst_ip="10.0.0.1",
        src_port=50000,
        dst_port=4444,  # High risk port!
        protocol="TCP",
        protocol_num=6,
        first_seen=now,
        last_seen=now,
        duration_seconds=1.0,
        packet_count=5000,
        byte_count=5000000,
        fwd_packets=5000,
        rev_packets=0,
        fwd_bytes=5000000,
        rev_bytes=0,
        packets_per_second=5000.0,  # High rate!
        bytes_per_second=5000000.0,
        min_packet_size=1000,
        max_packet_size=1000,
        avg_packet_size=1000.0,
        tcp_syn_count=100,  # SYN heavy!
        tcp_ack_count=0,
        tcp_fin_count=0,
        tcp_rst_count=0,
        tcp_psh_count=0,
        dns_query_count=0,
        dns_unique_query_count=0,
        upload_bytes=5000000,
        download_bytes=0,
        upload_ratio=1.0,
        is_local=True,
        is_broadcast=False,
        is_multicast=False,
        features={},
        feature_schema_version="1.0",
    )
    db_session.add(anom_flow)
    db_session.commit()

    res = client.post(f"/api/v1/predictions/{anom_flow.id}")
    assert res.status_code == 200
    pred_data = res.json()
    assert pred_data["alerts_generated"] >= 1

    # Verify alerts list endpoint
    alerts_res = client.get("/api/v1/alerts")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()
    assert alerts_data["total"] >= 1
    alert_item = alerts_data["items"][0]
    assert alert_item["status"] == "OPEN"

    # Test resolving the alert
    resolve_res = client.patch(f"/api/v1/alerts/{alert_item['id']}/resolve")
    assert resolve_res.status_code == 200
    assert resolve_res.json()["status"] == "RESOLVED"
    assert resolve_res.json()["resolved_at"] is not None


def test_api_predictions_filtering(client: TestClient):
    res = client.get("/api/v1/predictions")
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "items" in data
