import os
from datetime import datetime, timezone
from pathlib import Path
import tempfile
import uuid
import pytest
from sqlalchemy.orm import Session

from app.ml.features import (
    FEATURE_NAMES,
    FEATURE_SCHEMA_VERSION,
    extract_features_from_dict,
    extract_features_from_flow,
    flows_to_feature_matrix,
)
from app.ml.model_manager import ModelManager, model_manager
from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.detection import ModelStatus, PredictionStatus
from app.models.flow_record import FlowRecord


def make_dummy_flow(
    packet_count: int = 10,
    byte_count: int = 1000,
    duration_seconds: float = 2.0,
    pps: float = 5.0,
    bps: float = 500.0,
    syn_count: int = 1,
    ack_count: int = 9,
    rst_count: int = 0,
    dns_count: int = 0,
    dst_port: int = 443,
    upload_ratio: float = 0.5,
) -> FlowRecord:
    f_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    return FlowRecord(
        id=f_id,
        session_id=uuid.uuid4(),
        window_start=now,
        window_end=now,
        flow_key=f"TCP:192.168.1.50:50000<->93.184.216.34:{dst_port}",
        src_ip="192.168.1.50",
        dst_ip="93.184.216.34",
        src_port=50000,
        dst_port=dst_port,
        protocol="TCP",
        protocol_num=6,
        first_seen=now,
        last_seen=now,
        duration_seconds=duration_seconds,
        packet_count=packet_count,
        byte_count=byte_count,
        fwd_packets=packet_count // 2,
        rev_packets=packet_count - (packet_count // 2),
        fwd_bytes=byte_count // 2,
        rev_bytes=byte_count - (byte_count // 2),
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
        dns_query_count=dns_count,
        dns_unique_query_count=dns_count,
        upload_bytes=byte_count // 2,
        download_bytes=byte_count - (byte_count // 2),
        upload_ratio=upload_ratio,
        is_local=True,
        is_broadcast=False,
        is_multicast=False,
        features={},
        feature_schema_version="1.0",
    )


def test_feature_extraction_order_and_completeness():
    flow = make_dummy_flow()
    vec = extract_features_from_flow(flow)
    assert len(vec) == len(FEATURE_NAMES)
    assert len(vec) == 22
    assert FEATURE_SCHEMA_VERSION == "1.0"
    # Check that duration is first and upload_ratio is last
    assert vec[0] == 2.0
    assert vec[-1] == 0.5


def test_feature_matrix_conversion():
    flows = [make_dummy_flow(packet_count=i) for i in range(1, 6)]
    mat = flows_to_feature_matrix(flows)
    assert mat.shape == (5, 22)


def test_model_not_ready_handling():
    mgr = ModelManager()
    mgr.reset()
    assert not mgr.is_model_ready

    flow = make_dummy_flow()
    status, score, raw_pred = mgr.predict_flow(flow)
    assert status == PredictionStatus.MODEL_NOT_READY
    assert score is None
    assert raw_pred is None


def test_baseline_validation_insufficient_samples():
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = ModelManager(artifacts_dir=tmp_dir)
        # Empty flows
        with pytest.raises(ValueError, match="empty dataset"):
            mgr.train_baseline(session_id=uuid.uuid4(), flows=[])

        # Less than min_samples
        flows = [make_dummy_flow() for _ in range(5)]
        with pytest.raises(ValueError, match="Insufficient baseline samples"):
            mgr.train_baseline(session_id=uuid.uuid4(), flows=flows, min_samples=20)


def test_model_fit_save_and_reload():
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = ModelManager(artifacts_dir=tmp_dir)
        # Generate 60 diverse baseline flows
        flows = []
        for i in range(60):
            flows.append(
                make_dummy_flow(
                    packet_count=10 + (i % 5),
                    byte_count=1000 + (i * 20),
                    duration_seconds=1.0 + (i % 3),
                    pps=5.0 + (i % 2),
                    bps=500.0 + (i * 10),
                )
            )

        sess_id = uuid.uuid4()
        res = mgr.train_baseline(
            session_id=sess_id,
            flows=flows,
            model_name="Test_IsoForest",
            min_samples=50,
            n_estimators=50,
        )

        assert res["status"] == ModelStatus.READY.value
        assert os.path.exists(res["artifact_path"])
        assert res["artifact_checksum"] is not None
        assert mgr.is_model_ready

        # Test reload in fresh manager
        mgr2 = ModelManager(artifacts_dir=tmp_dir)
        mgr2.load_artifact(
            artifact_path=res["artifact_path"],
            expected_checksum=res["artifact_checksum"],
            model_id=res["id"],
            model_version=res["version"],
        )
        assert mgr2.is_model_ready
        assert mgr2.active_model_info["model_id"] == res["id"]

        # Checksum mismatch fails
        with pytest.raises(ValueError, match="checksum verification failed"):
            mgr2.load_artifact(
                artifact_path=res["artifact_path"],
                expected_checksum="invalid_checksum_hash_0000000000",
            )


def test_inference_predictions_on_normal_and_anomalous():
    with tempfile.TemporaryDirectory() as tmp_dir:
        mgr = ModelManager(artifacts_dir=tmp_dir)
        # Train on normal baseline with natural variance
        flows = [
            make_dummy_flow(
                packet_count=10 + (i % 6),
                byte_count=1000 + (i * 20),
                pps=5.0 + (i % 3),
                bps=500.0 + (i * 10),
            )
            for i in range(60)
        ]
        mgr.train_baseline(
            session_id=uuid.uuid4(),
            flows=flows,
            min_samples=50,
            n_estimators=100,
            contamination=0.05,
        )

        # 1. Normal flow matching baseline
        normal_flow = make_dummy_flow(packet_count=12, byte_count=1040, pps=6.0, bps=520.0)
        status, score, raw_pred = mgr.predict_flow(normal_flow)
        assert status == PredictionStatus.NORMAL
        assert raw_pred == 1
        assert isinstance(score, float)
        assert score >= 0.0

        # 2. Extreme anomalous flow (huge pps, massive bytes, abnormal flags)
        anomaly_flow = make_dummy_flow(
            packet_count=50000,
            byte_count=50000000,
            pps=25000.0,
            bps=25000000.0,
            syn_count=1000,
            ack_count=0,
            rst_count=500,
        )
        a_status, a_score, a_pred = mgr.predict_flow(anomaly_flow)
        assert a_status == PredictionStatus.ANOMALY
        assert a_pred == -1
        assert isinstance(a_score, float)
        assert a_score < 0.0
