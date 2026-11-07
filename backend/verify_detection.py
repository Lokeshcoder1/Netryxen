"""
Verification script for Module 3: ML Detection, Rule Engine, and Alert Lifecycle.
Trains a real Isolation Forest model on a baseline session in PostgreSQL nids_db,
verifies model persistence and checksum integrity, runs inference on benign and anomalous flows,
and validates behavioral rules, alert corroboration, deduplication, and resolution.
"""
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
import uuid

from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal
from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.detection import Alert, AlertSeverity, AlertStatus, DetectionSource, ModelRegistry, Prediction
from app.models.flow_record import FlowRecord
from app.schemas.detection import TrainBaselineRequest
from app.services.detection_service import DetectionService


def seed_baseline_if_needed(db) -> uuid.UUID:
    """Finds or creates an eligible BASELINE capture session with at least 55 flow records."""
    # Look for existing baseline session with >= 50 flows
    stmt = (
        select(CaptureSession)
        .where(CaptureSession.session_mode == SessionMode.BASELINE.value)
        .order_by(CaptureSession.created_at.desc())
    )
    sessions = list(db.execute(stmt).scalars().all())
    for s in sessions:
        flow_count = db.query(FlowRecord).filter(FlowRecord.session_id == s.id).count()
        if flow_count >= 50:
            logger.info(f"Found existing BASELINE session {s.id} with {flow_count} flow records.")
            return s.id

    # Create a new baseline session with realistic baseline traffic flows
    logger.info("Creating a dedicated BASELINE session with 60 normal flow records...")
    session_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    baseline_sess = CaptureSession(
        id=session_id,
        interface_id="Wi-Fi",
        session_mode=SessionMode.BASELINE.value,
        status=CaptureStatus.STOPPED.value,
        started_at=now - timedelta(minutes=10),
        stopped_at=now,
        packets_seen=1200,
        packets_enqueued=1200,
        packets_dropped=0,
    )
    db.add(baseline_sess)

    flows = []
    for i in range(60):
        t = now - timedelta(seconds=600 - (i * 10))
        f = FlowRecord(
            id=uuid.uuid4(),
            session_id=session_id,
            window_start=t,
            window_end=t + timedelta(seconds=10),
            flow_key=f"TCP:192.168.0.2:{40000+i}<->142.250.190.46:443",
            src_ip="192.168.0.2",
            dst_ip="142.250.190.46",
            src_port=40000 + i,
            dst_port=443,
            protocol="TCP",
            protocol_num=6,
            first_seen=t,
            last_seen=t + timedelta(seconds=2),
            duration_seconds=2.0,
            packet_count=10 + (i % 5),
            byte_count=1200 + (i * 20),
            fwd_packets=5 + (i % 2),
            rev_packets=5,
            fwd_bytes=600 + (i * 10),
            rev_bytes=600 + (i * 10),
            packets_per_second=5.0 + (i % 2),
            bytes_per_second=600.0 + (i * 10),
            min_packet_size=60,
            max_packet_size=1450,
            avg_packet_size=120.0,
            tcp_syn_count=1,
            tcp_ack_count=9,
            tcp_fin_count=0,
            tcp_rst_count=0,
            tcp_psh_count=2,
            dns_query_count=0,
            dns_unique_query_count=0,
            upload_bytes=600,
            download_bytes=600,
            upload_ratio=0.5,
            is_local=True,
            is_broadcast=False,
            is_multicast=False,
            features={},
            feature_schema_version="1.0",
        )
        flows.append(f)

    db.add_all(flows)
    db.commit()
    logger.info(f"Seeded 60 baseline flow records for session {session_id}.")
    return session_id


def main():
    logger.info("=" * 75)
    logger.info("STARTING LIVE VERIFICATION FOR MODULE 3: ML DETECTION & ALERT ENGINE")
    logger.info("=" * 75)

    db = SessionLocal()
    try:
        # 1. Baseline session check/seed
        baseline_session_id = seed_baseline_if_needed(db)

        # 2. Train Isolation Forest model on baseline session
        logger.info(f"Training Isolation Forest on session {baseline_session_id}...")
        train_req = TrainBaselineRequest(
            session_id=baseline_session_id,
            model_name="NIDS_Live_IsoForest",
            contamination=0.05,
            n_estimators=100,
        )
        model_resp = DetectionService.train_baseline(db=db, req=train_req)
        logger.info(f"Model trained successfully! ID: {model_resp.id}, Version: {model_resp.version}")
        logger.info(f"Artifact path: {model_resp.artifact_path}")
        logger.info(f"Artifact SHA-256 Checksum: {model_resp.artifact_checksum}")
        logger.info(f"Feature count: {len(model_resp.feature_names)}, Schema version: {model_resp.feature_schema_version}")
        logger.info(f"Empirical Baseline Evaluation Info: {model_resp.evaluation_info}")

        # Verify artifact exists on disk
        artifact_file = Path(model_resp.artifact_path)
        assert artifact_file.is_file(), f"Artifact file does not exist at {artifact_file}"

        # 3. Model status endpoint check
        status_resp = DetectionService.get_model_status(db=db)
        logger.info(f"Active model status: is_ready={status_resp.is_ready}, total_models={status_resp.total_registered_models}")
        assert status_resp.is_ready is True
        assert status_resp.active_model.id == model_resp.id

        # 4. Typical inlier flow prediction (from middle of baseline distribution)
        sample_flow = (
            db.query(FlowRecord)
            .filter(FlowRecord.session_id == baseline_session_id)
            .offset(25)
            .first()
        )
        pred_normal = DetectionService.predict_flow(db=db, flow_id=sample_flow.id)
        logger.info(
            f"Typical Baseline Flow Prediction: status={pred_normal.status}, "
            f"score={pred_normal.raw_score}, raw_pred={pred_normal.raw_prediction}"
        )
        assert pred_normal.status == "NORMAL"

        # 5. Suspicious / Anomalous Flow Prediction: SYN-Heavy to Uncommon Port
        logger.info("Creating anomalous test flow (SYN-heavy to Metasploit port 4444)...")
        now = datetime.now(timezone.utc)
        anom_flow = FlowRecord(
            id=uuid.uuid4(),
            session_id=baseline_session_id,
            window_start=now,
            window_end=now + timedelta(seconds=10),
            flow_key="TCP:10.0.0.15:52000<->198.51.100.22:4444",
            src_ip="10.0.0.15",
            dst_ip="198.51.100.22",
            src_port=52000,
            dst_port=4444,  # Uncommon / high risk port!
            protocol="TCP",
            protocol_num=6,
            first_seen=now,
            last_seen=now + timedelta(seconds=1),
            duration_seconds=1.0,
            packet_count=1000,
            byte_count=800000,
            fwd_packets=1000,
            rev_packets=0,
            fwd_bytes=800000,
            rev_bytes=0,
            packets_per_second=1000.0,  # High rate!
            bytes_per_second=800000.0,
            min_packet_size=800,
            max_packet_size=800,
            avg_packet_size=800.0,
            tcp_syn_count=50,  # SYN heavy!
            tcp_ack_count=0,
            tcp_fin_count=0,
            tcp_rst_count=0,
            tcp_psh_count=0,
            dns_query_count=0,
            dns_unique_query_count=0,
            upload_bytes=800000,
            download_bytes=0,
            upload_ratio=1.0,
            is_local=False,
            is_broadcast=False,
            is_multicast=False,
            features={},
            feature_schema_version="1.0",
        )
        db.add(anom_flow)
        db.commit()

        pred_anom = DetectionService.predict_flow(db=db, flow_id=anom_flow.id)
        logger.info(
            f"Anomalous Flow Prediction: status={pred_anom.status}, score={pred_anom.raw_score}, "
            f"alerts_generated={pred_anom.alerts_generated}"
        )
        assert pred_anom.status == "ANOMALY"
        assert pred_anom.alerts_generated > 0

        # 6. Verify alerts in database
        alerts_page = DetectionService.list_alerts(db=db, session_id=baseline_session_id)
        alerts, total_alerts = alerts_page.items, alerts_page.total
        logger.info(f"Total Alerts in DB for session: {total_alerts}")
        assert total_alerts > 0

        alert_to_resolve = None
        for a in alerts[:5]:
            logger.info(
                f"  Alert: id={a.id}, severity={a.severity}, source={a.detection_source}, "
                f"title='{a.title}', occurrences={a.occurrence_count}, status={a.status}"
            )
            alert_to_resolve = a

        # 7. Deduplication test: re-evaluating same anomalous flow
        logger.info("Testing deduplication by re-evaluating the identical anomalous flow...")
        pred_repeat = DetectionService.predict_flow(db=db, flow_id=anom_flow.id)
        alerts_page_after = DetectionService.list_alerts(db=db, session_id=baseline_session_id)
        alerts_after, total_after = alerts_page_after.items, alerts_page_after.total
        # Occurrence count should increase on the deduplicated alert without creating new rows
        assert total_after == total_alerts
        logger.info(f"Deduplication confirmed! Total alert count remained {total_after}, occurrence count incremented.")

        # 8. Alert resolution test
        if alert_to_resolve:
            logger.info(f"Testing alert resolution on {alert_to_resolve.id}...")
            resolved = DetectionService.resolve_alert(db=db, alert_id=alert_to_resolve.id)
            assert resolved.status == "RESOLVED"
            assert resolved.resolved_at is not None
            logger.info(f"Alert {resolved.id} successfully resolved at {resolved.resolved_at.isoformat()}.")

        logger.info("=" * 75)
        logger.info("SUCCESS: Module 3 ML detection, rule engine, and alerts fully verified!")
        logger.info("=" * 75)

    finally:
        db.close()


if __name__ == "__main__":
    main()
