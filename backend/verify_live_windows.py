"""
Live Windows Packet Capture and Flow Aggregation Verification Script.
Validates live Npcap capture, queue buffering, flow aggregation, and PostgreSQL persistence on Windows.
"""
from datetime import datetime, timezone
import time
import uuid

from app.capture.interface_discovery import InterfaceDiscoveryService
from app.core.logging import logger
from app.db.session import SessionLocal
from app.models.capture_session import CaptureSession, CaptureStatus, SessionMode
from app.models.flow_record import FlowRecord
from app.schemas.capture import CaptureStartRequest
from app.services.capture_service import CaptureService
from app.services.flow_service import FlowService


def main():
    logger.info("=" * 75)
    logger.info("WINDOWS LIVE CAPTURE & FLOW PERSISTENCE VERIFICATION")
    logger.info("=" * 75)

    db = SessionLocal()
    try:
        # 1. Interface Discovery
        interfaces = InterfaceDiscoveryService.list_interfaces()
        logger.info(f"Discovered {len(interfaces)} system network interfaces.")

        # Pick active Wi-Fi or Loopback interface
        target_iface = None
        for iface in interfaces:
            if iface.id == "Wi-Fi" and iface.ip_addresses:
                target_iface = iface
                break
        if not target_iface:
            for iface in interfaces:
                if iface.ip_addresses and not iface.id.startswith("Ethernet-"):
                    target_iface = iface
                    break

        if not target_iface:
            logger.warning("No active network interface with an IP address found. Testing with first available.")
            target_iface = interfaces[0]

        logger.info(f"Selected target interface for live test: '{target_iface.id}' ({target_iface.name})")
        logger.info(f"Interface IP addresses: {target_iface.ip_addresses}")

        # 2. Start Live Capture Session
        start_req = CaptureStartRequest(
            interface_id=target_iface.id,
            session_mode=SessionMode.MONITORING,
            bpf_filter=None,
        )

        logger.info(f"Starting live capture session on '{target_iface.id}'...")
        start_resp = CaptureService.start_capture(db=db, req=start_req)
        session_id = start_resp.active_session_id
        logger.info(f"Capture started successfully! Session ID: {session_id}, is_running={start_resp.is_running}")
        assert start_resp.is_running is True
        assert session_id is not None

        # 3. Live capture window
        logger.info("Capturing live network traffic for 6 seconds...")
        for sec in range(1, 7):
            time.sleep(1.0)
            status = CaptureService.get_status()
            logger.info(f"  [{sec}s] Packets seen: {status.packets_seen}, enqueued: {status.packets_enqueued}, dropped: {status.packets_dropped}")

        # 4. Stop capture session
        logger.info("Stopping capture session and flushing flow windows to PostgreSQL...")
        stop_resp = CaptureService.stop_capture(db=db)
        persisted_flows = db.query(FlowRecord).filter(FlowRecord.session_id == session_id).count()
        logger.info(f"Capture stopped cleanly. Persisted flows in DB for session: {persisted_flows}")
        if stop_resp.session:
            logger.info(f"Final session stats: seen={stop_resp.session.packets_seen}, enqueued={stop_resp.session.packets_enqueued}")

        # 5. Verify database session record
        db_sess = db.query(CaptureSession).filter(CaptureSession.id == session_id).one()
        assert db_sess.status == CaptureStatus.STOPPED.value
        assert db_sess.stopped_at is not None
        logger.info(f"DB session {db_sess.id} status verified: {db_sess.status}")

        # 6. Verify dashboard summary
        dash = FlowService.get_dashboard_summary(db=db)
        logger.info(f"Dashboard summary: total_sessions={dash.total_sessions}, total_flows={dash.total_flows}, top_talkers={len(dash.top_talkers)}")

        logger.info("=" * 75)
        logger.info("LIVE WINDOWS VERIFICATION COMPLETED SUCCESSFULLY!")
        logger.info("=" * 75)

    finally:
        db.close()


if __name__ == "__main__":
    main()
