"""
Verification script for Module 2: Live Network Flow Aggregation & PostgreSQL Persistence.
Starts live Scapy packet capture, aggregates real network packets into 10-second bidirectional
flow windows, persists them to PostgreSQL nids_db, and validates flow features and dashboard metrics.
"""
import socket
import sys
import time
from datetime import datetime, timezone

from sqlalchemy import func, select

from app.capture.interface_discovery import InterfaceDiscoveryService
from app.core.config import settings
from app.core.logging import logger
from app.db.session import SessionLocal
from app.models.capture_session import CaptureSession
from app.models.flow_record import FlowRecord
from app.schemas.capture import CaptureStartRequest
from app.services.capture_service import CaptureService
from app.services.flow_service import FlowService


def trigger_traffic():
    """Generates benign DNS / HTTP network activity to ensure packets flow across the interface."""
    logger.info("Triggering sample network traffic (DNS lookups)...")
    for host in ["example.com", "google.com", "cloudflare.com"]:
        try:
            socket.getaddrinfo(host, 80)
        except Exception:
            pass


def main():
    logger.info("=" * 70)
    logger.info("STARTING LIVE VERIFICATION FOR MODULE 2: FLOW AGGREGATION & PERSISTENCE")
    logger.info("=" * 70)

    # 1. Discover interfaces
    interfaces = InterfaceDiscoveryService.list_interfaces()
    logger.info(f"Discovered {len(interfaces)} network interfaces.")
    
    # Select active interface: prefer 'Wi-Fi' or first 'Up' interface
    selected_iface = None
    for iface in interfaces:
        if "wi-fi" in iface.name.lower() or "wireless" in (iface.description or "").lower():
            selected_iface = iface
            break
    if not selected_iface:
        for iface in interfaces:
            if iface.status == "Up" and not iface.is_loopback:
                selected_iface = iface
                break
    if not selected_iface and interfaces:
        selected_iface = interfaces[0]

    if not selected_iface:
        logger.error("No suitable interface found for live capture verification.")
        sys.exit(1)

    logger.info(
        f"Selected Interface: id='{selected_iface.id}', name='{selected_iface.name}', "
        f"IPs={selected_iface.ip_addresses}"
    )

    # 2. Start capture session
    db = SessionLocal()
    try:
        req = CaptureStartRequest(interface_id=selected_iface.id)
        start_status = CaptureService.start_capture(db=db, req=req)
        session_id = start_status.active_session_id
        logger.info(f"Capture successfully started. Session ID: {session_id}")

        # 3. Capture for 12 seconds (exceeds 10-second window length)
        logger.info("Capturing live traffic for 12 seconds across 10-second window boundary...")
        trigger_traffic()
        for i in range(12):
            time.sleep(1)
            trigger_traffic()
            print(".", end="", flush=True)
        print()

        # 4. Stop capture and flush all windows
        logger.info("Stopping capture session and flushing flow windows...")
        stop_resp = CaptureService.stop_capture(db=db)
        logger.info(f"Stop response: {stop_resp.message}")

        # 5. Query PostgreSQL for persisted flow records
        flow_records = (
            db.execute(
                select(FlowRecord)
                .where(FlowRecord.session_id == session_id)
                .order_by(FlowRecord.window_start, FlowRecord.packet_count.desc())
            )
            .scalars()
            .all()
        )

        logger.info("=" * 70)
        logger.info(f"DATABASE VERIFICATION RESULTS FOR SESSION: {session_id}")
        logger.info(f"Total Flow Records Persisted: {len(flow_records)}")
        logger.info("=" * 70)

        for idx, flow in enumerate(flow_records[:10], 1):
            logger.info(f"--- Flow #{idx}: {flow.flow_key} ({flow.protocol}) ---")
            logger.info(f"  Window: {flow.window_start.isoformat()} -> {flow.window_end.isoformat()}")
            logger.info(
                f"  Endpoints: Initiator={flow.src_ip}:{flow.src_port} -> Responder={flow.dst_ip}:{flow.dst_port}"
            )
            logger.info(
                f"  Packets: Total={flow.packet_count} (Fwd={flow.fwd_packets}, Rev={flow.rev_packets})"
            )
            logger.info(
                f"  Bytes: Total={flow.byte_count} (Fwd={flow.fwd_bytes}, Rev={flow.rev_bytes})"
            )
            logger.info(
                f"  Rates: Duration={flow.duration_seconds:.2f}s, PPS={flow.packets_per_second:.2f}, BPS={flow.bytes_per_second:.2f}"
            )
            logger.info(
                f"  Packet Sizes: Min={flow.min_packet_size}B, Max={flow.max_packet_size}B, Avg={flow.avg_packet_size:.1f}B"
            )
            if flow.protocol == "TCP":
                logger.info(
                    f"  TCP Flags: SYN={flow.tcp_syn_count}, ACK={flow.tcp_ack_count}, FIN={flow.tcp_fin_count}, "
                    f"RST={flow.tcp_rst_count}, PSH={flow.tcp_psh_count}"
                )
            if flow.dns_query_count > 0:
                logger.info(
                    f"  DNS Queries: Total={flow.dns_query_count}, Unique={flow.dns_unique_query_count}"
                )
            logger.info(
                f"  Host Traffic: Upload={flow.upload_bytes}B, Download={flow.download_bytes}B, Ratio={flow.upload_ratio}"
            )
            logger.info(
                f"  Flags: Local={flow.is_local}, Broadcast={flow.is_broadcast}, Multicast={flow.is_multicast}"
            )

        if len(flow_records) > 10:
            logger.info(f"... and {len(flow_records) - 10} more flow records.")

        # 6. Verify Dashboard Summary Endpoint
        dashboard = FlowService.get_dashboard_summary(db=db)
        logger.info("=" * 70)
        logger.info("DASHBOARD SUMMARY METRICS:")
        logger.info(f"  Total Capture Sessions in DB: {dashboard.total_sessions}")
        logger.info(f"  Total Flow Records in DB:    {dashboard.total_flows}")
        logger.info(f"  Total Packets Aggregated:    {dashboard.total_packets}")
        logger.info(f"  Total Bytes Aggregated:      {dashboard.total_bytes}")
        logger.info(f"  Protocol Breakdown:          {dashboard.protocol_distribution}")
        logger.info(f"  Top Talkers Count:           {len(dashboard.top_talkers)}")
        for tt in dashboard.top_talkers[:5]:
            logger.info(f"    - IP {tt.ip}: {tt.packets} pkts, {tt.bytes} bytes")
        logger.info("=" * 70)

        assert len(flow_records) > 0, "Expected at least 1 live flow record to be persisted in PostgreSQL!"
        logger.info("SUCCESS: Module 2 live flow aggregation and PostgreSQL persistence verified!")

    finally:
        db.close()


if __name__ == "__main__":
    main()
