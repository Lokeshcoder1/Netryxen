"""
Manual verification script for Module 1 Live Packet Capture.
Captures live traffic on an active host interface for a few seconds
and displays parsed metadata to verify Npcap and Scapy functionality.
"""
import sys
import time
import uuid

# Ensure backend directory is in sys.path
sys.path.insert(0, ".")

from app.capture.capture_manager import capture_manager
from app.capture.interface_discovery import InterfaceDiscoveryService, is_npcap_installed
from app.models.capture_session import SessionMode


def run_manual_test() -> None:
    print("=" * 60)
    print("NIDS Module 1 — Live Packet Capture Verification")
    print("=" * 60)

    # 1. Npcap verification
    npcap_status = is_npcap_installed()
    print(f"[*] Npcap driver installed: {npcap_status}")

    # 2. Interface discovery
    interfaces = InterfaceDiscoveryService.list_interfaces()
    print(f"[*] Discovered {len(interfaces)} interface(s):")
    active_iface = None
    for iface in interfaces:
        ip_info = f" ({', '.join(iface.ip_addresses)})" if iface.ip_addresses else ""
        print(f"    - [{iface.id}] {iface.name} - Status: {iface.status}{ip_info}")
        # Pick Wi-Fi or active interface with an IP
        if iface.status == "Up" and any("." in ip for ip in iface.ip_addresses) and not iface.is_loopback:
            if active_iface is None or "wi-fi" in iface.name.lower():
                active_iface = iface

    if not active_iface:
        print("[!] No active non-loopback network interface found with an IPv4 address.")
        if interfaces:
            active_iface = interfaces[0]
            print(f"[*] Falling back to: {active_iface.name}")
        else:
            print("[-] Cannot proceed with live capture test without network interfaces.")
            return

    print(f"\n[*] Selected target interface for test: [{active_iface.id}] {active_iface.name}")
    print("[*] Starting live capture for 5 seconds...")

    test_session_id = uuid.uuid4()
    try:
        capture_manager.start_capture(
            interface_id=active_iface.id,
            session_id=test_session_id,
            session_mode=SessionMode.MONITORING,
        )
    except Exception as exc:
        print(f"[!] Failed to start capture: {exc}")
        print("    Note: On Windows, packet sniffing may require Administrator privileges.")
        return

    # Sleep while packets arrive
    time.sleep(5.0)

    # Inspect preview while running
    preview = capture_manager.get_preview()
    status_now = capture_manager.get_status()
    print(f"[*] Intermediate stats: Seen={status_now.packets_seen}, Enqueued={status_now.packets_enqueued}, Dropped={status_now.packets_dropped}")

    # Stop capture
    stats = capture_manager.stop_capture()
    print(f"\n[+] Capture stopped cleanly!")
    print(f"    - Total packets seen:      {stats['packets_seen']}")
    print(f"    - Packets enqueued:        {stats['packets_enqueued']}")
    print(f"    - Packets dropped:         {stats['packets_dropped']}")
    print(f"    - Preview buffer count:    {stats['preview_count']}")

    print("\n[*] Sample captured packet metadata (Privacy-safe preview):")
    for i, pkt in enumerate(preview[:5], 1):
        flags_str = f" [{','.join(pkt.tcp_flags)}]" if pkt.tcp_flags else ""
        ports_str = f" :{pkt.src_port} -> :{pkt.dst_port}" if pkt.src_port or pkt.dst_port else ""
        print(f"  [{i}] {pkt.timestamp.strftime('%H:%M:%S.%f')} | {pkt.protocol_name}{flags_str} | {pkt.src_ip} -> {pkt.dst_ip}{ports_str} | Len={pkt.length}b")

    print("\n" + "=" * 60)
    print("Verification completed successfully.")
    print("=" * 60)


if __name__ == "__main__":
    run_manual_test()
