from datetime import datetime, timezone
import threading
from typing import Any, Dict, List, Optional
import uuid

from scapy.sendrecv import AsyncSniffer

from app.capture.interface_discovery import InterfaceDiscoveryService
from app.capture.packet_parser import PacketParser
from app.capture.packet_queue import BoundedPacketQueue
from app.core.config import settings
from app.core.logging import logger
from app.models.capture_session import SessionMode
from app.schemas.capture import CaptureStatusResponse
from app.schemas.packet import PacketEventSchema


class CaptureManager:
    """
    Manages non-blocking network packet capture lifecycle via Scapy AsyncSniffer.
    Enforces concurrency controls, interface validation, queue backpressure,
    and thread-safe state inspection.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.packet_queue = BoundedPacketQueue(
            capacity=settings.CAPTURE_QUEUE_CAPACITY,
            preview_capacity=settings.CAPTURE_PREVIEW_CAPACITY,
        )
        self._sniffer: Optional[AsyncSniffer] = None
        self._is_running: bool = False
        self._active_session_id: Optional[uuid.UUID] = None
        self._interface_id: Optional[str] = None
        self._session_mode: Optional[SessionMode] = None
        self._started_at: Optional[datetime] = None
        self._error_summary: Optional[str] = None

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def _packet_callback(self, pkt: Any) -> None:
        """
        Lightweight Scapy callback. Must NEVER perform DB queries, disk I/O, or ML.
        """
        try:
            self.packet_queue.increment_seen()
            event = PacketParser.parse(pkt)
            if event is not None:
                self.packet_queue.push(event)
        except Exception as exc:
            # Under live packet capture, individual packet parse errors must never crash the sniffer
            logger.debug(f"Packet parsing callback error: {exc}")

    def start_capture(
        self,
        interface_id: str,
        session_id: uuid.UUID,
        session_mode: SessionMode = SessionMode.MONITORING,
        bpf_filter: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Starts live packet capture on the validated interface.
        """
        with self._lock:
            if self._is_running:
                raise RuntimeError("A capture session is already actively running")

            # Validate interface existence
            iface = InterfaceDiscoveryService.get_interface_by_id(interface_id)
            if not iface:
                raise ValueError(f"Invalid interface ID: '{interface_id}'. Interface not found.")

            # Reset queue counters for the new session
            self.packet_queue.reset()
            self._error_summary = None

            try:
                # Scapy on Windows can accept interface name or GUID or Iface object
                self._sniffer = AsyncSniffer(
                    iface=iface.id,
                    prn=self._packet_callback,
                    store=False,
                    filter=bpf_filter,
                )
                self._sniffer.start()
            except Exception as exc:
                self._error_summary = f"Capture startup failed: {str(exc)}"
                logger.error(f"Failed to start Scapy AsyncSniffer on {interface_id}: {exc}")
                raise RuntimeError(self._error_summary) from exc

            self._is_running = True
            self._active_session_id = session_id
            self._interface_id = iface.id
            self._session_mode = session_mode
            self._started_at = datetime.now(timezone.utc)

            logger.info(
                f"Capture started: session={session_id}, interface={iface.id}, mode={session_mode.value}"
            )
            return self._get_status_unlocked()

    def stop_capture(self) -> Dict[str, Any]:
        """
        Stops the currently running capture session cleanly.
        """
        with self._lock:
            if not self._is_running or not self._sniffer:
                raise RuntimeError("No capture session is currently running")

            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.warning(f"Error while stopping AsyncSniffer: {exc}")
                self._error_summary = f"Stop error: {str(exc)}"

            stopped_session_id = self._active_session_id
            stats = self.packet_queue.get_stats()
            self._is_running = False
            self._sniffer = None
            self._active_session_id = None
            self._interface_id = None
            self._session_mode = None
            self._started_at = None

            logger.info(
                f"Capture stopped: session={stopped_session_id}, stats={stats}"
            )
            return stats

    def get_status(self) -> CaptureStatusResponse:
        """
        Thread-safe snapshot of capture status and metrics.
        """
        with self._lock:
            status_dict = self._get_status_unlocked()
            return CaptureStatusResponse(**status_dict)

    def _get_status_unlocked(self) -> Dict[str, Any]:
        stats = self.packet_queue.get_stats()
        return {
            "is_running": self._is_running,
            "active_session_id": self._active_session_id,
            "interface_id": self._interface_id,
            "session_mode": self._session_mode,
            "started_at": self._started_at,
            "packets_seen": stats["packets_seen"],
            "packets_enqueued": stats["packets_enqueued"],
            "packets_dropped": stats["packets_dropped"],
            "queue_size": stats["queue_size"],
            "queue_capacity": stats["queue_capacity"],
            "preview_count": stats["preview_count"],
            "error_summary": self._error_summary,
        }

    def get_preview(self) -> List[PacketEventSchema]:
        """
        Returns recent packet events from preview ring-buffer.
        """
        return self.packet_queue.get_preview()


# Global capture manager singleton
capture_manager = CaptureManager()
