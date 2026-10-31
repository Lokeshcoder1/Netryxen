from collections import defaultdict
from datetime import datetime, timedelta, timezone
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import uuid

from app.core.config import settings
from app.core.logging import logger
from app.models.flow_record import FlowRecord
from app.schemas.packet import PacketEventSchema


def generate_canonical_flow_key(
    src_ip: Optional[str],
    dst_ip: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
    protocol: Optional[str],
) -> str:
    """
    Generates a deterministic bidirectional canonical flow key.
    Endpoints are ordered symmetrically: A->B and B->A produce identical keys.
    Protocols are strictly prefixed to prevent protocol mixing.
    """
    proto = (protocol or "UNKNOWN").upper()
    ep_a = (src_ip or "0.0.0.0", src_port or 0)
    ep_b = (dst_ip or "0.0.0.0", dst_port or 0)

    # Deterministic tuple comparison sorts endpoints
    ep1, ep2 = sorted([ep_a, ep_b])
    return f"{proto}:{ep1[0]}:{ep1[1]}<->{ep2[0]}:{ep2[1]}"


class FlowAccumulator:
    """
    In-memory state accumulator for a single bidirectional flow within an observation window.
    """

    def __init__(
        self,
        session_id: uuid.UUID,
        flow_key: str,
        window_start: datetime,
        window_end: datetime,
        first_packet: PacketEventSchema,
        local_ips: Set[str],
    ) -> None:
        self.session_id: uuid.UUID = session_id
        self.flow_key: str = flow_key
        self.window_start: datetime = window_start
        self.window_end: datetime = window_end
        self.local_ips: Set[str] = local_ips

        # Initiator endpoints defined by first packet seen in this window
        self.initiator_src_ip: Optional[str] = first_packet.src_ip
        self.initiator_dst_ip: Optional[str] = first_packet.dst_ip
        self.initiator_src_port: Optional[int] = first_packet.src_port
        self.initiator_dst_port: Optional[int] = first_packet.dst_port

        self.protocol: str = (first_packet.protocol_name or "UNKNOWN").upper()
        self.protocol_num: Optional[int] = first_packet.protocol_num

        # Timestamps
        pkt_time = first_packet.timestamp.astimezone(timezone.utc)
        self.first_seen: datetime = pkt_time
        self.last_seen: datetime = pkt_time

        # Counts and bytes
        self.packet_count: int = 0
        self.byte_count: int = 0
        self.fwd_packets: int = 0
        self.rev_packets: int = 0
        self.fwd_bytes: int = 0
        self.rev_bytes: int = 0

        # Packet sizes
        self.min_packet_size: int = first_packet.length
        self.max_packet_size: int = first_packet.length

        # TCP flags
        self.tcp_syn_count: int = 0
        self.tcp_ack_count: int = 0
        self.tcp_fin_count: int = 0
        self.tcp_rst_count: int = 0
        self.tcp_psh_count: int = 0

        # DNS counters
        self.dns_query_count: int = 0
        self.dns_unique_query_count: int = 0

        # Directional host-relative traffic
        self.upload_bytes: int = 0
        self.download_bytes: int = 0

        # Boolean indicators
        self.is_local: bool = False
        self.is_broadcast: bool = False
        self.is_multicast: bool = False

        # Add the first packet
        self.add_packet(first_packet)

    def add_packet(self, packet: PacketEventSchema) -> None:
        pkt_time = packet.timestamp.astimezone(timezone.utc)
        if pkt_time < self.first_seen:
            self.first_seen = pkt_time
        if pkt_time > self.last_seen:
            self.last_seen = pkt_time

        length = packet.length
        self.packet_count += 1
        self.byte_count += length

        # Update packet size bounds
        if length < self.min_packet_size:
            self.min_packet_size = length
        if length > self.max_packet_size:
            self.max_packet_size = length

        # Forward / Reverse direction tracking
        # Forward is initiator -> responder (matching the first packet seen)
        is_forward = (
            packet.src_ip == self.initiator_src_ip
            and packet.dst_ip == self.initiator_dst_ip
            and (self.initiator_src_port is None or packet.src_port == self.initiator_src_port)
        )
        if is_forward:
            self.fwd_packets += 1
            self.fwd_bytes += length
        else:
            self.rev_packets += 1
            self.rev_bytes += length

        # Host-relative Upload / Download tracking
        src_is_local = packet.src_ip in self.local_ips if packet.src_ip else False
        dst_is_local = packet.dst_ip in self.local_ips if packet.dst_ip else False

        if src_is_local and not dst_is_local:
            self.upload_bytes += length
        elif dst_is_local and not src_is_local:
            self.download_bytes += length
        elif src_is_local and dst_is_local:
            # Intra-host / loopback traffic
            self.upload_bytes += length
            self.download_bytes += length

        # TCP flags
        if packet.tcp_flags:
            flags_upper = {f.upper() for f in packet.tcp_flags}
            if "SYN" in flags_upper:
                self.tcp_syn_count += 1
            if "ACK" in flags_upper:
                self.tcp_ack_count += 1
            if "FIN" in flags_upper:
                self.tcp_fin_count += 1
            if "RST" in flags_upper:
                self.tcp_rst_count += 1
            if "PSH" in flags_upper:
                self.tcp_psh_count += 1

        # DNS counters
        self.dns_query_count += packet.dns_query_count
        self.dns_unique_query_count += packet.dns_unique_query_count

        # Indicators
        if packet.is_local:
            self.is_local = True
        if packet.is_broadcast:
            self.is_broadcast = True
        if packet.is_multicast:
            self.is_multicast = True

    def to_flow_record(self) -> FlowRecord:
        """
        Calculates final derived statistical rates and constructs a persistent FlowRecord model.
        Rates use an effective minimum duration clamp to prevent division by zero
        and unrealistic rate spikes caused by sub-millisecond durations.
        """
        duration = max(0.0, (self.last_seen - self.first_seen).total_seconds())

        # Safeguard: clamp duration to minimum 1.0 second for rate calculation
        # to prevent division-by-zero or unrealistic rate explosions on tiny micro-bursts
        rate_duration = max(duration, 1.0)
        pps = round(self.packet_count / rate_duration, 4)
        bps = round(self.byte_count / rate_duration, 4)

        avg_size = round(self.byte_count / self.packet_count, 2) if self.packet_count > 0 else 0.0

        total_up_down = self.upload_bytes + self.download_bytes
        upload_ratio = (
            round(self.upload_bytes / total_up_down, 4) if total_up_down > 0 else None
        )

        features: Dict[str, Any] = {
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "fwd_packets": self.fwd_packets,
            "rev_packets": self.rev_packets,
            "fwd_bytes": self.fwd_bytes,
            "rev_bytes": self.rev_bytes,
            "duration_seconds": duration,
            "packets_per_second": pps,
            "bytes_per_second": bps,
            "min_packet_size": self.min_packet_size,
            "max_packet_size": self.max_packet_size,
            "avg_packet_size": avg_size,
            "tcp_syn_count": self.tcp_syn_count,
            "tcp_ack_count": self.tcp_ack_count,
            "tcp_fin_count": self.tcp_fin_count,
            "tcp_rst_count": self.tcp_rst_count,
            "tcp_psh_count": self.tcp_psh_count,
            "dns_query_count": self.dns_query_count,
            "dns_unique_query_count": self.dns_unique_query_count,
            "upload_bytes": self.upload_bytes,
            "download_bytes": self.download_bytes,
            "upload_ratio": upload_ratio,
            "is_local": self.is_local,
            "is_broadcast": self.is_broadcast,
            "is_multicast": self.is_multicast,
            "protocol": self.protocol,
        }

        return FlowRecord(
            id=uuid.uuid4(),
            session_id=self.session_id,
            window_start=self.window_start,
            window_end=self.window_end,
            flow_key=self.flow_key,
            src_ip=self.initiator_src_ip,
            dst_ip=self.initiator_dst_ip,
            src_port=self.initiator_src_port,
            dst_port=self.initiator_dst_port,
            protocol=self.protocol,
            protocol_num=self.protocol_num,
            first_seen=self.first_seen,
            last_seen=self.last_seen,
            duration_seconds=duration,
            packet_count=self.packet_count,
            byte_count=self.byte_count,
            fwd_packets=self.fwd_packets,
            rev_packets=self.rev_packets,
            fwd_bytes=self.fwd_bytes,
            rev_bytes=self.rev_bytes,
            packets_per_second=pps,
            bytes_per_second=bps,
            min_packet_size=self.min_packet_size,
            max_packet_size=self.max_packet_size,
            avg_packet_size=avg_size,
            tcp_syn_count=self.tcp_syn_count,
            tcp_ack_count=self.tcp_ack_count,
            tcp_fin_count=self.tcp_fin_count,
            tcp_rst_count=self.tcp_rst_count,
            tcp_psh_count=self.tcp_psh_count,
            dns_query_count=self.dns_query_count,
            dns_unique_query_count=self.dns_unique_query_count,
            upload_bytes=self.upload_bytes,
            download_bytes=self.download_bytes,
            upload_ratio=upload_ratio,
            is_local=self.is_local,
            is_broadcast=self.is_broadcast,
            is_multicast=self.is_multicast,
            features=features,
            feature_schema_version="1.0",
        )


class FlowAggregator:
    """
    Consumes packet metadata from the BoundedPacketQueue, aggregates them into
    bidirectional flows over configurable 10-second windows, and persists finalized
    flow records into PostgreSQL.
    """

    def __init__(
        self,
        window_size_seconds: int = 10,
        worker_interval: float = 1.0,
        session_factory: Optional[Callable[[], Any]] = None,
        max_in_memory_flows: int = 50000,
    ) -> None:
        self.window_size_seconds: int = window_size_seconds
        self.worker_interval: float = worker_interval
        self._session_factory = session_factory
        self.max_in_memory_flows: int = max_in_memory_flows

        self._active_session_id: Optional[uuid.UUID] = None
        self._local_ips: Set[str] = set()
        self._packet_queue: Optional[Any] = None

        # In-memory accumulators: key is (canonical_flow_key, window_start)
        self._accumulators: Dict[Tuple[str, datetime], FlowAccumulator] = {}
        self._lock = threading.Lock()

        # Lifecycle control
        self._is_running: bool = False
        self._worker_thread: Optional[threading.Thread] = None

        # Metrics & observability
        self._total_flows_persisted: int = 0
        self._aggregation_errors: int = 0

    @property
    def is_running(self) -> bool:
        with self._lock:
            return self._is_running

    def _get_db_session(self) -> Any:
        if self._session_factory:
            return self._session_factory()
        from app.db.session import SessionLocal
        return SessionLocal()

    def start(
        self,
        session_id: uuid.UUID,
        packet_queue: Any,
        local_ips: Optional[List[str]] = None,
    ) -> None:
        """
        Starts the background aggregator worker thread for the given capture session.
        """
        with self._lock:
            if self._is_running:
                raise RuntimeError("FlowAggregator is already running")

            self._active_session_id = session_id
            self._packet_queue = packet_queue
            self._local_ips = set(local_ips or [])
            self._accumulators.clear()
            self._total_flows_persisted = 0
            self._aggregation_errors = 0
            self._is_running = True

            self._worker_thread = threading.Thread(
                target=self._worker_loop,
                name="FlowAggregatorWorker",
                daemon=True,
            )
            self._worker_thread.start()
            logger.info(
                f"FlowAggregator started: session={session_id}, window={self.window_size_seconds}s, local_ips={self._local_ips}"
            )

    def stop_and_flush(self) -> int:
        """
        Stops the worker thread, processes any remaining queued packets,
        and flushes all partial/open flow windows to PostgreSQL.
        Returns the total number of flow records persisted.
        """
        with self._lock:
            if not self._is_running:
                return 0
            self._is_running = False

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=10.0)

        # Drain any remaining packets from queue
        self._drain_remaining_packets()

        # Flush all active partial windows
        flushed_count = self._finalize_windows(force_all=True)

        with self._lock:
            self._active_session_id = None
            self._packet_queue = None
            self._worker_thread = None
            total = self._total_flows_persisted

        logger.info(f"FlowAggregator stopped: persisted total {total} flow records")
        return total

    def _process_packet(self, packet: PacketEventSchema) -> None:
        if not self._active_session_id:
            return

        flow_key = generate_canonical_flow_key(
            src_ip=packet.src_ip,
            dst_ip=packet.dst_ip,
            src_port=packet.src_port,
            dst_port=packet.dst_port,
            protocol=packet.protocol_name,
        )

        pkt_time = packet.timestamp.astimezone(timezone.utc)
        epoch = pkt_time.timestamp()
        w_start_sec = (int(epoch) // self.window_size_seconds) * self.window_size_seconds
        window_start = datetime.fromtimestamp(w_start_sec, tz=timezone.utc)
        window_end = window_start + timedelta(seconds=self.window_size_seconds)

        acc_key = (flow_key, window_start)

        # Check bounds before adding new flows
        if acc_key not in self._accumulators and len(self._accumulators) >= self.max_in_memory_flows:
            logger.warning("FlowAggregator in-memory capacity reached. Forcing early finalization of oldest windows.")
            self._finalize_windows(force_oldest=True)

        if acc_key in self._accumulators:
            self._accumulators[acc_key].add_packet(packet)
        else:
            self._accumulators[acc_key] = FlowAccumulator(
                session_id=self._active_session_id,
                flow_key=flow_key,
                window_start=window_start,
                window_end=window_end,
                first_packet=packet,
                local_ips=self._local_ips,
            )

    def _drain_remaining_packets(self) -> None:
        """
        Drains all remaining packet events from the bounded queue.
        """
        if not self._packet_queue:
            return

        count = 0
        while True:
            pkt = self._packet_queue.pop(timeout=0.01)
            if pkt is None:
                break
            self._process_packet(pkt)
            count += 1

        if count > 0:
            logger.debug(f"FlowAggregator drained {count} remaining packets from queue")

    def _finalize_windows(self, force_all: bool = False, force_oldest: bool = False) -> int:
        """
        Extracts eligible or expired flow windows, converts them to FlowRecord models,
        and persists them into PostgreSQL in batches.
        """
        now = datetime.now(timezone.utc)
        grace_period = timedelta(seconds=2)  # allow slightly delayed packets to enter current window

        keys_to_finalize: List[Tuple[str, datetime]] = []

        if force_all:
            keys_to_finalize = list(self._accumulators.keys())
        elif force_oldest:
            # Sort windows by start time and finalize the oldest half
            sorted_keys = sorted(self._accumulators.keys(), key=lambda k: k[1])
            keys_to_finalize = sorted_keys[: len(sorted_keys) // 2]
        else:
            for (key, w_start), acc in self._accumulators.items():
                if acc.window_end + grace_period <= now:
                    keys_to_finalize.append((key, w_start))

        if not keys_to_finalize:
            return 0

        records: List[FlowRecord] = []
        for k in keys_to_finalize:
            acc = self._accumulators.pop(k, None)
            if acc:
                records.append(acc.to_flow_record())

        if not records:
            return 0

        # Persist to PostgreSQL
        try:
            from app.repositories.flow_repository import FlowRepository
            db = self._get_db_session()
            try:
                FlowRepository.create_batch(db, records)
                with self._lock:
                    self._total_flows_persisted += len(records)
                logger.info(f"Persisted {len(records)} flow records to database")
            finally:
                db.close()
        except Exception as exc:
            with self._lock:
                self._aggregation_errors += 1
            logger.error(f"Error persisting {len(records)} flow records to database: {exc}")

        return len(records)

    def _worker_loop(self) -> None:
        """
        Continuous background aggregation loop.
        """
        last_check_monotonic = time.monotonic()

        while True:
            with self._lock:
                if not self._is_running:
                    break

            # Consume up to 500 packets in a quick burst
            batch_count = 0
            while batch_count < 500:
                pkt = self._packet_queue.pop(timeout=0.1) if self._packet_queue else None
                if pkt is None:
                    break
                self._process_packet(pkt)
                batch_count += 1

            # Check for window expirations periodically
            now_mono = time.monotonic()
            if now_mono - last_check_monotonic >= self.worker_interval:
                last_check_monotonic = now_mono
                self._finalize_windows(force_all=False)

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns atomic metrics snapshot of aggregator state.
        """
        with self._lock:
            return {
                "is_running": self._is_running,
                "window_size_seconds": self.window_size_seconds,
                "active_windows_count": len(self._accumulators),
                "total_flows_persisted": self._total_flows_persisted,
                "aggregation_errors": self._aggregation_errors,
            }


# Global singleton aggregator instance
flow_aggregator = FlowAggregator(
    window_size_seconds=settings.FLOW_WINDOW_SECONDS,
    worker_interval=settings.FLOW_AGGREGATOR_INTERVAL_SECONDS,
    max_in_memory_flows=settings.FLOW_MEMORY_CAPACITY,
)
