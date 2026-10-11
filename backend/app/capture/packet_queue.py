from collections import deque
import queue
import threading
from typing import Any, Dict, List, Optional

from app.schemas.packet import PacketEventSchema


class BoundedPacketQueue:
    """
    Thread-safe, bounded packet event queue with drop counter and diagnostic preview buffer.
    Ensures backpressure protection: when queue capacity is reached, new packets are
    dropped and counted rather than exhausting host memory.
    """

    def __init__(self, capacity: int = 10000, preview_capacity: int = 50) -> None:
        self.capacity: int = capacity
        self.preview_capacity: int = preview_capacity
        self._queue: queue.Queue[PacketEventSchema] = queue.Queue(maxsize=capacity)
        self._preview_buffer: deque[PacketEventSchema] = deque(maxlen=preview_capacity)
        self._lock: threading.Lock = threading.Lock()

        # Metrics counters
        self._packets_seen: int = 0
        self._packets_enqueued: int = 0
        self._packets_dropped: int = 0

    def increment_seen(self) -> None:
        with self._lock:
            self._packets_seen += 1

    def push(self, event: PacketEventSchema) -> bool:
        """
        Pushes a parsed packet event into the queue non-blockingly.
        Updates preview buffer and drop counters.
        Returns True if enqueued, False if dropped due to queue capacity.
        """
        with self._lock:
            # Always update preview ring-buffer for diagnostic inspection
            self._preview_buffer.appendleft(event)

            try:
                self._queue.put_nowait(event)
                self._packets_enqueued += 1
                return True
            except queue.Full:
                self._packets_dropped += 1
                return False

    def pop(self, timeout: Optional[float] = None) -> Optional[PacketEventSchema]:
        """
        Pops a packet event from the queue. Blocks up to timeout seconds.
        Returns None if queue is empty.
        """
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_preview(self) -> List[PacketEventSchema]:
        """
        Returns a snapshot of the current diagnostic preview buffer.
        """
        with self._lock:
            return list(self._preview_buffer)

    def get_stats(self) -> Dict[str, Any]:
        """
        Returns atomic snapshot of packet queue metrics.
        """
        with self._lock:
            return {
                "packets_seen": self._packets_seen,
                "packets_enqueued": self._packets_enqueued,
                "packets_dropped": self._packets_dropped,
                "queue_size": self._queue.qsize(),
                "queue_capacity": self.capacity,
                "preview_count": len(self._preview_buffer),
            }

    def reset(self) -> None:
        """
        Resets all counters and clears the queue and preview buffers.
        """
        with self._lock:
            self._packets_seen = 0
            self._packets_enqueued = 0
            self._packets_dropped = 0
            self._preview_buffer.clear()
            while not self._queue.empty():
                try:
                    self._queue.get_nowait()
                except queue.Empty:
                    break
