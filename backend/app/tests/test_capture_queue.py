from datetime import datetime, timezone
from app.capture.packet_queue import BoundedPacketQueue
from app.schemas.packet import PacketEventSchema


def create_dummy_event(port: int) -> PacketEventSchema:
    return PacketEventSchema(
        timestamp=datetime.now(timezone.utc),
        ip_version=4,
        src_ip="192.168.1.100",
        dst_ip="192.168.1.1",
        src_port=port,
        dst_port=80,
        protocol_num=6,
        protocol_name="TCP",
        tcp_flags=["SYN"],
        ttl=64,
        length=60,
        is_local=True,
        is_broadcast=False,
        is_multicast=False,
    )


def test_bounded_queue_limits_and_drops():
    # Create queue with capacity of 3 and preview buffer size of 2
    queue = BoundedPacketQueue(capacity=3, preview_capacity=2)

    # Push 5 events
    results = []
    for p in range(1, 6):
        queue.increment_seen()
        res = queue.push(create_dummy_event(p))
        results.append(res)

    # First 3 should succeed, last 2 should drop
    assert results == [True, True, True, False, False]

    stats = queue.get_stats()
    assert stats["packets_seen"] == 5
    assert stats["packets_enqueued"] == 3
    assert stats["packets_dropped"] == 2
    assert stats["queue_size"] == 3
    assert stats["preview_count"] == 2

    # Check preview buffer contains the 2 most recent packets (ports 5 and 4)
    preview = queue.get_preview()
    assert len(preview) == 2
    assert preview[0].src_port == 5
    assert preview[1].src_port == 4


def test_bounded_queue_pop_and_reset():
    queue = BoundedPacketQueue(capacity=5, preview_capacity=5)

    queue.increment_seen()
    queue.push(create_dummy_event(1001))
    queue.increment_seen()
    queue.push(create_dummy_event(1002))

    popped1 = queue.pop(timeout=0.1)
    assert popped1 is not None
    assert popped1.src_port == 1001

    queue.reset()
    stats = queue.get_stats()
    assert stats["packets_seen"] == 0
    assert stats["packets_enqueued"] == 0
    assert stats["packets_dropped"] == 0
    assert stats["queue_size"] == 0
    assert len(queue.get_preview()) == 0
