from unittest.mock import MagicMock, patch
import uuid
import pytest

from app.capture.capture_manager import CaptureManager
from app.models.capture_session import SessionMode
from app.schemas.capture import InterfaceInfo


def test_invalid_interface_handling():
    manager = CaptureManager()
    dummy_session_id = uuid.uuid4()

    with patch("app.capture.interface_discovery.InterfaceDiscoveryService.get_interface_by_id", return_value=None):
        with pytest.raises(ValueError) as excinfo:
            manager.start_capture(
                interface_id="non_existent_adapter_xyz",
                session_id=dummy_session_id,
            )
        assert "non_existent_adapter_xyz" in str(excinfo.value)
    assert not manager.is_running


def test_capture_start_stop_lifecycle():
    manager = CaptureManager()
    mock_iface = InterfaceInfo(
        id="test_eth0",
        name="test_eth0",
        description="Test Virtual Ethernet",
        mac_address="00:11:22:33:44:55",
        ip_addresses=["192.168.1.100"],
        status="Up",
        is_loopback=False,
    )

    with patch("app.capture.interface_discovery.InterfaceDiscoveryService.get_interface_by_id", return_value=mock_iface):
        with patch("app.capture.capture_manager.AsyncSniffer") as MockSniffer:
            mock_sniffer_instance = MagicMock()
            MockSniffer.return_value = mock_sniffer_instance

            session_id = uuid.uuid4()
            status = manager.start_capture(
                interface_id="test_eth0",
                session_id=session_id,
                session_mode=SessionMode.MONITORING,
            )

            assert manager.is_running is True
            assert status["is_running"] is True
            assert status["active_session_id"] == session_id
            MockSniffer.assert_called_once()
            mock_sniffer_instance.start.assert_called_once()

            # Attempting to start again while running should fail
            with pytest.raises(RuntimeError):
                manager.start_capture(
                    interface_id="test_eth0",
                    session_id=uuid.uuid4(),
                )

            # Stop capture
            stats = manager.stop_capture()
            assert manager.is_running is False
            mock_sniffer_instance.stop.assert_called_once()

            # Attempting to stop again should fail
            with pytest.raises(RuntimeError):
                manager.stop_capture()


def test_capture_callback_ingestion(synthetic_tcp_syn):
    manager = CaptureManager()
    manager.packet_queue.reset()

    # Call the callback directly with synthetic packet
    manager._packet_callback(synthetic_tcp_syn)

    stats = manager.packet_queue.get_stats()
    assert stats["packets_seen"] == 1
    assert stats["packets_enqueued"] == 1
    assert stats["packets_dropped"] == 0

    preview = manager.get_preview()
    assert len(preview) == 1
    assert preview[0].src_ip == "192.168.1.50"
    assert preview[0].dst_ip == "192.168.1.1"
    assert preview[0].protocol_name == "TCP"
