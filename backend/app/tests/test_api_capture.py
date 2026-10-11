from unittest.mock import MagicMock, patch
from fastapi import status

from app.schemas.capture import InterfaceInfo


def test_api_list_interfaces(client):
    response = client.get("/api/v1/capture/interfaces")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert isinstance(data, list)


def test_api_get_capture_status_initial(client):
    response = client.get("/api/v1/capture/status")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["is_running"] is False
    assert data["active_session_id"] is None
    assert data["packets_seen"] == 0


def test_api_start_capture_invalid_interface(client):
    payload = {
        "interface_id": "non_existent_adapter_foo_bar",
        "session_mode": "MONITORING",
    }
    response = client.post("/api/v1/capture/start", json=payload)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert "was not found" in response.text


def test_api_stop_capture_when_not_running(client):
    response = client.post("/api/v1/capture/stop")
    assert response.status_code == status.HTTP_409_CONFLICT


def test_api_start_and_stop_lifecycle_with_mock(client):
    mock_iface = InterfaceInfo(
        id="mock_iface_1",
        name="Mock Adapter 1",
        description="Testing Adapter",
        mac_address="AA:BB:CC:DD:EE:FF",
        ip_addresses=["192.168.1.150"],
        status="Up",
        is_loopback=False,
    )

    with patch("app.capture.interface_discovery.InterfaceDiscoveryService.get_interface_by_id", return_value=mock_iface):
        with patch("app.capture.capture_manager.AsyncSniffer") as MockSniffer:
            mock_sniffer_instance = MagicMock()
            MockSniffer.return_value = mock_sniffer_instance

            # Start capture
            start_payload = {
                "interface_id": "mock_iface_1",
                "session_mode": "BASELINE",
            }
            start_res = client.post("/api/v1/capture/start", json=start_payload)
            assert start_res.status_code == status.HTTP_200_OK
            start_data = start_res.json()
            assert start_data["is_running"] is True
            assert start_data["session_mode"] == "BASELINE"
            active_id = start_data["active_session_id"]

            # Double-start should fail with 409 Conflict
            double_res = client.post("/api/v1/capture/start", json=start_payload)
            assert double_res.status_code == status.HTTP_409_CONFLICT

            # Check status endpoint reflects running
            status_res = client.get("/api/v1/capture/status")
            assert status_res.status_code == status.HTTP_200_OK
            assert status_res.json()["is_running"] is True

            # Stop capture
            stop_res = client.post("/api/v1/capture/stop")
            assert stop_res.status_code == status.HTTP_200_OK
            stop_data = stop_res.json()
            assert stop_data["message"] == "Capture session stopped successfully."
            assert stop_data["session"]["id"] == active_id
            assert stop_data["session"]["status"] == "STOPPED"

            # Check session is in session history
            sessions_res = client.get("/api/v1/capture/sessions")
            assert sessions_res.status_code == status.HTTP_200_OK
            sessions_data = sessions_res.json()
            assert len(sessions_data) >= 1
            assert any(s["id"] == active_id for s in sessions_data)


def test_api_get_preview(client):
    response = client.get("/api/v1/capture/preview")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "count" in data
    assert "packets" in data
    assert isinstance(data["packets"], list)
