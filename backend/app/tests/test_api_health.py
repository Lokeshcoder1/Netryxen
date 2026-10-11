from fastapi import status


def test_health_live_endpoint(client):
    response = client.get("/api/v1/health/live")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert data["status"] == "ok"
    assert "timestamp" in data


def test_health_ready_endpoint(client):
    response = client.get("/api/v1/health/ready")
    assert response.status_code == status.HTTP_200_OK
    data = response.json()
    assert "status" in data
    assert "database" in data
    assert "npcap_available" in data
    assert "capture_worker" in data
    assert "timestamp" in data
