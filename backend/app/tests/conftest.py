from datetime import datetime, timezone
from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.packet import Packet

import os

from app.capture.capture_manager import capture_manager
from app.db.base import Base
from app.db.session import get_db
from app.main import app
from app.models.capture_session import CaptureSession

# Support dedicated PostgreSQL integration tests when TEST_DATABASE_URL is set,
# while preserving SQLite in-memory as default for fast, isolated unit tests.
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL", "sqlite:///:memory:")

if "sqlite" in TEST_DATABASE_URL:
    test_engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
else:
    test_engine = create_engine(TEST_DATABASE_URL)

TestingSessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=test_engine,
)


@pytest.fixture(scope="session", autouse=True)
def setup_test_db():
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture(autouse=True)
def clear_in_memory_sqlite_database():
    if TEST_DATABASE_URL != "sqlite:///:memory:":
        return
    with test_engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def reset_capture_manager():
    """Ensure capture manager, detection worker, and model manager are cleanly reset around every test."""
    from app.services.detection_worker import detection_worker
    if detection_worker.is_running:
        try:
            detection_worker.stop()
        except Exception:
            pass
    if capture_manager.is_running:
        try:
            capture_manager.stop_capture()
        except Exception:
            pass
    capture_manager.packet_queue.reset()
    yield
    if detection_worker.is_running:
        try:
            detection_worker.stop()
        except Exception:
            pass
    if capture_manager.is_running:
        try:
            capture_manager.stop_capture()
        except Exception:
            pass
    capture_manager.packet_queue.reset()


@pytest.fixture
def synthetic_tcp_syn() -> Packet:
    return Ether() / IP(src="192.168.1.50", dst="192.168.1.1", ttl=64) / TCP(sport=54321, dport=80, flags="S")


@pytest.fixture
def synthetic_tcp_ack() -> Packet:
    return Ether() / IP(src="192.168.1.1", dst="192.168.1.50", ttl=128) / TCP(sport=80, dport=54321, flags="A")


@pytest.fixture
def synthetic_udp() -> Packet:
    return Ether() / IP(src="10.0.0.5", dst="8.8.8.8", ttl=64) / UDP(sport=53535, dport=53)


@pytest.fixture
def synthetic_icmp() -> Packet:
    return Ether() / IP(src="172.16.0.2", dst="172.16.0.1", ttl=64) / ICMP(type=8, code=0)


@pytest.fixture
def synthetic_ipv6_tcp() -> Packet:
    return Ether() / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64) / TCP(sport=443, dport=60000, flags="SA")
