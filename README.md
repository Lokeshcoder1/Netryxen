# AI/ML-Based Network Intrusion Detection System (NIDS)

## Module 1 — Backend Foundation and Live Packet Capture

This repository contains the backend foundation and live network packet capture engine for the AI/ML-Based Network Intrusion Detection System (NIDS).

---

## 1. Architecture & Modular Layout

```
Netryxen/
├── .env.example                     # Environment template
├── .gitignore                       # Git ignore patterns
├── requirements.txt                 # Project dependencies
├── README.md                        # Setup and operational documentation
├── backend/
│   ├── alembic.ini                  # Database migration configuration
│   ├── init_db.py                   # Automated database creation & migration runner
│   ├── verify_live_capture.py       # Live packet capture verification script
│   ├── alembic/
│   │   ├── env.py                   # Alembic environment with dynamic app settings
│   │   ├── script.py.mako           # Revision template
│   │   └── versions/
│   │       └── 001_initial_capture_sessions.py  # Capture sessions schema
│   └── app/
│       ├── main.py                  # FastAPI entry point & lifespan manager
│       ├── api/
│       │   └── v1/
│       │       ├── router.py        # API v1 aggregator router
│       │       └── endpoints/
│       │           ├── health.py    # /live and /ready health probes
│       │           └── capture.py   # Capture control & session endpoints
│       ├── core/
│       │   ├── config.py            # Pydantic v2 application settings
│       │   └── logging.py           # Secure, non-leaking application logging
│       ├── db/
│       │   ├── base.py              # DeclarativeBase
│       │   └── session.py           # SQLAlchemy 2.x engine & sessionmaker
│       ├── models/
│       │   └── capture_session.py   # CaptureSession model with check constraints
│       ├── schemas/
│       │   ├── capture.py           # Request/response schemas for capture
│       │   ├── packet.py            # Privacy-safe packet metadata schema
│       │   ├── health.py            # Health probe schemas
│       │   └── error.py             # Standard error schemas
│       ├── repositories/
│       │   └── capture_repository.py# CaptureSession persistence queries
│       ├── services/
│       │   └── capture_service.py   # Business logic coordinator
│       ├── capture/
│       │   ├── interface_discovery.py# Npcap/Windows network adapter discovery
│       │   ├── packet_parser.py     # Privacy-preserving packet header parser
│       │   ├── packet_queue.py      # Bounded, thread-safe queue & preview buffer
│       │   └── capture_manager.py   # Scapy AsyncSniffer lifecycle manager
│       └── tests/
│           ├── conftest.py          # Pytest fixtures & synthetic packet helpers
│           ├── test_packet_parser.py# TCP, UDP, ICMP, IPv6, ARP & privacy tests
│           ├── test_capture_queue.py# Bounded queue backpressure & drop counts
│           ├── test_capture_lifecycle.py # State transitions & start/stop lifecycle
│           ├── test_api_health.py   # /health/live and /health/ready tests
│           ├── test_api_capture.py  # REST endpoints for interface & capture
│           └── test_db_session.py   # Database model & check constraint tests
```

---

## 2. Windows Environment & Prerequisites

1. **Python 3.12 (64-bit)**:
   Ensure Python 3.12 is installed and available in PATH or accessible via `py -3.12`.

2. **Npcap**:
   - Required for live packet capture on Windows.
   - Verified installed at `C:\Program Files\Npcap` and `C:\Windows\System32\Npcap`.
   - Install with "WinPcap API-compatible Mode" enabled if prompting during setup.
   - Live packet sniffing requires administrator privileges in Windows PowerShell.
   - **Do not disable Windows Firewall.**

3. **PostgreSQL 18**:
   - Running locally on port 5432 as a Windows service (`postgresql-x64-18`).
   - A dedicated database `nids_db` is used.

---

## 3. Installation & Setup Instructions

### Step 1: Create and Activate Virtual Environment
```powershell
# Open PowerShell in the Netryxen directory
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### Step 2: Install Dependencies
```powershell
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy `.env.example` to `.env` and configure your local PostgreSQL password:
```powershell
Copy-Item .env.example .env
```
Edit `.env` to set your PostgreSQL superuser password:
```ini
POSTGRES_USER=postgres
POSTGRES_PASSWORD=your_postgres_password
POSTGRES_DB=nids_db
```

### Step 4: Initialize Database & Run Migrations
```powershell
.\.venv\Scripts\python.exe backend\init_db.py
```
Or directly using Alembic:
```powershell
.\.venv\Scripts\alembic -c backend\alembic.ini upgrade head
```

---

## 4. Running Automated Tests

Run the complete 25-test unit suite:
```powershell
.\.venv\Scripts\pytest backend\app\tests -v
```

The test suite tests:
- TCP SYN / ACK parsing and flag extraction
- UDP transport parsing
- ICMP packets without transport ports
- IPv6 packets
- Privacy safeguards (payloads, cookies, auth tokens, raw DNS text strictly scrubbed)
- Bounded packet queue limits and packet drop metrics
- Capture manager lifecycle and concurrency safeguards
- REST API health and capture endpoints
- Database models and check constraints

---

## 5. Live Capture Verification

To run a manual live packet capture on an active interface (e.g. Wi-Fi) for 5 seconds and view real captured packet metadata:
```powershell
.\.venv\Scripts\python.exe backend\verify_live_capture.py
```

Expected output:
- Verifies Npcap driver availability
- Discovers active network interfaces
- Starts capture via Scapy `AsyncSniffer` (non-blocking)
- Pushes parsed packets into the bounded queue and diagnostic preview buffer
- Stops capture cleanly and displays captured metadata

---

## 6. Running the FastAPI Application

Start the backend server on localhost:
```powershell
$env:PYTHONPATH = "backend"
.\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

Interactive Swagger documentation is available at:
- **Swagger UI**: `http://127.0.0.1:8000/docs`
- **ReDoc**: `http://127.0.0.1:8000/redoc`

---

## 7. REST API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health/live` | Process liveness probe |
| `GET` | `/api/v1/health/ready` | Database & Npcap readiness probe |
| `GET` | `/api/v1/capture/interfaces` | List available network interfaces |
| `POST` | `/api/v1/capture/start` | Start live capture on validated interface |
| `POST` | `/api/v1/capture/stop` | Stop active capture session |
| `GET` | `/api/v1/capture/status` | Current capture status, queue size & drop count |
| `GET` | `/api/v1/capture/sessions` | Historical capture session records |
| `GET` | `/api/v1/capture/preview` | Recent privacy-safe packet metadata preview |
