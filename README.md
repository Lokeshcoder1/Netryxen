# AI/ML-Based Network Intrusion Detection System (NIDS)

## Module 1 — Backend Foundation and Live Packet Capture
## Module 2 — Bidirectional Flow Aggregation and PostgreSQL Persistence

This repository contains the backend for an AI/ML-Based Network Intrusion Detection System (NIDS).
Module 1 provides the live packet capture engine; Module 2 aggregates captured packets into bidirectional flow records over configurable 10-second observation windows and persists them to PostgreSQL.

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
│   ├── verify_live_capture.py       # Module 1: Live packet capture verification
│   ├── verify_live_flows.py         # Module 2: Live flow aggregation verification
│   ├── alembic/
│   │   ├── env.py                   # Alembic environment with dynamic app settings
│   │   ├── script.py.mako           # Revision template
│   │   └── versions/
│   │       ├── 001_initial_capture_sessions.py  # Capture sessions schema
│   │       └── 002_flow_records.py              # Flow records schema
│   └── app/
│       ├── main.py                  # FastAPI entry point & lifespan manager
│       ├── api/
│       │   └── v1/
│       │       ├── router.py        # API v1 aggregator router
│       │       └── endpoints/
│       │           ├── health.py    # /live and /ready health probes
│       │           ├── capture.py   # Capture control & session endpoints
│       │           ├── flows.py     # Flow listing & detail endpoints
│       │           └── dashboard.py # Dashboard summary endpoint
│       ├── core/
│       │   ├── config.py            # Pydantic v2 application settings
│       │   └── logging.py           # Secure, non-leaking application logging
│       ├── db/
│       │   ├── base.py              # DeclarativeBase
│       │   └── session.py           # SQLAlchemy 2.x engine & sessionmaker
│       ├── models/
│       │   ├── capture_session.py   # CaptureSession model with check constraints
│       │   └── flow_record.py       # FlowRecord model with JSONB features
│       ├── schemas/
│       │   ├── capture.py           # Request/response schemas for capture
│       │   ├── packet.py            # Privacy-safe packet metadata schema
│       │   ├── flow.py              # Flow record response & filter schemas
│       │   ├── dashboard.py         # Dashboard summary response schema
│       │   ├── health.py            # Health probe schemas
│       │   └── error.py             # Standard error schemas
│       ├── repositories/
│       │   ├── capture_repository.py# CaptureSession persistence queries
│       │   └── flow_repository.py   # FlowRecord bulk insert & filtered queries
│       ├── services/
│       │   ├── capture_service.py   # Capture business logic coordinator
│       │   └── flow_service.py      # Flow query & dashboard service
│       ├── capture/
│       │   ├── interface_discovery.py# Npcap/Windows network adapter discovery
│       │   ├── packet_parser.py     # Privacy-preserving packet header parser
│       │   ├── packet_queue.py      # Bounded, thread-safe queue & preview buffer
│       │   ├── capture_manager.py   # Scapy AsyncSniffer lifecycle manager
│       │   └── flow_aggregator.py   # Bidirectional flow aggregation engine
│       └── tests/
│           ├── conftest.py          # Pytest fixtures & synthetic packet helpers
│           ├── test_packet_parser.py# TCP, UDP, ICMP, IPv6, ARP & privacy tests
│           ├── test_capture_queue.py# Bounded queue backpressure & drop counts
│           ├── test_capture_lifecycle.py # State transitions & start/stop lifecycle
│           ├── test_api_health.py   # /health/live and /health/ready tests
│           ├── test_api_capture.py  # REST endpoints for interface & capture
│           ├── test_db_session.py   # Database model & check constraint tests
│           ├── test_flow_aggregator.py  # Flow key symmetry, aggregation, flushing
│           └── test_api_flows.py    # Flows & dashboard API endpoint tests
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

Run the complete 41-test unit suite:
```powershell
.\.venv\Scripts\pytest backend\app\tests -v
```

The test suite covers:

**Module 1 — Packet Capture (25 tests):**
- TCP SYN / ACK parsing and flag extraction
- UDP transport parsing
- ICMP packets without transport ports
- IPv6 packets
- Privacy safeguards (payloads, cookies, auth tokens, raw DNS text strictly scrubbed)
- Bounded packet queue limits and packet drop metrics
- Capture manager lifecycle and concurrency safeguards
- REST API health and capture endpoints
- Database models and check constraints

**Module 2 — Flow Aggregation (16 tests):**
- Canonical bidirectional flow key symmetry (A→B == B→A)
- Protocol separation (TCP vs UDP on same endpoints produces distinct flows)
- Non-transport protocol handling (ICMP with no ports)
- Forward/reverse directional packet and byte counting
- TCP flag counter accumulation (SYN, ACK, FIN, RST, PSH)
- DNS query and unique query counting
- Division-by-zero / zero-duration rate safeguards
- Flow aggregator database flush lifecycle
- Multiple time-window separation (packets in different 10s windows)
- Unrelated connection separation (distinct endpoints in same window)
- Flow listing, filtering (by protocol, IP, session), and pagination API
- Flow detail retrieval and 404 handling
- Dashboard summary with protocol distribution and top talkers

---

## 5. Live Capture Verification

### Module 1: Packet Capture
To run a manual live packet capture on an active interface (e.g. Wi-Fi) for 5 seconds and view real captured packet metadata:
```powershell
.\.venv\Scripts\python.exe backend\verify_live_capture.py
```

### Module 2: Flow Aggregation
To capture 12 seconds of live traffic, aggregate packets into bidirectional 10-second flow windows, persist them to PostgreSQL, and display flow feature details:
```powershell
$env:PYTHONPATH = "backend"
.\.venv\Scripts\python.exe backend\verify_live_flows.py
```

Expected output:
- Discovers active network interface and local IP addresses
- Starts Scapy capture and flow aggregator simultaneously
- Aggregates real traffic into canonical bidirectional flows
- Finalizes and persists flow records across window boundaries
- Displays flow features per record (endpoints, byte/packet counts, TCP flags, DNS queries, upload/download ratios)
- Prints dashboard summary (total sessions, flows, protocol breakdown, top talkers)

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
| `GET` | `/api/v1/flows` | List aggregated flow records (filtered, paginated) |
| `GET` | `/api/v1/flows/{flow_id}` | Get detailed flow record by UUID |
| `GET` | `/api/v1/dashboard/summary` | Dashboard metrics, protocol distribution, top talkers |

### Flow Query Parameters

| Parameter | Type | Description |
|---|---|---|
| `session_id` | UUID | Filter by capture session |
| `protocol` | string | Filter by protocol (TCP, UDP, ICMP, etc.) |
| `src_ip` | string | Filter by initiator source IP |
| `dst_ip` | string | Filter by responder destination IP |
| `ip` | string | Filter flows matching either source or destination |
| `start_time` | ISO datetime | Filter flows with window_start ≥ value |
| `end_time` | ISO datetime | Filter flows with window_end ≤ value |
| `min_packet_count` | int | Filter flows with packet_count ≥ value |
| `skip` | int | Pagination offset (default 0) |
| `limit` | int | Page size, 1–500 (default 50) |

---

## 8. Module 2 — Flow Aggregation Design

### Observation Windows vs Connection Lifetime

A **10-second observation window** is a fixed time-slice of network activity, not the full lifecycle of a TCP connection. A long-lived HTTPS session may span many windows, each producing an independent flow record. Window boundaries are aligned to UTC epoch seconds (e.g. `12:00:00–12:00:10`, `12:00:10–12:00:20`).

### Canonical Bidirectional Flow Key

Flows are keyed by a deterministic canonical key: `PROTO:IP1:PORT1<->IP2:PORT2` where endpoints are sorted so that A→B and B→A produce the identical key. Different protocols on the same IP/port pair (e.g. TCP vs UDP) produce **distinct** flows.

### Directional Tracking

- **Forward** = initiator → responder (defined by the first packet seen in each window)
- **Reverse** = responder → initiator
- **Upload** = traffic from a monitored local interface IP to external destinations
- **Download** = traffic from external sources to a local interface IP

### Flow Features (per window)

| Feature | Unit | Notes |
|---|---|---|
| `packet_count` | count | Total packets in window |
| `byte_count` | bytes | Total wire-length bytes |
| `fwd_packets` / `rev_packets` | count | Directional packet split |
| `fwd_bytes` / `rev_bytes` | bytes | Directional byte split |
| `duration_seconds` | seconds | `last_seen − first_seen` within window |
| `packets_per_second` | pps | Clamped min duration = 1.0s |
| `bytes_per_second` | Bps | Clamped min duration = 1.0s |
| `min/max/avg_packet_size` | bytes | Per-packet wire length |
| `tcp_syn/ack/fin/rst/psh_count` | count | TCP flag counters (0 for non-TCP) |
| `dns_query_count` | count | DNS question records observed |
| `dns_unique_query_count` | count | Unique DNS questions |
| `upload_bytes` / `download_bytes` | bytes | Host-relative traffic |
| `upload_ratio` | ratio | `upload / (upload + download)`, null if 0 |
| `is_local` | bool | Any packet in flow touched RFC1918/loopback |
| `is_broadcast` / `is_multicast` | bool | Broadcast/multicast indicator |

### Rate Calculation Safeguards

Rates (`packets_per_second`, `bytes_per_second`) use an effective duration clamped to a minimum of 1.0 second. This prevents division-by-zero and unrealistic rate explosions when a single packet or micro-burst produces a zero or sub-millisecond duration.

### Configuration

| Setting | Default | Description |
|---|---|---|
| `FLOW_WINDOW_SECONDS` | 10 | Observation window length |
| `FLOW_AGGREGATOR_INTERVAL_SECONDS` | 1.0 | Worker loop finalization check interval |
| `FLOW_MEMORY_CAPACITY` | 50000 | Max in-memory flow accumulators |
