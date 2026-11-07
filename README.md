# AI/ML-Based Network Intrusion Detection System (NIDS)

## Module 1 — Backend Foundation and Live Packet Capture
## Module 2 — Bidirectional Flow Aggregation and PostgreSQL Persistence
## Module 3 — ML Detection, Rule Engine and Alert Management

This repository contains the backend for an AI/ML-Based Network Intrusion Detection System (NIDS).
- **Module 1**: Live network packet capture engine with Scapy AsyncSniffer and Windows Npcap support.
- **Module 2**: Bidirectional flow aggregation over 10-second observation windows with PostgreSQL persistence.
- **Module 3**: Machine learning anomaly detection using Isolation Forest, configurable behavioral rule engine, and deduplicated security alert lifecycle management.

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
│   ├── verify_detection.py          # Module 3: ML detection & alert engine verification
│   ├── models/                      # Versioned serialized ML model artifacts (.joblib)
│   ├── alembic/
│   │   ├── env.py                   # Alembic environment with dynamic app settings
│   │   ├── script.py.mako           # Revision template
│   │   └── versions/
│   │       ├── 001_initial_capture_sessions.py  # Capture sessions schema
│   │       ├── 002_flow_records.py              # Flow records schema
│   │       └── 003_detection_tables.py          # Model registry, predictions, alerts
│   └── app/
│       ├── main.py                  # FastAPI entry point & lifespan manager
│       ├── api/
│       │   └── v1/
│       │       ├── router.py        # API v1 aggregator router
│       │       └── endpoints/
│       │           ├── health.py    # /live and /ready health probes
│       │           ├── capture.py   # Capture control & session endpoints
│       │           ├── flows.py     # Flow listing & detail endpoints
│       │           ├── dashboard.py # Dashboard summary endpoint
│       │           ├── models.py    # Baseline model training & status endpoints
│       │           ├── predictions.py# Flow inference & prediction history
│       │           └── alerts.py    # Security alert listing & resolution
│       ├── core/
│       │   ├── config.py            # Pydantic v2 application settings
│       │   └── logging.py           # Secure, non-leaking application logging
│       ├── db/
│       │   ├── base.py              # DeclarativeBase
│       │   └── session.py           # SQLAlchemy 2.x engine & sessionmaker
│       ├── ml/
│       │   ├── features.py          # Versioned 22-dimensional flow feature schema
│       │   └── model_manager.py     # Isolation Forest pipeline & artifact manager
│       ├── rules/
│       │   └── rule_engine.py       # Behavioral rule engine (8 detection rules)
│       ├── models/
│       │   ├── capture_session.py   # CaptureSession model with check constraints
│       │   ├── flow_record.py       # FlowRecord model with JSONB features
│       │   └── detection.py         # ModelRegistry, Prediction, Alert models
│       ├── schemas/
│       │   ├── capture.py           # Request/response schemas for capture
│       │   ├── packet.py            # Privacy-safe packet metadata schema
│       │   ├── flow.py              # Flow record response & filter schemas
│       │   ├── dashboard.py         # Dashboard summary response schema
│       │   ├── detection.py         # Model training, prediction, alert schemas
│       │   ├── health.py            # Health probe schemas
│       │   └── error.py             # Standard error schemas
│       ├── repositories/
│       │   ├── capture_repository.py# CaptureSession persistence queries
│       │   ├── flow_repository.py   # FlowRecord bulk insert & filtered queries
│       │   └── detection_repository.py# Model, prediction, alert data access
│       ├── services/
│       │   ├── capture_service.py   # Capture business logic coordinator
│       │   ├── flow_service.py      # Flow query & dashboard service
│       │   ├── alert_service.py     # Alert decision policy & deduplication
│       │   └── detection_service.py # ML training & inference coordinator
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
│           ├── test_api_flows.py    # Flows & dashboard API endpoint tests
│           ├── test_ml_model.py     # Baseline training, serialization, inference
│           ├── test_rules.py        # 8 Behavioral rules positive & negative tests
│           ├── test_alert_service.py# Alert policy, deduplication, resolution
│           └── test_api_detection.py# Models, predictions, alerts API tests
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

Run the complete 76-test unit suite:
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

**Module 3 — ML Detection, Rules & Alert Engine (35 tests):**
- Stable 22-dimensional feature extraction and schema ordering
- Baseline session validation (insufficient samples, empty datasets, invalid mode rejection)
- Isolation Forest pipeline training, serialization, and SHA-256 integrity verification
- Tamper-proofing: corrupted artifact checksum rejection
- Safe model unready handling (`MODEL_NOT_READY` with no fabricated normal predictions)
- Empirical baseline score distribution calculation (without fake supervised accuracy claims)
- Real inference execution on normal inliers vs extreme anomalous flows
- Behavioral rules testing for all 8 rules (positive and negative cases):
  - `RULE_SYN_HEAVY`: Excessive SYN flags without ACKs
  - `RULE_HIGH_RATE`: Volumetric packet or byte transmission surges
  - `RULE_EXCESSIVE_RST`: Abnormal frequency of TCP connection resets
  - `RULE_HIGH_DNS`: High-density DNS query concentrations
  - `RULE_UNCOMMON_PORT`: Targeted connections to known backdoor/trojan ports (e.g. 4444, 31337)
  - `RULE_HIGH_BROADCAST_MULTICAST`: Volumetric layer-2 broadcast/multicast storms
  - `RULE_PORT_SCAN`: Multi-flow historical aggregation across distinct destination ports
  - `RULE_BEACONING`: Multi-flow periodic low-volume heartbeat / C2 polling detection
- Alert decision policy:
  - ML anomaly only -> LOW or MEDIUM severity based on isolation depth
  - Rule finding only -> Default rule severity (independent of ML availability)
  - ML + Rule corroboration -> Elevated severity (e.g. HIGH -> CRITICAL)
  - No alert when flow is inlier and no rules trigger
- Alert deduplication and cooldown: updating occurrence counts on identical fingerprints
- Alert resolution lifecycle and resolution timestamping
- REST API endpoints for models, predictions, and alerts

---

## 5. Live Capture & Detection Verification

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

### Module 3: ML Detection & Alert Engine
To train an Isolation Forest model on an authorized BASELINE capture session, verify artifact persistence with SHA-256 checksums, execute inference on normal and anomalous traffic, and validate behavioral rules, corroboration, deduplication, and resolution:
```powershell
$env:PYTHONPATH = "backend"
.\.venv\Scripts\python.exe backend\verify_detection.py
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
| `POST` | `/api/v1/models/train-baseline` | Train Isolation Forest on completed BASELINE session |
| `GET` | `/api/v1/models/status` | Get active model readiness, checksum & feature schema |
| `GET` | `/api/v1/predictions` | List historical predictions with status/score filtering |
| `POST` | `/api/v1/predictions/{flow_id}` | Run inference + rules on flow and persist prediction/alerts |
| `GET` | `/api/v1/alerts` | List security alerts (filtered by status, severity, source) |
| `PATCH` | `/api/v1/alerts/{alert_id}/resolve` | Resolve an open security alert |

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

---

## 9. Module 3 — ML Detection, Rule Engine and Alert Management Design

### Baseline Capture vs Monitoring Traffic

- **Baseline Sessions (`session_mode = 'BASELINE'`)**: Dedicated capture periods designated for recording authorized, ordinary network traffic. Training is strictly restricted to completed baseline sessions (`POST /api/v1/models/train-baseline`) to prevent contaminated monitoring traffic from shifting the baseline.
- **Important Limitation**: Capturing traffic in a baseline session does **not** guarantee that every observed packet is benign without qualification. Users must ensure that baseline collection occurs under clean, authorized conditions. A minimum sample size (default 50 flows) is strictly enforced.

### Preprocessing & Isolation Forest Pipeline

- **Feature Schema v1.0**: 22 ordered numerical features extracted from flow records.
- **Preprocessing**: Encapsulated in a single scikit-learn `Pipeline([('imputer', SimpleImputer(strategy='median')), ('scaler', RobustScaler()), ('model', IsolationForest(...))])`.
- **Note on Scaling**: Isolation Forest creates orthogonal random tree splits along individual features and is invariant to monotonic scaling. However, `RobustScaler` and `SimpleImputer` are retained in the serialized pipeline to ensure robust protection against missing, infinite, or degenerate inputs during real-time inference without skewing distance metrics.
- **Artifact Versioning & Integrity**: Trained pipelines are saved to `backend/models/` as versioned `.joblib` files. SHA-256 checksums are calculated upon serialization and verified before loading to prevent artifact tampering.

### Prediction Semantics

- `predict() == -1`: Statistical **ANOMALY** (isolation depth indicates rarity relative to baseline).
- `predict() == 1`: **NORMAL** inlier.
- `decision_function()`: Continuous isolation depth score. **Note**: This score is a distance-to-separating-hyperplane metric, **not a calibrated attack probability**.
- `MODEL_NOT_READY`: Returned if no model is loaded or ready. The system **never** generates fake normal predictions when the model is unavailable.

### Behavioral Rule Engine (8 Rules)

| Rule ID | Name | Trigger Condition | Default Severity |
|---|---|---|---|
| `RULE_SYN_HEAVY` | SYN-Heavy Probing | `tcp_syn_count >= 10 and tcp_ack_count == 0` | MEDIUM |
| `RULE_HIGH_RATE` | Abnormal Rate | `packets_per_second >= 500.0 or bytes_per_second >= 5,000,000.0` | MEDIUM |
| `RULE_EXCESSIVE_RST` | Excessive TCP Resets | `tcp_rst_count >= 5 and (rst / packets >= 0.25 or rst >= 10)` | LOW |
| `RULE_HIGH_DNS` | High-Volume DNS Queries | `dns_query_count >= 25 or dns_unique_query_count >= 15` | MEDIUM |
| `RULE_UNCOMMON_PORT` | High-Risk Destination Port | `dst_port in {1337, 4444, 5555, 6667, 9999, 12345, 31337, ...}` | MEDIUM |
| `RULE_HIGH_BROADCAST_MULTICAST` | Broadcast/Multicast Storm | `(is_broadcast or is_multicast) and (packets >= 50 or pps >= 50.0)` | LOW |
| `RULE_PORT_SCAN` | Multi-Port Scan | Host targeted ≥ 10 distinct destination ports within recent 60s window | HIGH |
| `RULE_BEACONING` | Periodic C2 Beaconing | ≥ 4 periodic low-volume flows between same pair with low timing variance | HIGH |

*Findings are classified as suspicious patterns, not confirmed attacks.*

### Alert Decision Policy & Corroboration

| Scenario | Detection Source | Severity Assigned |
|---|---|---|
| **ML Anomaly Only** | `ML` | `LOW` (score ≥ -0.15) or `MEDIUM` (score < -0.15) |
| **Rule Finding Only** | `RULE` | Rule default severity (`LOW`, `MEDIUM`, or `HIGH`) |
| **ML + Rule Corroboration** | `COMBINED` | **Elevated Severity** (e.g. `HIGH` → `CRITICAL`, `MEDIUM` → `HIGH`) |
| **No Anomaly / No Rules** | None | No alert generated |

Rules operate completely independently when the ML model is offline or unready.

### Deduplication & Alert Lifecycle

- **Fingerprint**: Deterministic string `RULE_ID:SRC_IP->DST_IP:DST_PORT:PROTOCOL`.
- **Cooldown Window**: 300 seconds (`ALERT_COOLDOWN_SECONDS`).
- **Deduplication**: When an open alert matches an incoming fingerprint within the cooldown period, its `occurrence_count` is incremented and `last_seen` is updated. Unlimited duplicate alert rows are prevented.
- **Resolution**: Open alerts can be marked as `RESOLVED` via `PATCH /api/v1/alerts/{alert_id}/resolve` which timestamps `resolved_at`.
