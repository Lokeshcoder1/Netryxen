from typing import Optional, Union
from pathlib import Path
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL, make_url

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    PROJECT_NAME: str = "AI/ML-Based Network Intrusion Detection System (NIDS)"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    DEBUG: bool = False

    # PostgreSQL Database Settings
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "nids_db"
    
    # Optional direct DATABASE_URL override
    SQLALCHEMY_DATABASE_URI: Optional[str] = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def DATABASE_URL(self) -> URL:
        if self.SQLALCHEMY_DATABASE_URI:
            return make_url(self.SQLALCHEMY_DATABASE_URI)
        return URL.create(
            drivername="postgresql+psycopg",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_HOST,
            port=self.POSTGRES_PORT,
            database=self.POSTGRES_DB,
        )

    def get_database_url_str(self, hide_password: bool = False) -> str:
        """
        Returns the database URL as a properly encoded connection string.
        """
        if isinstance(self.DATABASE_URL, URL):
            return self.DATABASE_URL.render_as_string(hide_password=hide_password)
        return str(self.DATABASE_URL)

    # Capture Engine Configurations
    CAPTURE_QUEUE_CAPACITY: int = 10000
    CAPTURE_PREVIEW_CAPACITY: int = 50
    CAPTURE_PROMISCUOUS: bool = True
    CAPTURE_STORE_PACKETS: bool = False

    # Flow Aggregation Configurations
    FLOW_WINDOW_SECONDS: int = 10
    FLOW_AGGREGATOR_INTERVAL_SECONDS: float = 1.0
    FLOW_MEMORY_CAPACITY: int = 50000

    # ML / Detection Configuration
    MODEL_ARTIFACTS_DIR: str = "models"
    ML_MIN_BASELINE_SAMPLES: int = 50
    ML_CONTAMINATION: float = 0.05
    ML_N_ESTIMATORS: int = 100
    ML_RANDOM_STATE: int = 42

    def get_model_artifacts_path(self) -> Path:
        p = Path(self.MODEL_ARTIFACTS_DIR)
        if not p.is_absolute():
            return PROJECT_ROOT / "backend" / p
        return p

    # Alert Configuration
    ALERT_COOLDOWN_SECONDS: int = 300
    ALERT_SEVERITY_THRESHOLDS: str = "LOW=-0.3,MEDIUM=-0.5,HIGH=-0.7,CRITICAL=-0.9"

    # Behavioral Rule Thresholds
    RULE_SYN_RATIO_THRESHOLD: float = 5.0
    RULE_SYN_MIN_PACKETS: int = 10
    RULE_HIGH_PPS_THRESHOLD: float = 500.0
    RULE_HIGH_BPS_THRESHOLD: float = 5_000_000.0
    RULE_HIGH_RST_THRESHOLD: int = 5
    RULE_HIGH_DNS_THRESHOLD: int = 25
    RULE_PORT_SCAN_DISTINCT_PORTS: int = 10
    RULE_PORT_SCAN_WINDOW_SECONDS: int = 60
    RULE_BEACON_MIN_INTERVALS: int = 4
    RULE_BEACON_MAX_PACKETS_PER_FLOW: int = 10
    RULE_BEACON_MAX_JITTER_SECONDS: float = 3.0
    RULE_BEACON_MAX_CV: float = 0.25

    # Background Detection Worker Configuration
    DETECTION_WORKER_ENABLED: bool = True
    DETECTION_WORKER_INTERVAL_SECONDS: float = 1.0
    DETECTION_WORKER_BATCH_SIZE: int = 50
    DETECTION_WORKER_MAX_RETRIES: int = 3
    DETECTION_JOB_STUCK_TIMEOUT_SECONDS: int = 300

    # CORS Configuration
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ]

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
