from typing import Optional, Union
from pydantic import computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import URL, make_url


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

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=True,
    )


settings = Settings()
