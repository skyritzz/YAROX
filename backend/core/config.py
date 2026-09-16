from typing import List, Union, Optional
from pydantic_settings import BaseSettings
from pydantic import field_validator
import os

DEV_JWT_PLACEHOLDER = "yarox-dev-insecure-secret-key-change-in-production-2026-phase4a"
DEV_INGEST_KEY_PLACEHOLDER = "yarox-dev-ingest-key-change-in-production-2026"

class Settings(BaseSettings):
    PROJECT_NAME: str = "YAROX"
    VERSION: str = "0.2.0"
    ENVIRONMENT: str = "development"  # development, staging, production, test
    
    # Database and Broker URLs
    DATABASE_URL: str = "postgresql+asyncpg://yarox:yaroxpassword@postgres:5432/yarox"
    REDIS_URL: str = "redis://redis:6379/0"
    QDRANT_URL: str = "http://qdrant:6333"
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434"
    OLLAMA_MODEL: str = "llama3.1"
    
    # JWT Authentication & RBAC (Human User Access)
    JWT_SECRET_KEY: str = DEV_JWT_PLACEHOLDER
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours
    
    # Live Telemetry Ingestion (Machine-to-Machine API Key)
    INGESTION_API_KEY: str = DEV_INGEST_KEY_PLACEHOLDER
    RATE_LIMIT_INGEST_PER_MINUTE: int = 120  # Max 120 ingest requests per minute
    
    # CORS Configuration
    ALLOWED_ORIGINS: Union[List[str], str] = [
        "http://localhost:3000",
        "http://localhost:3002",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3002",
    ]
    
    # Initial Pre-Seeded Accounts (for local pilot / test environment)
    INITIAL_ADMIN_EMAIL: str = "admin@yarox.local"
    INITIAL_ADMIN_PASSWORD: str = "YaroxAdmin2026!"
    INITIAL_ANALYST_EMAIL: str = "analyst@yarox.local"
    INITIAL_ANALYST_PASSWORD: str = "YaroxAnalyst2026!"
    INITIAL_VIEWER_EMAIL: str = "viewer@yarox.local"
    INITIAL_VIEWER_PASSWORD: str = "YaroxViewer2026!"

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, (list, str)):
            return v
        return ["http://localhost:3000", "http://localhost:3002"]

    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

def validate_production_settings():
    """
    Ensures that default development placeholder secrets cannot be used in a production environment.
    """
    if settings.ENVIRONMENT.lower() == "production":
        if settings.JWT_SECRET_KEY == DEV_JWT_PLACEHOLDER:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Default development JWT_SECRET_KEY detected in PRODUCTION environment. "
                "You must supply a secure, randomly generated JWT_SECRET_KEY via environment variable."
            )
        if settings.INGESTION_API_KEY == DEV_INGEST_KEY_PLACEHOLDER:
            raise ValueError(
                "CRITICAL SECURITY CONFIGURATION ERROR: Default development INGESTION_API_KEY detected in PRODUCTION environment. "
                "You must supply a unique, secure INGESTION_API_KEY via environment variable."
            )
