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
    # "redis": durable Redis Streams shared by all replicas; "memory": single-process only
    EVENT_BUS: str = "redis"
    QDRANT_URL: str = "http://qdrant:6333"
    QDRANT_COLLECTION: str = "investigation_memory"
    # Similar cases scoring below this weighted similarity are not returned (see memory/service.py).
    # Measured on this stack (BAAI/bge-small-en-v1.5): a true repeat incident scores ~0.98, while
    # unrelated security text still reaches ~0.24-0.39 because the embedding model gives any two
    # security summaries a high baseline. Semantic similarity alone is therefore not a match;
    # 0.45 keeps matches carried by technique/IOC/asset overlap and drops semantic-only noise.
    MEMORY_MIN_SIMILARITY: float = 0.45
    OLLAMA_BASE_URL: str = "http://host.docker.internal:11434"
    OLLAMA_MODEL: str = "llama3.1"

    # ---- LLM provider -------------------------------------------------------------
    # Local inference is the default: security telemetry must not leave the deployment.
    # External providers (anthropic) require LLM_ALLOW_EXTERNAL_PROVIDERS=true.
    LLM_PROVIDER: str = "ollama"          # ollama | vllm | anthropic
    LLM_MODEL: str = "llama3.1"
    LLM_BASE_URL: str = ""                 # falls back to the provider-specific URL below
    VLLM_BASE_URL: str = "http://vllm:8000"
    ANTHROPIC_BASE_URL: str = "https://api.anthropic.com"
    ANTHROPIC_API_KEY: str = ""
    LLM_ALLOW_EXTERNAL_PROVIDERS: bool = False
    LLM_TIMEOUT_SECONDS: float = 180.0
    LLM_MAX_ATTEMPTS: int = 3
    LLM_RETRY_BASE_DELAY_SECONDS: float = 1.0
    LLM_RETRY_MAX_DELAY_SECONDS: float = 20.0
    # A local model server handles few requests at a time; unbounded fan-out from the
    # concurrent agent stage produced timeouts on the live stack.
    LLM_MAX_CONCURRENCY: int = 2
    # Prompts longer than the context window are silently truncated by the server
    LLM_CONTEXT_TOKENS: int = 8192
    MINIO_URL: str = "http://minio:9000"
    HEALTH_PROBE_TIMEOUT_SECONDS: float = 3.0
    # Per-case investigation lock: TTL is refreshed while the investigation runs, and
    # expires on its own if the holder crashes.
    INVESTIGATION_LOCK_TTL_SECONDS: float = 300.0
    # How many times an investigation may immediately re-run because evidence arrived while it ran
    INVESTIGATION_MAX_RERUNS: int = 2
    
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
