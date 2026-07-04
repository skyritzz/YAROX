from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "YAROX"
    VERSION: str = "0.1.0"
    DATABASE_URL: str = "postgresql+asyncpg://yarox:yaroxpassword@localhost:5432/yarox"
    REDIS_URL: str = "redis://localhost:6379/0"

    class Config:
        env_file = ".env"

settings = Settings()
