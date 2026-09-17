import os
from pathlib import Path
from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

# Explicitly load .env from backend root
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(dotenv_path=env_path, override=True)

class Settings(BaseSettings):
    """Platform configuration settings."""
    
    # Project Settings
    PROJECT_NAME: str = "Enterprise Compliance Platform"
    ENV: str = Field("development")
    
    # PostgreSQL Settings
    POSTGRES_USER: str = Field("postgres")
    POSTGRES_PASSWORD: str = Field("postgres")
    POSTGRES_HOST: str = Field("localhost")
    POSTGRES_PORT: int = Field(5432)
    POSTGRES_DB: str = Field("compliance_db")
    
    # MongoDB Settings
    MONGODB_URL: str = Field("mongodb://localhost:27017")
    MONGODB_DB_NAME: str = Field("compliance_raw_db")

    # Storage Settings
    STORAGE_PROVIDER: str = Field("local")
    LOCAL_STORAGE_PATH: str = Field("/tmp/compliance_evidence")
    S3_BUCKET_NAME: str = Field("compliance-evidence-bucket")
    
    # Custom Override
    DATABASE_URL: str | None = Field(None)

    # Atlassian OAuth 2.0 (3LO) Settings
    JIRA_CLIENT_ID: str = Field("")
    JIRA_CLIENT_SECRET: str = Field("")
    JIRA_REDIRECT_URI: str = Field("http://127.0.0.1:8000/api/auth/jira/callback")
    JIRA_OAUTH_SCOPES: str = Field(
        "read:jira-work read:jira-user offline_access"
    )

    model_config = SettingsConfigDict(
        env_file=str(env_path),
        env_file_encoding="utf-8",
        extra="ignore"
    )


    @property
    def database_url(self) -> str:
        """Construct database connection string."""
        # Fallback to SQLite if DATABASE_URL is set or for development tests
        if self.DATABASE_URL:
            return self.DATABASE_URL
        db_url = os.environ.get("DATABASE_URL")
        if db_url:
            return db_url
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_HOST}:{self.POSTGRES_PORT}/{self.POSTGRES_DB}"

settings = Settings()
