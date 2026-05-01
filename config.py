"""
Central configuration for XAI-SecOps.
Loads settings from environment variables with sensible defaults.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # MongoDB
    mongodb_uri: str = Field(default="mongodb://localhost:27017", description="MongoDB connection URI")
    mongodb_db_name: str = Field(default="system_binary", description="MongoDB database name")

    # Ollama / CodeLlama
    ollama_base_url: str = Field(default="http://localhost:11434", description="Ollama API base URL")
    codellama_model: str = Field(default="codellama:7b", description="CodeLlama model tag")

    # App
    app_env: str = Field(default="development", description="Application environment")
    app_port: int = Field(default=8000, description="Application port")
    log_level: str = Field(default="info", description="Log level")

    # Risk Scoring
    risk_threshold: float = Field(default=7.0, description="Risk score threshold for CI/CD failure")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
