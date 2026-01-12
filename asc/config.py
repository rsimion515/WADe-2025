"""
Configuration management for ASC system.
"""

from pydantic_settings import BaseSettings
from functools import lru_cache
from typing import Optional


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    app_name: str = "ASC - Web Application Security Control"
    app_version: str = "1.0.0"
    debug: bool = False
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Database
    database_url: str = "sqlite+aiosqlite:///./asc.db"
    
    # Caching
    cache_ttl: int = 300  # seconds
    proxy_cache_ttl: int = 600  # seconds
    
    # WebSub
    websub_hub_url: str = "http://localhost:8000/websub/hub"
    websub_lease_seconds: int = 86400  # 24 hours
    
    # RDF Namespace
    asc_namespace: str = "http://asc.example.org/ontology#"
    asc_data_namespace: str = "http://asc.example.org/data/"
    
    class Config:
        env_prefix = "ASC_"
        env_file = ".env"
        extra = "ignore"


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
