"""
Configuration management for SecuNik LogX
Handles all application settings and environment variables
"""

import os
from pathlib import Path
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import BaseModel, field_validator


class Settings(BaseSettings):
    """Application settings with environment variable support"""
    
    # Application info
    APP_NAME: str = "SecuNik LogX"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]
    SERVE_FRONTEND: bool = False
    
    # Storage configuration
    STORAGE_PATH: Path = Path("storage")
    UPLOAD_PATH: Path = Path("storage/uploads")
    PARSED_PATH: Path = Path("storage/parsed")
    ANALYSIS_PATH: Path = Path("storage/analysis")
    TEMP_PATH: Path = Path("storage/temp")
    HISTORY_FILE: Path = Path("storage/history.json")
    
    # File upload limits
    MAX_FILE_SIZE_MB: int = 500
    MAX_FILE_SIZE_BYTES: int = 500 * 1024 * 1024  # 500MB
    ALLOWED_EXTENSIONS: Optional[List[str]] = None  # None means all extensions allowed
    CHUNK_SIZE: int = 1024 * 1024  # 1MB chunks for file processing
    
    # Analysis configuration
    ANALYSIS_TIMEOUT: int = 300  # 5 minutes
    MAX_CONCURRENT_ANALYSES: int = 5
    ENABLE_AI_ANALYSIS: bool = True
    
    # External API keys
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4"
    OPENAI_MAX_TOKENS: int = 2000
    OPENAI_TEMPERATURE: float = 0.7
    
    VIRUSTOTAL_API_KEY: Optional[str] = None
    VIRUSTOTAL_TIMEOUT: int = 30
    
    # Rule configuration
    YARA_RULES_PATH: Path = Path("rules/yara")
    SIGMA_RULES_PATH: Path = Path("rules/sigma")
    MITRE_RULES_PATH: Path = Path("rules/mitre")
    CUSTOM_RULES_PATH: Path = Path("rules/custom")
    
    # WebSocket configuration
    WS_HEARTBEAT_INTERVAL: int = 30
    WS_MESSAGE_QUEUE_SIZE: int = 100
    
    # Security
    SECRET_KEY: str = "your-secret-key-change-in-production"
    API_KEY_HEADER: str = "X-API-Key"
    REQUIRE_API_KEY: bool = False
    API_KEYS: List[str] = []
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FILE: Optional[Path] = Path("logs/app.log")
    LOG_MAX_SIZE: int = 10 * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT: int = 5
    
    # Performance
    WORKER_THREADS: int = 4
    ENABLE_CACHE: bool = True
    CACHE_TTL: int = 3600  # 1 hour
    
    # Parser-specific settings
    PCAP_MAX_PACKETS: int = 10000
    LOG_MAX_LINES: int = 100000
    ARCHIVE_MAX_DEPTH: int = 3
    
    @field_validator("CORS_ORIGINS", mode='before')
    @classmethod
    def parse_cors_origins(cls, v):
        """Parse CORS origins from comma-separated string"""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",")]
        return v
    
    @field_validator("API_KEYS", mode='before')
    @classmethod
    def parse_api_keys(cls, v):
        """Parse API keys from comma-separated string"""
        if isinstance(v, str):
            return [key.strip() for key in v.split(",") if key.strip()]
        return v
    
    @field_validator("MAX_FILE_SIZE_BYTES", mode='before')
    @classmethod
    def calculate_max_size(cls, v, info):
        """Calculate max file size in bytes from MB"""
        if info.data.get("MAX_FILE_SIZE_MB"):
            return info.data.get("MAX_FILE_SIZE_MB") * 1024 * 1024
        return v
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False
    )


# Create settings instance
settings = Settings()

# Create directories if they don't exist
for path_attr in ["STORAGE_PATH", "UPLOAD_PATH", "PARSED_PATH", 
                  "ANALYSIS_PATH", "TEMP_PATH", "YARA_RULES_PATH",
                  "SIGMA_RULES_PATH", "MITRE_RULES_PATH", "CUSTOM_RULES_PATH"]:
    path = getattr(settings, path_attr)
    if isinstance(path, Path):
        path.mkdir(parents=True, exist_ok=True)

# Create log directory if logging to file
if settings.LOG_FILE:
    settings.LOG_FILE.parent.mkdir(parents=True, exist_ok=True)


def get_file_extensions() -> List[str]:
    """Get list of allowed file extensions"""
    if settings.ALLOWED_EXTENSIONS:
        return settings.ALLOWED_EXTENSIONS
    
    # Default supported extensions (will be expanded)
    return [
        # Logs
        ".log", ".txt", ".syslog", ".evtx", ".evt", ".etl",
        # Network
        ".pcap", ".pcapng", ".cap", ".netflow", ".zeek", ".bro",
        # Archives
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
        # Documents
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        # Email
        ".eml", ".msg", ".mbox", ".pst", ".ost",
        # Database
        ".sqlite", ".db", ".sql", ".dump",
        # Structured
        ".json", ".xml", ".csv", ".yaml", ".yml", ".ini",
        # Forensics
        ".dd", ".img", ".e01", ".aff", ".vmdk", ".vhd",
        # Mobile
        ".ab", ".logcat", ".ips",
        # Code
        ".py", ".js", ".php", ".sh", ".ps1", ".bat", ".exe", ".dll",
        # Any extension if none specified
        "*"
    ]


# Export commonly used settings
__all__ = ["settings", "get_file_extensions"]