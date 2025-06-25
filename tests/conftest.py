"""
Pytest configuration and fixtures for SecuNik LogX tests
Provides common test utilities and fixtures
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from datetime import datetime
import json
import os

from fastapi.testclient import TestClient
from backend.main import app
from backend.config import settings


# Configure pytest-asyncio
pytest_plugins = ('pytest_asyncio',)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_client():
    """Create a test client for the FastAPI app"""
    with TestClient(app) as client:
        yield client


@pytest.fixture(scope="function")
def temp_storage_dir():
    """Create temporary storage directory for tests"""
    temp_dir = tempfile.mkdtemp()
    yield Path(temp_dir)
    shutil.rmtree(temp_dir)


@pytest.fixture(scope="function")
def mock_settings(monkeypatch, temp_storage_dir):
    """Mock application settings for tests"""
    monkeypatch.setattr(settings, "STORAGE_PATH", str(temp_storage_dir))
    monkeypatch.setattr(settings, "MAX_FILE_SIZE", 10 * 1024 * 1024)  # 10MB
    monkeypatch.setattr(settings, "VIRUSTOTAL_API_KEY", "test_vt_key")
    monkeypatch.setattr(settings, "OPENAI_API_KEY", "test_openai_key")
    return settings


@pytest.fixture
def sample_log_file(temp_storage_dir):
    """Create a sample log file"""
    log_content = """
    2024-01-01 10:00:00 INFO Starting application
    2024-01-01 10:00:05 ERROR Failed login attempt from 192.168.1.100
    2024-01-01 10:00:10 WARNING Suspicious activity detected
    2024-01-01 10:00:15 INFO User admin logged in successfully
    """
    
    log_file = temp_storage_dir / "sample.log"
    log_file.write_text(log_content)
    return log_file


@pytest.fixture
def sample_pcap_data():
    """Create sample PCAP data structure"""
    return {
        "packets": [
            {
                "timestamp": "2024-01-01T10:00:00Z",
                "src_ip": "192.168.1.100",
                "dst_ip": "192.168.1.1",
                "protocol": "TCP",
                "src_port": 54321,
                "dst_port": 80
            },
            {
                "timestamp": "2024-01-01T10:00:01Z",
                "src_ip": "192.168.1.1",
                "dst_ip": "192.168.1.100",
                "protocol": "TCP",
                "src_port": 80,
                "dst_port": 54321
            }
        ]
    }


@pytest.fixture
def sample_events():
    """Create sample security events"""
    return [
        {
            "id": "evt1",
            "timestamp": "2024-01-01T10:00:00Z",
            "type": "login_failure",
            "source_ip": "192.168.1.100",
            "username": "admin",
            "severity": "medium"
        },
        {
            "id": "evt2",
            "timestamp": "2024-01-01T10:00:05Z",
            "type": "port_scan",
            "source_ip": "192.168.1.100",
            "target_ports": [22, 80, 443],
            "severity": "high"
        },
        {
            "id": "evt3",
            "timestamp": "2024-01-01T10:00:10Z",
            "type": "malware_detected",
            "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
            "severity": "critical"
        }
    ]


@pytest.fixture
def sample_iocs():
    """Create sample IOCs"""
    return {
        "ip_addresses": ["192.168.1.100", "10.0.0.1"],
        "domains": ["malware.com", "phishing-site.net"],
        "hashes": {
            "md5": ["d41d8cd98f00b204e9800998ecf8427e"],
            "sha256": ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
        },
        "emails": ["malicious@evil.com"],
        "urls": ["http://malware.com/payload.exe"]
    }


@pytest.fixture
def yara_rules_dir(temp_storage_dir):
    """Create directory with sample YARA rules"""
    rules_dir = temp_storage_dir / "yara_rules"
    rules_dir.mkdir()
    
    # Create sample rule
    rule_content = """
    rule TestMalware {
        meta:
            description = "Test malware detection"
        strings:
            $a = "malicious"
            $b = {48 65 6c 6c 6f}
        condition:
            any of them
    }
    """
    
    (rules_dir / "test.yar").write_text(rule_content)
    return rules_dir


@pytest.fixture
def sigma_rules_dir(temp_storage_dir):
    """Create directory with sample Sigma rules"""
    rules_dir = temp_storage_dir / "sigma_rules"
    rules_dir.mkdir()
    
    # Create sample rule
    rule_content = {
        "title": "Test Rule",
        "logsource": {
            "product": "windows",
            "service": "security"
        },
        "detection": {
            "selection": {
                "EventID": 4625
            },
            "condition": "selection"
        }
    }
    
    (rules_dir / "test.yml").write_text(json.dumps(rule_content))
    return rules_dir


@pytest.fixture
def mock_virustotal_response():
    """Mock VirusTotal API response"""
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 45,
                    "suspicious": 5,
                    "harmless": 10,
                    "undetected": 5
                },
                "last_analysis_results": {
                    "Avast": {"result": "Malware.Generic"},
                    "BitDefender": {"result": "Trojan.Generic"}
                }
            }
        }
    }


@pytest.fixture
def mock_openai_response():
    """Mock OpenAI API response"""
    return {
        "choices": [{
            "message": {
                "content": json.dumps({
                    "threat_level": "high",
                    "analysis": "Detected suspicious behavior patterns",
                    "recommendations": ["Isolate system", "Run full scan"]
                })
            }
        }]
    }


# Cleanup function
def pytest_sessionfinish(session, exitstatus):
    """Clean up after all tests"""
    # Clean any remaining temp files
    temp_dirs = Path(tempfile.gettempdir()).glob("pytest-*")
    for temp_dir in temp_dirs:
        try:
            shutil.rmtree(temp_dir)
        except:
            pass