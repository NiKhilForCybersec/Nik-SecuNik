"""
API endpoint tests for SecuNik LogX
Tests all REST API endpoints with various scenarios
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import Mock, patch, AsyncMock
import json
import io
from datetime import datetime
import asyncio

from backend.main import app


@pytest.fixture
def client():
    """Create test client"""
    return TestClient(app)


@pytest.fixture
def mock_file():
    """Create mock file upload"""
    return io.BytesIO(b"Test file content")


class TestUploadAPI:
    """Test file upload endpoints"""
    
    def test_upload_file_success(self, client, mock_file):
        """Test successful file upload"""
        with patch('backend.api.upload.storage_manager.save_file') as mock_save:
            mock_save.return_value = "12345"
            
            response = client.post(
                "/api/upload",
                files={"file": ("test.log", mock_file, "text/plain")}
            )
            
            assert response.status_code == 200
            assert response.json()["file_id"] == "12345"
    
    def test_upload_large_file(self, client):
        """Test large file upload handling"""
        large_file = io.BytesIO(b"x" * (100 * 1024 * 1024))  # 100MB
        
        response = client.post(
            "/api/upload",
            files={"file": ("large.log", large_file, "text/plain")}
        )
        
        assert response.status_code == 413
        assert "too large" in response.json()["detail"].lower()
    
    def test_upload_invalid_file_type(self, client):
        """Test invalid file type rejection"""
        response = client.post(
            "/api/upload",
            files={"file": ("test.xyz", mock_file, "application/unknown")}
        )
        
        assert response.status_code == 400
    
    def test_batch_upload(self, client):
        """Test multiple file upload"""
        files = [
            ("files", ("test1.log", io.BytesIO(b"content1"), "text/plain")),
            ("files", ("test2.log", io.BytesIO(b"content2"), "text/plain"))
        ]
        
        with patch('backend.api.upload.storage_manager.save_file') as mock_save:
            mock_save.side_effect = ["id1", "id2"]
            
            response = client.post("/api/upload/batch", files=files)
            
            assert response.status_code == 200
            assert len(response.json()["files"]) == 2


class TestAnalysisAPI:
    """Test analysis endpoints"""
    
    def test_start_analysis(self, client):
        """Test analysis initiation"""
        with patch('backend.api.analysis.analysis_engine.analyze_file') as mock_analyze:
            mock_analyze.return_value = {"status": "started", "job_id": "job123"}
            
            response = client.post("/api/analyze/file123")
            
            assert response.status_code == 200
            assert response.json()["job_id"] == "job123"
    
    def test_get_analysis_status(self, client):
        """Test analysis status retrieval"""
        with patch('backend.api.analysis.get_analysis_status') as mock_status:
            mock_status.return_value = {
                "status": "in_progress",
                "progress": 75,
                "current_step": "Running YARA scan"
            }
            
            response = client.get("/api/analyze/status/job123")
            
            assert response.status_code == 200
            assert response.json()["progress"] == 75
    
    def test_get_analysis_results(self, client):
        """Test analysis results retrieval"""
        with patch('backend.api.analysis.get_analysis_results') as mock_results:
            mock_results.return_value = {
                "iocs": ["192.168.1.1", "malware.com"],
                "patterns": ["brute_force"],
                "severity": "high"
            }
            
            response = client.get("/api/analyze/results/job123")
            
            assert response.status_code == 200
            assert response.json()["severity"] == "high"
    
    def test_cancel_analysis(self, client):
        """Test analysis cancellation"""
        with patch('backend.api.analysis.cancel_analysis') as mock_cancel:
            mock_cancel.return_value = True
            
            response = client.delete("/api/analyze/job123")
            
            assert response.status_code == 200
            assert response.json()["status"] == "cancelled"


class TestHistoryAPI:
    """Test history endpoints"""
    
    def test_get_history(self, client):
        """Test history retrieval"""
        with patch('backend.api.history.get_analysis_history') as mock_history:
            mock_history.return_value = {
                "analyses": [
                    {
                        "id": "123",
                        "filename": "test.log",
                        "timestamp": "2024-01-01T10:00:00Z",
                        "status": "completed"
                    }
                ],
                "total": 1,
                "page": 1
            }
            
            response = client.get("/api/history")
            
            assert response.status_code == 200
            assert len(response.json()["analyses"]) == 1
    
    def test_search_history(self, client):
        """Test history search"""
        response = client.get("/api/history/search?q=malware&date_from=2024-01-01")
        
        assert response.status_code == 200
    
    def test_export_history(self, client):
        """Test history export"""
        response = client.get("/api/history/export?format=csv")
        
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/csv"


class TestRulesAPI:
    """Test rule management endpoints"""
    
    def test_get_rules(self, client):
        """Test rule listing"""
        with patch('backend.api.rules.rule_manager.get_rules') as mock_get:
            mock_get.return_value = [
                {
                    "id": "rule1",
                    "name": "Test Rule",
                    "type": "yara",
                    "enabled": True
                }
            ]
            
            response = client.get("/api/rules")
            
            assert response.status_code == 200
            assert len(response.json()) == 1
    
    def test_create_rule(self, client):
        """Test rule creation"""
        rule_data = {
            "name": "New Rule",
            "type": "sigma",
            "content": "detection: selection: EventID: 4625"
        }
        
        response = client.post("/api/rules", json=rule_data)
        
        assert response.status_code == 201
    
    def test_update_rule(self, client):
        """Test rule update"""
        update_data = {"enabled": False}
        
        response = client.patch("/api/rules/rule1", json=update_data)
        
        assert response.status_code == 200
    
    def test_delete_rule(self, client):
        """Test rule deletion"""
        response = client.delete("/api/rules/rule1")
        
        assert response.status_code == 204
    
    def test_test_rule(self, client):
        """Test rule validation"""
        rule_content = {
            "type": "yara",
            "content": "rule test { condition: true }"
        }
        
        response = client.post("/api/rules/test", json=rule_content)
        
        assert response.status_code == 200


class TestVirusTotalAPI:
    """Test VirusTotal integration endpoints"""
    
    def test_check_hash(self, client):
        """Test hash checking"""
        with patch('backend.api.virustotal.vt_client.check_hash') as mock_check:
            mock_check.return_value = {
                "malicious": 45,
                "suspicious": 5,
                "harmless": 10,
                "undetected": 5
            }
            
            response = client.get("/api/virustotal/hash/d41d8cd98f00b204e9800998ecf8427e")
            
            assert response.status_code == 200
            assert response.json()["malicious"] == 45
    
    def test_check_ip(self, client):
        """Test IP checking"""
        response = client.get("/api/virustotal/ip/192.168.1.1")
        
        assert response.status_code == 200
    
    def test_check_domain(self, client):
        """Test domain checking"""
        response = client.get("/api/virustotal/domain/example.com")
        
        assert response.status_code == 200
    
    def test_batch_check(self, client):
        """Test batch IOC checking"""
        iocs = {
            "hashes": ["hash1", "hash2"],
            "ips": ["192.168.1.1"],
            "domains": ["example.com"]
        }
        
        response = client.post("/api/virustotal/batch", json=iocs)
        
        assert response.status_code == 200


class TestWebSocketAPI:
    """Test WebSocket endpoints"""
    
    def test_websocket_connection(self, client):
        """Test WebSocket connection"""
        with client.websocket_connect("/ws") as websocket:
            data = websocket.receive_json()
            assert data["type"] == "connection"
            assert data["status"] == "connected"
    
    def test_websocket_analysis_updates(self, client):
        """Test real-time analysis updates"""
        with client.websocket_connect("/ws") as websocket:
            # Subscribe to analysis updates
            websocket.send_json({
                "action": "subscribe",
                "channel": "analysis",
                "job_id": "job123"
            })
            
            # Simulate analysis update
            with patch('backend.api.websocket.send_update') as mock_send:
                mock_send.return_value = None
                
                # Should receive update
                data = websocket.receive_json()
                assert "analysis" in data


class TestHealthAPI:
    """Test health check endpoints"""
    
    def test_health_check(self, client):
        """Test basic health check"""
        response = client.get("/health")
        
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"
    
    def test_detailed_health(self, client):
        """Test detailed health check"""
        response = client.get("/health/detailed")
        
        assert response.status_code == 200
        assert "database" in response.json()
        assert "storage" in response.json()
        assert "analyzers" in response.json()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])