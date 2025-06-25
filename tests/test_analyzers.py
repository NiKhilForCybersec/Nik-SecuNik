"""
Comprehensive test suite for SecuNik LogX analyzers
Tests all analysis engines with various file types and scenarios
"""

import pytest
import asyncio
from pathlib import Path
from unittest.mock import Mock, patch, AsyncMock
import json
import tempfile
from datetime import datetime, timedelta

# Import all analyzers
from backend.analyzers.yara_analyzer import YaraAnalyzer
from backend.analyzers.sigma_analyzer import SigmaAnalyzer
from backend.analyzers.mitre_analyzer import MITREAnalyzer
from backend.analyzers.ai_analyzer import AIAnalyzer
from backend.analyzers.pattern_analyzer import PatternAnalyzer
from backend.analyzers.anomaly_detector import AnomalyDetector
from backend.analyzers.ioc_extractor import IOCExtractor
from backend.analyzers.correlation_engine import CorrelationEngine
from backend.integrations.virustotal_client import VirusTotalClient


class TestYaraAnalyzer:
    """Test YARA rule analysis"""
    
    @pytest.fixture
    def yara_analyzer(self):
        return YaraAnalyzer()
    
    @pytest.fixture
    def sample_yara_rule(self):
        return """
        rule test_malware {
            meta:
                description = "Test malware detection"
                severity = "high"
            strings:
                $a = "malicious_string"
                $b = {48 65 6c 6c 6f}
            condition:
                any of them
        }
        """
    
    async def test_compile_rules(self, yara_analyzer, sample_yara_rule, tmp_path):
        """Test YARA rule compilation"""
        rule_file = tmp_path / "test.yar"
        rule_file.write_text(sample_yara_rule)
        
        result = await yara_analyzer.compile_rules(str(tmp_path))
        assert result["status"] == "success"
        assert result["rules_loaded"] == 1
    
    async def test_scan_content(self, yara_analyzer):
        """Test content scanning with YARA"""
        content = "This contains a malicious_string in the text"
        
        with patch.object(yara_analyzer, 'compiled_rules') as mock_rules:
            mock_match = Mock()
            mock_match.rule = "test_malware"
            mock_match.meta = {"description": "Test malware", "severity": "high"}
            mock_rules.match.return_value = [mock_match]
            
            results = await yara_analyzer.scan_content(content)
            assert len(results) == 1
            assert results[0]["rule"] == "test_malware"
            assert results[0]["severity"] == "high"
    
    async def test_scan_file(self, yara_analyzer, tmp_path):
        """Test file scanning with YARA"""
        test_file = tmp_path / "malware.exe"
        test_file.write_bytes(b"Hello\x00malicious_string\x00World")
        
        with patch.object(yara_analyzer, 'compiled_rules') as mock_rules:
            mock_rules.match.return_value = []
            
            results = await yara_analyzer.scan_file(str(test_file))
            assert isinstance(results, list)


class TestSigmaAnalyzer:
    """Test Sigma rule analysis"""
    
    @pytest.fixture
    def sigma_analyzer(self):
        return SigmaAnalyzer()
    
    @pytest.fixture
    def sample_sigma_rule(self):
        return {
            "title": "Suspicious PowerShell Download",
            "logsource": {
                "product": "windows",
                "service": "powershell"
            },
            "detection": {
                "selection": {
                    "EventID": 4104,
                    "ScriptBlockText|contains": [
                        "Invoke-WebRequest",
                        "DownloadFile"
                    ]
                },
                "condition": "selection"
            },
            "level": "high"
        }
    
    async def test_load_rules(self, sigma_analyzer, sample_sigma_rule, tmp_path):
        """Test Sigma rule loading"""
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(json.dumps(sample_sigma_rule))
        
        result = await sigma_analyzer.load_rules(str(tmp_path))
        assert result["rules_loaded"] >= 1
    
    async def test_analyze_events(self, sigma_analyzer, sample_sigma_rule):
        """Test event analysis with Sigma rules"""
        events = [
            {
                "EventID": 4104,
                "ScriptBlockText": "Invoke-WebRequest -Uri http://malicious.com",
                "TimeCreated": "2024-01-01T10:00:00Z"
            }
        ]
        
        sigma_analyzer.rules = [sample_sigma_rule]
        
        results = await sigma_analyzer.analyze_events(events)
        assert len(results["matches"]) == 1
        assert results["matches"][0]["rule"] == "Suspicious PowerShell Download"
        assert results["matches"][0]["level"] == "high"


class TestMITREAnalyzer:
    """Test MITRE ATT&CK mapping"""
    
    @pytest.fixture
    def mitre_analyzer(self):
        return MITREAnalyzer()
    
    async def test_map_techniques(self, mitre_analyzer):
        """Test technique mapping"""
        events = [
            {
                "type": "process_creation",
                "process": "powershell.exe",
                "command_line": "powershell -enc <base64>",
                "tags": ["encoded_command", "powershell"]
            }
        ]
        
        mappings = await mitre_analyzer.map_techniques(events)
        assert len(mappings) > 0
        assert any(t["technique_id"] == "T1059.001" for t in mappings)
    
    async def test_generate_navigator_layer(self, mitre_analyzer):
        """Test ATT&CK Navigator layer generation"""
        techniques = ["T1059.001", "T1055", "T1003.001"]
        
        layer = await mitre_analyzer.generate_navigator_layer(
            techniques,
            name="Test Layer"
        )
        assert layer["name"] == "Test Layer"
        assert len(layer["techniques"]) == 3


class TestAIAnalyzer:
    """Test AI-powered analysis"""
    
    @pytest.fixture
    def ai_analyzer(self):
        return AIAnalyzer(api_key="test_key")
    
    @pytest.mark.asyncio
    async def test_analyze_content(self, ai_analyzer):
        """Test AI content analysis"""
        content = "Suspicious activity detected: multiple failed login attempts"
        
        with patch.object(ai_analyzer.client.chat.completions, 'create') as mock_create:
            mock_response = Mock()
            mock_response.choices = [Mock(message=Mock(content=json.dumps({
                "threat_level": "medium",
                "indicators": ["brute_force_attempt"],
                "recommendations": ["Enable account lockout policy"]
            })))]
            mock_create.return_value = mock_response
            
            result = await ai_analyzer.analyze_security_event(content)
            assert result["threat_level"] == "medium"
            assert "brute_force_attempt" in result["indicators"]
    
    @pytest.mark.asyncio
    async def test_generate_summary(self, ai_analyzer):
        """Test AI summary generation"""
        events = [
            {"type": "login_failure", "count": 50},
            {"type": "port_scan", "source": "192.168.1.100"}
        ]
        
        with patch.object(ai_analyzer.client.chat.completions, 'create') as mock_create:
            mock_response = Mock()
            mock_response.choices = [Mock(message=Mock(
                content="Multiple security events detected including failed logins and port scanning"
            ))]
            mock_create.return_value = mock_response
            
            summary = await ai_analyzer.generate_summary(events)
            assert "security events" in summary.lower()


class TestPatternAnalyzer:
    """Test pattern detection"""
    
    @pytest.fixture
    def pattern_analyzer(self):
        return PatternAnalyzer()
    
    async def test_detect_patterns(self, pattern_analyzer):
        """Test pattern detection in events"""
        events = [
            {"ip": "192.168.1.100", "action": "login_fail", "time": "10:00:00"},
            {"ip": "192.168.1.100", "action": "login_fail", "time": "10:00:05"},
            {"ip": "192.168.1.100", "action": "login_fail", "time": "10:00:10"},
            {"ip": "192.168.1.100", "action": "login_success", "time": "10:00:15"}
        ]
        
        patterns = await pattern_analyzer.detect_patterns(events)
        assert len(patterns) > 0
        assert any(p["pattern_type"] == "brute_force" for p in patterns)
    
    async def test_time_series_analysis(self, pattern_analyzer):
        """Test time series pattern analysis"""
        timestamps = [
            datetime.now() - timedelta(minutes=i) 
            for i in range(100, 0, -1)
        ]
        
        # Create periodic pattern
        for i in range(0, 100, 10):
            timestamps.append(timestamps[i])
        
        patterns = await pattern_analyzer.analyze_time_series(timestamps)
        assert "periodic" in patterns


class TestAnomalyDetector:
    """Test anomaly detection"""
    
    @pytest.fixture
    def anomaly_detector(self):
        return AnomalyDetector()
    
    async def test_detect_statistical_anomalies(self, anomaly_detector):
        """Test statistical anomaly detection"""
        data = [10, 12, 11, 13, 12, 11, 10, 12, 100, 11, 12, 10]  # 100 is anomaly
        
        anomalies = await anomaly_detector.detect_anomalies(data)
        assert len(anomalies) == 1
        assert anomalies[0]["value"] == 100
        assert anomalies[0]["score"] > 0.8
    
    async def test_detect_behavioral_anomalies(self, anomaly_detector):
        """Test behavioral anomaly detection"""
        user_events = [
            {"user": "john", "action": "login", "time": "09:00", "location": "office"},
            {"user": "john", "action": "file_access", "time": "09:30", "location": "office"},
            {"user": "john", "action": "login", "time": "03:00", "location": "china"},  # Anomaly
        ]
        
        anomalies = await anomaly_detector.detect_behavioral_anomalies(user_events)
        assert len(anomalies) > 0
        assert anomalies[0]["type"] == "unusual_login_location"


class TestIOCExtractor:
    """Test IOC extraction"""
    
    @pytest.fixture
    def ioc_extractor(self):
        return IOCExtractor()
    
    async def test_extract_ips(self, ioc_extractor):
        """Test IP address extraction"""
        text = "Connection from 192.168.1.100 and 10.0.0.1, also saw 256.1.1.1"
        
        iocs = await ioc_extractor.extract_iocs(text)
        assert len(iocs["ip_addresses"]) == 2
        assert "192.168.1.100" in iocs["ip_addresses"]
        assert "256.1.1.1" not in iocs["ip_addresses"]  # Invalid IP
    
    async def test_extract_domains(self, ioc_extractor):
        """Test domain extraction"""
        text = "Detected malware.evil.com and phishing-site.net connections"
        
        iocs = await ioc_extractor.extract_iocs(text)
        assert len(iocs["domains"]) == 2
        assert "malware.evil.com" in iocs["domains"]
    
    async def test_extract_hashes(self, ioc_extractor):
        """Test hash extraction"""
        text = """
        MD5: d41d8cd98f00b204e9800998ecf8427e
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        
        iocs = await ioc_extractor.extract_iocs(text)
        assert len(iocs["hashes"]["md5"]) == 1
        assert len(iocs["hashes"]["sha256"]) == 1


class TestCorrelationEngine:
    """Test event correlation"""
    
    @pytest.fixture
    def correlation_engine(self):
        return CorrelationEngine()
    
    async def test_correlate_events(self, correlation_engine):
        """Test event correlation"""
        events = [
            {"id": 1, "type": "firewall_block", "src_ip": "192.168.1.100", "time": "10:00:00"},
            {"id": 2, "type": "ids_alert", "src_ip": "192.168.1.100", "time": "10:00:05"},
            {"id": 3, "type": "login_failure", "src_ip": "192.168.1.100", "time": "10:00:10"}
        ]
        
        correlations = await correlation_engine.correlate_events(events)
        assert len(correlations) > 0
        assert correlations[0]["correlation_type"] == "attack_chain"
        assert len(correlations[0]["events"]) == 3
    
    async def test_create_timeline(self, correlation_engine):
        """Test timeline creation"""
        events = [
            {"timestamp": "2024-01-01T10:00:00Z", "action": "scan_started"},
            {"timestamp": "2024-01-01T10:05:00Z", "action": "vulnerability_found"},
            {"timestamp": "2024-01-01T10:10:00Z", "action": "exploit_attempt"}
        ]
        
        timeline = await correlation_engine.create_timeline(events)
        assert len(timeline) == 3
        assert timeline[0]["action"] == "scan_started"


class TestVirusTotalIntegration:
    """Test VirusTotal integration"""
    
    @pytest.fixture
    def vt_client(self):
        return VirusTotalClient(api_key="test_key")
    
    @pytest.mark.asyncio
    async def test_check_hash(self, vt_client):
        """Test hash checking"""
        hash_value = "d41d8cd98f00b204e9800998ecf8427e"
        
        with patch('aiohttp.ClientSession.get') as mock_get:
            mock_response = AsyncMock()
            mock_response.json = AsyncMock(return_value={
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 45,
                            "suspicious": 5,
                            "harmless": 10
                        }
                    }
                }
            })
            mock_get.return_value.__aenter__.return_value = mock_response
            
            result = await vt_client.check_hash(hash_value)
            assert result["malicious"] == 45
            assert result["detection_rate"] > 0.7


if __name__ == "__main__":
    pytest.main([__file__, "-v"])