import os
import pytest
import httpx
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from fastapi.testclient import TestClient

# Must set these before importing the app
os.environ["WAF_API_KEY"] = "test-secret"
os.environ["WAF_UPSTREAM_URL"] = "http://mock-upstream.local"
os.environ["WAF_MAX_BODY_BYTES"] = "1048576" # 1MB limit for tests

from api.waf_api import app
import api.waf_api as waf_api
from inference.detector import DetectionResult

@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c

@pytest.fixture
def mock_aiohttp():
    with patch("aiohttp.ClientSession.request") as mock_req:
        # Create a mock response
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.headers = {"Content-Type": "application/json"}
        mock_resp.read = AsyncMock(return_value=b'{"status": "ok"}')
        
        ctx = AsyncMock()
        ctx.__aenter__.return_value = mock_resp
        mock_req.return_value = ctx
        yield mock_req

@pytest.fixture
def mock_detector():
    with patch("api.waf_api.detector.detect", new_callable=AsyncMock) as mock_detect:
        yield mock_detect

def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200

def test_normal_forwarding(client, mock_aiohttp, mock_detector):
    # Setup mock detection to return benign
    mock_detector.return_value = DetectionResult(
        is_anomalous=False,
        anomaly_score=0.1,
        threshold=0.8,
        reconstruction_error=0.01,
        perplexity=10.0,
        normalized_request="GET /api/test?query=123"
    )
    
    waf_api.SYSTEM_CONFIG.detection_mode = "block"
    
    response = client.get("/api/test?query=123", headers={"x-test-id": "req-1"})
    assert response.status_code == 200
    
    # Assert upstream was called
    mock_aiohttp.assert_called_once()
    args, kwargs = mock_aiohttp.call_args
    assert kwargs["method"] == "GET"
    assert "mock-upstream.local/api/test?query=123" in kwargs["url"]
    assert kwargs["headers"].get("x-test-id") == "req-1"

def test_post_forwarding(client, mock_aiohttp, mock_detector):
    mock_detector.return_value = DetectionResult(
        is_anomalous=False,
        anomaly_score=0.1,
        threshold=0.8,
        reconstruction_error=0.01,
        perplexity=10.0,
        normalized_request="POST /api/test"
    )
    
    waf_api.SYSTEM_CONFIG.detection_mode = "block"
    
    response = client.post("/api/test", json={"data": "safe"})
    assert response.status_code == 200
    mock_aiohttp.assert_called_once()
    args, kwargs = mock_aiohttp.call_args
    assert kwargs["method"] == "POST"
    assert kwargs["data"] == b'{"data":"safe"}'

def test_block_mode(client, mock_aiohttp, mock_detector):
    # Setup mock detection to return anomalous
    mock_detector.return_value = DetectionResult(
        is_anomalous=True,
        anomaly_score=0.99,
        threshold=0.8,
        reconstruction_error=1.5,
        perplexity=500.0,
        normalized_request="POST /api/test"
    )
    
    waf_api.SYSTEM_CONFIG.detection_mode = "block"
    
    response = client.post("/api/test", json={"payload": "DROP TABLE users;"})
    assert response.status_code == 403
    
    # CRITICAL WAF ASSERTION: Upstream MUST NOT be contacted!
    mock_aiohttp.assert_not_called()
    
    result = response.json()
    assert result["error"] == "Request blocked by WAF"

def test_monitor_mode(client, mock_aiohttp, mock_detector):
    mock_detector.return_value = DetectionResult(
        is_anomalous=True,
        anomaly_score=0.99,
        threshold=0.8,
        reconstruction_error=1.5,
        perplexity=500.0,
        normalized_request="POST /api/test"
    )
    
    # Set monitor mode
    waf_api.SYSTEM_CONFIG.detection_mode = "monitor"
    
    response = client.post("/api/test", json={"payload": "attack"})
    
    # Assert allowed and forwarded despite anomaly
    assert response.status_code == 200
    mock_aiohttp.assert_called_once()

def test_oversized_payload(client, mock_aiohttp):
    large_body = "x" * 2000000 # 2MB
    response = client.post("/api/test", content=large_body, headers={"Content-Length": "2000000"})
    
    assert response.status_code == 413 # Payload Too Large
    mock_aiohttp.assert_not_called()

def test_header_sanitization(client, mock_aiohttp, mock_detector):
    mock_detector.return_value = DetectionResult(
        is_anomalous=False,
        anomaly_score=0.1,
        threshold=0.8,
        reconstruction_error=0.01,
        perplexity=10.0,
        normalized_request="GET /api/test"
    )
    
    response = client.get("/api/test", headers={
        "Proxy-Authorization": "Basic 123",
        "Connection": "Keep-Alive",
        "X-Safe-Header": "Allowed"
    })
    
    assert response.status_code == 200
    mock_aiohttp.assert_called_once()
    
    forwarded_headers = mock_aiohttp.call_args[1]["headers"]
    assert "proxy-authorization" not in forwarded_headers
    assert "connection" not in forwarded_headers
    assert "x-safe-header" in forwarded_headers

def test_auth_invalid(client):
    response = client.post("/config", json={"detection_mode": "block", "demo_mode": False}, headers={"x-api-key": "wrong"})
    assert response.status_code == 401

def test_auth_valid(client):
    response = client.post("/config", json={"detection_mode": "block", "demo_mode": False}, headers={"x-api-key": "test-secret"})
    assert response.status_code == 200

def test_threshold_sync(client):
    # Update threshold via API
    response = client.post("/config", json={
        "detection_mode": "block",
        "demo_mode": False,
        "anomaly_threshold": 0.75
    }, headers={"x-api-key": "test-secret"})
    
    assert response.status_code == 200
    assert waf_api.SYSTEM_CONFIG.anomaly_threshold == 0.75
