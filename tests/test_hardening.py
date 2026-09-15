import pytest
from app.scanner.target_validator import TargetValidator, TargetValidationError
from app.core.rate_limiter import InMemoryRateLimiter

def test_anti_ssrf_rejects_cloud_metadata():
    # Attempting to coerce the scanner into reading AWS metadata
    with pytest.raises(TargetValidationError) as exc:
        TargetValidator.validate_target("http://169.254.169.254/latest/meta-data/")
    assert "Security Policy Violation" in str(exc.value)

def test_anti_ssrf_rejects_gcp_metadata():
    with pytest.raises(TargetValidationError) as exc:
        TargetValidator.validate_target("http://metadata.google.internal/computeMetadata/v1/")
    assert "Security Policy Violation" in str(exc.value)

def test_anti_ssrf_rejects_file_scheme():
    with pytest.raises(TargetValidationError) as exc:
        TargetValidator.validate_target("file:///etc/passwd")
    assert "Invalid URL scheme" in str(exc.value)

def test_anti_ssrf_rejects_gopher_scheme():
    with pytest.raises(TargetValidationError) as exc:
        TargetValidator.validate_target("gopher://127.0.0.1:6379/_flushall")
    assert "Invalid URL scheme" in str(exc.value)

def test_rate_limiter_defense():
    limiter = InMemoryRateLimiter(limit=5, window_seconds=60)
    client_ip = "198.51.100.42"
    
    # 5 requests should be allowed
    for _ in range(5):
        assert limiter.is_allowed(client_ip) is True
        
    # 6th request should be blocked
    assert limiter.is_allowed(client_ip) is False
