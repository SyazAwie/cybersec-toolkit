import pytest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from network_utils import safe_port_scan, ALLOWED_HOSTS

def test_scan_blocked_host_fails():
    with pytest.raises(ValueError, match="not in allowed list"):
        safe_port_scan("google.com", [80])

def test_scan_localhost_works():
    # This should run without crashing. Port 80 may be closed, but no exception.
    results = safe_port_scan("127.0.0.1", [80], timeout=0.1)
    assert 80 in results
    assert results[80] in ["Open", "Closed", "Filtered", "Error"]

def test_invalid_port():
    results = safe_port_scan("127.0.0.1", [99999])
    assert results[99999] == "Invalid"