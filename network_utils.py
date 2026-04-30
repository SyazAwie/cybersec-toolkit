import socket
from typing import List, Dict

# SECURITY: Whitelist only safe hosts for portfolio demo
ALLOWED_HOSTS = ["127.0.0.1", "localhost", "scanme.nmap.org"]
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 8080]

def safe_port_scan(host: str, ports: List[int], timeout: float = 0.5) -> Dict[int, str]:
    """
    Portfolio-safe port scanner. Only scans whitelisted hosts.
    Returns dict {port: 'Open'/'Closed'/'Filtered'}.
    Raises ValueError if host not allowed.
    """
    if host not in ALLOWED_HOSTS:
        raise ValueError(f"Host '{host}' not in allowed list. For legal reasons, only {ALLOWED_HOSTS} permitted.")

    results = {}
    for port in ports:
        if not 1 <= port <= 65535:
            results[port] = "Invalid"
            continue

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            # connect_ex returns 0 if success
            result = sock.connect_ex((host, port))
            if result == 0:
                results[port] = "Open"
            else:
                results[port] = "Closed"
        except socket.timeout:
            results[port] = "Filtered"
        except Exception:
            results[port] = "Error"
        finally:
            sock.close()

    return results