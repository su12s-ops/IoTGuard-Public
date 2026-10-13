"""Read-only HTTP business check; configure and hash THIS file before registering.

This is not a CVE regression test. It deliberately fails until a meaningful
application response marker is configured by the experiment owner.
"""
import hashlib
import http.client
import ipaddress
import json
import sys

PORT = 80
PATH = "/health"
EXPECTED_STATUS = 200
EXPECTED_MARKER = b""  # Set the application's known healthy response marker.


def check(target):
    if not EXPECTED_MARKER:
        return {"passed": False, "evidence": {"reason": "business_marker_not_configured"}}
    host = str(ipaddress.ip_address(target["host"]))
    connection = http.client.HTTPConnection(host, PORT, timeout=5)
    try:
        connection.request("GET", PATH)
        response = connection.getresponse()
        body = response.read(65537)
        within_limit = len(body) <= 65536
        marker_found = within_limit and EXPECTED_MARKER in body
        return {"passed": response.status == EXPECTED_STATUS and marker_found,
                "evidence": {"method": "GET", "path": PATH, "port": PORT, "status": response.status,
                             "response_sha256": hashlib.sha256(body).hexdigest(),
                             "marker_found": marker_found, "within_body_limit": within_limit}}
    finally:
        connection.close()


if __name__ == "__main__":
    try:
        result = check(json.load(sys.stdin))
    except (OSError, ValueError, KeyError, http.client.HTTPException) as exc:
        result = {"passed": False, "evidence": {"reason": type(exc).__name__}}
    print(json.dumps(result))
