"""Read-only HTTP regression against an already deployed Zephyr instance.

python verify_live.py --host 192.168.183.129 --port 8080 --output evidence.json
Only run against your authorized sensor. Does not update or reboot firmware.
"""
import argparse
import json
import socket
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


def verify(host, port, version, uid):
    def identity():
        with urllib.request.urlopen(f"http://{host}:{port}/api/system", timeout=8) as response:
            value = json.load(response)
        assert value["device_id"] == uid, "Device identity changed"
        assert value["firmware_version"] == version, "Unexpected firmware version"
        assert value["entropy_self_test"] == "passed", "Entropy self-test failed"
        return value

    def request(parts):
        with socket.create_connection((host, port), timeout=8) as sock:
            sock.settimeout(8)
            for part in parts:
                sock.sendall(part)
                if len(parts) > 1:
                    time.sleep(0.1)
            response = bytearray()
            while len(response) < 65536:
                data = sock.recv(4096)
                if not data:
                    break
                response.extend(data)
            return bytes(response)

    result = {"checked_at": datetime.now(timezone.utc).isoformat(), "identity": identity()}
    for name, payload, status in (
        ("prefix_rejected", b"GET /api/system-evil HTTP/1.0\r\n\r\n", b"404"),
        ("method_rejected", b"POST /api/system HTTP/1.0\r\n\r\n", b"400"),
        ("extra_request_token_rejected", b"GET /api/system HTTP/1.0 extra\r\n\r\n", b"400"),
        ("path_traversal_rejected", b"GET /../../etc/passwd HTTP/1.0\r\n\r\n", b"404"),
    ):
        line = request([payload]).split(b"\r\n", 1)[0]
        assert status in line, (name, line)
        result[name] = line.decode("ascii")
    fragmented = request([b"GET /api/", b"system HTTP/1.0\r\n\r\n"])
    assert version.encode() in fragmented
    result["fragmented_request"] = "passed"
    with socket.create_connection((host, port), timeout=8):
        time.sleep(3)
        identity()
    result["idle_client_recovery"] = "passed"
    with socket.create_connection((host, port), timeout=8) as sock:
        sock.sendall(b"A" * 512)
    identity()
    result["oversize_client_recovery"] = "passed"
    for _ in range(20):
        identity()
    result["repeated_identity_requests"] = 20
    result["passed"] = True
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--version", default="0.3.0-iotguard")
    parser.add_argument("--uid", default="ZEPHYR-SENSOR-0001")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    result = verify(args.host, args.port, args.version, args.uid)
    text = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text)
