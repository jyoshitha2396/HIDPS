import argparse
import json
import re
from pathlib import Path
from urllib import request


LOG_PATTERN = re.compile(
    r'(?P<source_ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) \S+" '
    r"(?P<status>\d{3}) (?P<body_bytes>\d+) "
)


def classify_event(path: str, status_code: int):
    lowered_path = path.lower()
    if any(token in lowered_path for token in ["/wp-admin", "/admin", "select", "union", "../"]):
        return "Web Attack"
    if "login" in lowered_path and status_code in {401, 403, 429}:
        return "Brute Force"
    if status_code >= 500:
        return "Infiltration"
    return "Normal"


def parse_line(raw_line: str, telemetry_source: str, asset_name: str):
    match = LOG_PATTERN.search(raw_line)
    if not match:
        raise ValueError("Line does not match the expected Nginx combined log format.")

    source_ip = match.group("source_ip")
    path = match.group("path")
    status_code = int(match.group("status"))
    body_bytes = int(match.group("body_bytes"))
    attack_type = classify_event(path, status_code)

    return {
        "attack_type": attack_type,
        "source_ip": source_ip,
        "source_type": "web-access",
        "telemetry_source": telemetry_source,
        "asset_name": asset_name,
        "features": {
            "request_path": path,
            "http_method": match.group("method"),
            "status_code": status_code,
            "body_bytes": body_bytes,
            "failed_logins": 1 if attack_type == "Brute Force" else 0,
            "payload_kb": round(body_bytes / 1024, 3),
        },
    }


def main():
    parser = argparse.ArgumentParser(description="Send recent Nginx access log lines to the SOC ingest API.")
    parser.add_argument("--log-file", required=True)
    parser.add_argument("--api", default="http://localhost:8000/api/ingest/features")
    parser.add_argument("--telemetry-source", default="nginx-access")
    parser.add_argument("--asset-name", default="public-web")
    parser.add_argument("--limit", type=int, default=5)
    args = parser.parse_args()

    lines = [line.strip() for line in Path(args.log_file).read_text(encoding="utf-8").splitlines() if line.strip()]
    for raw_line in lines[-args.limit :]:
        payload = parse_line(raw_line, args.telemetry_source, args.asset_name)
        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            args.api,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req) as response:
            print(response.read().decode("utf-8"))


if __name__ == "__main__":
    main()
