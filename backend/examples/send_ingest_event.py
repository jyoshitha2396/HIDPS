import argparse
import json
from urllib import request


def parse_feature(raw_value: str):
    lowered = raw_value.lower()
    if lowered in {"true", "false"}:
        return lowered == "true"
    try:
        if "." in raw_value:
            return float(raw_value)
        return int(raw_value)
    except ValueError:
        return raw_value


def build_parser():
    parser = argparse.ArgumentParser(description="Send a custom telemetry event to the SOC ingest API.")
    parser.add_argument("--api", default="http://localhost:8000/api/ingest/features")
    parser.add_argument("--attack-type", default="Normal")
    parser.add_argument("--source-ip", required=True)
    parser.add_argument("--dest-ip")
    parser.add_argument("--source-type", default="network-flow")
    parser.add_argument("--telemetry-source", default="custom-ingest")
    parser.add_argument("--asset-name")
    parser.add_argument("--edge-node-id")
    parser.add_argument("--severity")
    parser.add_argument("--confidence", type=float)
    parser.add_argument("--correlation-score", type=float)
    parser.add_argument(
        "--feature",
        action="append",
        default=[],
        help="Extra feature in key=value form. Use multiple times.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    features = {}
    for item in args.feature:
        if "=" not in item:
            parser.error(f"Invalid feature '{item}'. Use key=value.")
        key, value = item.split("=", 1)
        features[key] = parse_feature(value)

    payload = {
        "attack_type": args.attack_type,
        "source_ip": args.source_ip,
        "dest_ip": args.dest_ip,
        "source_type": args.source_type,
        "telemetry_source": args.telemetry_source,
        "asset_name": args.asset_name,
        "edge_node_id": args.edge_node_id,
        "severity": args.severity,
        "confidence": args.confidence,
        "correlation_score": args.correlation_score,
        "features": features,
    }
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
