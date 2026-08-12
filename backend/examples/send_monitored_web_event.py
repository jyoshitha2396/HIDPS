import argparse
import json
import urllib.request


def main():
    parser = argparse.ArgumentParser(description="Send a monitored web event to the backend model endpoint.")
    parser.add_argument("--endpoint", required=True, help="Base backend URL, for example https://hidps.onrender.com")
    parser.add_argument("--page-url", required=True, help="Public page URL being monitored.")
    parser.add_argument("--request-path", default="/login")
    parser.add_argument("--http-method", default="POST")
    parser.add_argument("--source-ip", default="203.0.113.25")
    parser.add_argument("--asset-name", default="checkout-web")
    parser.add_argument("--telemetry-source", default="demo-web-monitor")
    parser.add_argument("--feature", action="append", default=[], help="Key=value feature pair.")
    parser.add_argument("--auto-prevent", action="store_true")
    args = parser.parse_args()

    features = {}
    for item in args.feature:
        if "=" not in item:
            raise ValueError(f"Feature must use key=value format: {item}")
        key, value = item.split("=", 1)
        try:
            parsed_value = float(value) if "." in value or value.isdigit() else value
        except ValueError:
            parsed_value = value
        features[key] = parsed_value

    payload = {
        "page_url": args.page_url,
        "request_path": args.request_path,
        "http_method": args.http_method,
        "source_ip": args.source_ip,
        "asset_name": args.asset_name,
        "telemetry_source": args.telemetry_source,
        "auto_prevent": args.auto_prevent,
        "features": features,
    }

    request = urllib.request.Request(
        f"{args.endpoint.rstrip('/')}/api/model/evaluate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request) as response:
        print(response.read().decode("utf-8"))


if __name__ == "__main__":
    main()
