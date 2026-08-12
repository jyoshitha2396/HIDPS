from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

import requests

BACKEND_DIR = Path(__file__).resolve().parents[1]
ROOT_DIR = BACKEND_DIR.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from model_presets import extract_hardened_ids_features, map_cicids_label


def pick_row(csv_path: Path, row_index: int, label_filter: str | None) -> dict[str, str]:
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        current_index = 0
        for row in reader:
            if label_filter and label_filter.lower() not in str(row.get(" Label", row.get("Label", ""))).lower():
                continue
            if current_index == row_index:
                return row
            current_index += 1
    raise ValueError("No matching CSV row found for the provided filters.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Send a CICIDS row to the monitored-event endpoint.")
    parser.add_argument("--api", default="http://localhost:8000")
    parser.add_argument(
        "--csv",
        default=str(ROOT_DIR / "datasets" / "MachineLearningCVE" / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"),
    )
    parser.add_argument("--row-index", type=int, default=0)
    parser.add_argument("--label-contains", default="")
    parser.add_argument("--page-url", default="https://demo-target.local/login")
    parser.add_argument("--request-path", default="/login")
    parser.add_argument("--source-ip", default="203.0.113.44")
    parser.add_argument("--auto-prevent", action="store_true")
    args = parser.parse_args()

    csv_path = Path(args.csv).resolve()
    row = pick_row(csv_path, args.row_index, args.label_contains or None)
    raw_label = str(row.get(" Label", row.get("Label", "Unknown"))).strip()
    features = extract_hardened_ids_features(row)

    payload = {
        "attack_type": "AUTO",
        "page_url": args.page_url,
        "request_path": args.request_path,
        "http_method": "POST",
        "source_ip": args.source_ip,
        "source_type": "web-access",
        "telemetry_source": "sensor-web-nginx",
        "asset_name": "demo-webapp",
        "auto_prevent": args.auto_prevent,
        "features": {
            **features,
            "dataset_label": raw_label,
            "threat_hint": map_cicids_label(raw_label),
        },
    }

    response = requests.post(
        f"{args.api.rstrip('/')}/api/model/evaluate",
        json=payload,
        timeout=20,
    )
    response.raise_for_status()
    print(json.dumps(response.json(), indent=2))


if __name__ == "__main__":
    main()
