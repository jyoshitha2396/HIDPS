from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any, Dict, Mapping

HARDENED_IDS_FEATURE_ORDER = [
    "destination_port",
    "flow_duration",
    "total_fwd_packets",
    "total_backward_packets",
    "total_length_fwd_packets",
    "total_length_bwd_packets",
    "fwd_packet_length_max",
    "bwd_packet_length_mean",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "packet_length_mean",
    "avg_packet_size",
    "subflow_fwd_packets",
]

HARDENED_IDS_LABELS = ["Normal", "Intrusion"]

RAW_TO_CANONICAL_FEATURES = {
    "destination_port": "destination_port",
    "flow_duration": "flow_duration",
    "total_fwd_packets": "total_fwd_packets",
    "total_backward_packets": "total_backward_packets",
    "total_length_of_fwd_packets": "total_length_fwd_packets",
    "total_length_of_bwd_packets": "total_length_bwd_packets",
    "fwd_packet_length_max": "fwd_packet_length_max",
    "bwd_packet_length_mean": "bwd_packet_length_mean",
    "flow_bytes_s": "flow_bytes_per_s",
    "flow_packets_s": "flow_packets_per_s",
    "packet_length_mean": "packet_length_mean",
    "average_packet_size": "avg_packet_size",
    "avg_packet_size": "avg_packet_size",
    "subflow_fwd_packets": "subflow_fwd_packets",
}

BENIGN_LABELS = {"normal", "benign", "legitimate", "safe", "clean"}
ATTACK_LABEL_ALIASES = {
    "dos": "DoS",
    "ddos": "DoS",
    "brute_force": "Brute Force",
    "bruteforce": "Brute Force",
    "ftp_patator": "Brute Force",
    "ssh_patator": "Brute Force",
    "web_attack": "Web Attack",
    "sql_injection": "Web Attack",
    "xss": "Web Attack",
    "cross_site_scripting": "Web Attack",
    "infiltration": "Infiltration",
    "bot": "Infiltration",
    "heartbleed": "Infiltration",
    "port_scan": "Port Scan",
    "portscan": "Port Scan",
    "intrusion": "Intrusion",
    "attack": "Intrusion",
    "malicious": "Intrusion",
    "anomaly": "Intrusion",
    "anomalous": "Intrusion",
    "threat": "Intrusion",
}


def canonicalize_feature_name(name: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "_", str(name).strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return RAW_TO_CANONICAL_FEATURES.get(cleaned, cleaned)


def default_hardened_ids_model_path() -> Path:
    return Path(__file__).resolve().parent / "models" / "hardened_ids_vfinal.onnx"


def parse_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
            return default
        return float(value)

    text = str(value).strip()
    if not text:
        return default
    lowered = text.lower()
    if lowered in {"nan", "inf", "-inf", "infinity", "-infinity"}:
        return default
    try:
        return float(text)
    except ValueError:
        return default


def normalize_feature_map(features: Mapping[str, Any]) -> Dict[str, Any]:
    normalized: Dict[str, Any] = {}
    for key, value in features.items():
        normalized[canonicalize_feature_name(str(key))] = value
    return normalized


def extract_hardened_ids_features(features: Mapping[str, Any]) -> Dict[str, float]:
    normalized = normalize_feature_map(features)
    return {name: parse_float(normalized.get(name, 0.0)) for name in HARDENED_IDS_FEATURE_ORDER}


def infer_attack_type_from_features(label: str, features: Mapping[str, Any]) -> str:
    normalized = normalize_feature_map(features)
    attack_hint = ATTACK_LABEL_ALIASES.get(canonicalize_feature_name(label), "")
    if attack_hint and attack_hint != "Intrusion":
        return attack_hint

    request_path = str(normalized.get("request_path", "") or "").lower()
    page_url = str(normalized.get("page_url", "") or "").lower()
    source_type = str(normalized.get("source_type", "") or "").lower()
    failed_logins = parse_float(normalized.get("failed_logins"))
    packet_rate = parse_float(normalized.get("packet_rate"), parse_float(normalized.get("flow_packets_per_s")))
    payload_kb = parse_float(normalized.get("payload_kb"))
    destination_port = parse_float(normalized.get("destination_port"))
    backward_packets = parse_float(normalized.get("total_backward_packets"))

    suspicious_path_tokens = ["../", "<script", " union ", "select ", "drop table", "cmd=", "wp-admin"]
    if any(token in request_path or token in page_url for token in suspicious_path_tokens):
        return "Web Attack"
    if failed_logins >= 5 or "login" in request_path or "signin" in request_path:
        return "Brute Force"
    if packet_rate >= 3000:
        return "DoS"
    if destination_port in {21.0, 22.0, 23.0, 25.0, 53.0, 80.0, 443.0, 3389.0} and backward_packets <= 1:
        return "Port Scan"
    if source_type == "web-access":
        return "Web Attack"
    if payload_kb >= 24:
        return "Infiltration"
    return "Infiltration"


def resolve_attack_type_from_model_label(label: str, features: Mapping[str, Any]) -> str:
    normalized_label = canonicalize_feature_name(label)
    if normalized_label in BENIGN_LABELS:
        return "Normal"
    mapped = ATTACK_LABEL_ALIASES.get(normalized_label)
    if mapped and mapped != "Intrusion":
        return mapped
    return infer_attack_type_from_features(label, features)


def map_cicids_label(label: str) -> str:
    normalized = canonicalize_feature_name(label)
    if normalized in {"benign", "normal"}:
        return "Normal"
    mapped = ATTACK_LABEL_ALIASES.get(normalized)
    if mapped and mapped != "Intrusion":
        return mapped
    if "web_attack" in normalized or "sql" in normalized or "xss" in normalized:
        return "Web Attack"
    if "patator" in normalized or "brute" in normalized:
        return "Brute Force"
    if "dos" in normalized:
        return "DoS"
    if "portscan" in normalized:
        return "Port Scan"
    if "infiltration" in normalized or "bot" in normalized or "heartbleed" in normalized:
        return "Infiltration"
    return "Intrusion"
