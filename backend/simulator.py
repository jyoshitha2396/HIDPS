import random
import time
import asyncio
from typing import List, Optional

ATTACK_TYPES = ["DoS", "Brute Force", "Web Attack", "Infiltration", "Port Scan", "Normal", "Zero-day (GAN-generated)", "Adversarial (FGSM/PGD)"]
EDGE_NODES = ["Node-Alpha", "Node-Beta", "Node-Gamma", "Node-Delta"]
COUNTRIES = [
    ("US", 37.0902, -95.7129),
    ("CN", 35.8617, 104.1954),
    ("RU", 61.5240, 105.3188),
    ("BR", -14.2350, -51.9253),
    ("IN", 20.5937, 78.9629),
    ("IR", 32.4279, 53.6880),
    ("KR", 35.9078, 127.7669),
    ("KP", 40.3399, 127.5101)
]

def generate_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

def generate_alert():
    is_attack = random.random() < 0.3 # 30% chance of attack vs normal traffic
    
    if is_attack:
        attack_type = random.choice(ATTACK_TYPES[0:5] + ATTACK_TYPES[6:])
        confidence = random.uniform(0.75, 0.99)
        if attack_type in ["Zero-day (GAN-generated)", "Adversarial (FGSM/PGD)"]:
            confidence = random.uniform(0.50, 0.85) # Lower confidence for complex attacks
            severity = "Critical"
        else:
            severity = random.choice(["Critical", "High", "Medium"])
    else:
        attack_type = "Normal"
        confidence = random.uniform(0.85, 0.99)
        severity = "Low"

    country, lat, lon = random.choice(COUNTRIES)
    lat += random.uniform(-2.0, 2.0)
    lon += random.uniform(-2.0, 2.0)

    # Destination is usually internal network (mocking it)
    dest_ip = f"10.0.{random.randint(1, 255)}.{random.randint(1, 255)}"
    dest_lat, dest_lon = (39.0438, -77.4874) # Ashburn, VA (AWS US-East-1)

    return {
        "id": f"alert-{int(time.time() * 1000)}-{random.randint(1000, 9999)}",
        "timestamp": time.time(),
        "source_ip": generate_ip(),
        "dest_ip": dest_ip,
        "source_geo": {"country": country, "lat": lat, "lon": lon},
        "dest_geo": {"country": "US", "lat": dest_lat, "lon": dest_lon},
        "attack_type": attack_type,
        "severity": severity,
        "confidence": confidence,
        "edge_node_id": random.choice(EDGE_NODES)
    }

def generate_shap_values(attack_type):
    features = ["Packet Rate", "Avg Packet Size", "Duration", "Num Connections", "Port Behavior", "Flags", "Payload Entropy"]
    shap_vals = [{"feature": f, "importance": random.uniform(-0.8, 1.0)} for f in features]
    shap_vals.sort(key=lambda x: abs(x["importance"]), reverse=True)
    return shap_vals

def generate_dashboard_stats():
    return {
        "total_alerts_24h": random.randint(15000, 50000),
        "critical_count": random.randint(100, 500),
        "high_count": random.randint(500, 2000),
        "medium_count": random.randint(2000, 5000),
        "low_count": random.randint(10000, 40000),
        "system_status": "Operational",
        "active_edge_nodes": 4,
        "cloud_sync": "Online"
    }
