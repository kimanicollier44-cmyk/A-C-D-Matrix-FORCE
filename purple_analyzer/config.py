"""Config — compatible with the Purple Hat Bot's config file.

Upstream file: accuratecyberbot_config.json with keys
  telegram_token, telegram_chat_id, monitored_ips,
  thresholds {port_scan, dos_attack, http_flood}, alert_cooldown
The bot's README also showed {telegram_token, user_id}; user_id is accepted
as an alias for telegram_chat_id on load and normalised on save.
No secret value is ever printed or included in reports.
"""
from __future__ import annotations

import json
import os

CONFIG_FILE = "accuratecyberbot_config.json"
DEFAULT_CONFIG = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "monitored_ips": [],
    "thresholds": {"port_scan": 10, "dos_attack": 100, "http_flood": 50},
    "alert_cooldown": 300,
}


def load_config(path: str = CONFIG_FILE) -> dict:
    if os.path.exists(path):
        try:
            with open(path) as f:
                cfg = json.load(f)
        except Exception:
            return json.loads(json.dumps(DEFAULT_CONFIG))
        merged = json.loads(json.dumps(DEFAULT_CONFIG))
        merged.update({k: v for k, v in cfg.items() if k != "user_id"})
        if not merged.get("telegram_chat_id") and cfg.get("user_id"):
            merged["telegram_chat_id"] = str(cfg["user_id"])
        if isinstance(cfg.get("thresholds"), dict):
            merged["thresholds"].update(cfg["thresholds"])
        return merged
    return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(cfg: dict, path: str = CONFIG_FILE) -> bool:
    try:
        with open(path, "w") as f:
            json.dump(cfg, f, indent=4)
        return True
    except Exception:
        return False


def validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
