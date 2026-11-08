"""Telegram alerting — the bot's integration, on stdlib urllib.

Config keys are read from the loaded config dict at call time. The bot
token is used only to build the API URL for the send; it is never logged,
returned, or written into any report. Without a configured token/chat,
sends return {"sent": False, "reason": "not configured"} — no network call.
Tests inject a fake opener, so nothing here needs the network to verify.
"""
from __future__ import annotations

import json
import urllib.request


def _post(url: str, payload: dict, opener=None) -> int:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    open_fn = opener or urllib.request.urlopen
    with open_fn(req, timeout=10) as resp:
        return int(getattr(resp, "status", 200))


def send_alert(cfg: dict, alert: dict, opener=None) -> dict:
    chat = str(cfg.get("telegram_chat_id") or "")
    tok = str(cfg.get("telegram_token") or "")
    if not tok or not chat:
        return {"sent": False, "reason": "not configured"}
    message = (
        "*Accurate Cyber Defense Alert*\n"
        f"Timestamp: {alert.get('timestamp')}\n"
        f"IP Address: {alert.get('ip')}\n"
        f"Threat Type: {alert.get('type')}\n"
        f"Description: {alert.get('description')}"
    )
    url = "https://api.telegram.org/bot" + tok + "/sendMessage"
    try:
        status = _post(url, {"chat_id": chat, "text": message, "parse_mode": "Markdown"},
                       opener=opener)
        return {"sent": status == 200, "status": status}
    except Exception as e:
        return {"sent": False, "reason": f"send failed: {type(e).__name__}"}


def test_alert(cfg: dict, opener=None) -> dict:
    return send_alert(cfg, {"timestamp": "test", "ip": "127.0.0.1",
                            "type": "Test Alert",
                            "description": "Test notification from Purple-Hat Network Analyzer"},
                      opener=opener)


def export_report(cfg: dict, alerts: list, opener=None) -> dict:
    if not alerts:
        return {"sent": False, "reason": "no threats to export"}
    lines = ["*Accurate Cyber Defense Threat Report*\n"]
    for a in alerts[-5:]:
        lines.append(f"Time: {a.get('timestamp')}  Type: {a.get('type')}  "
                     f"IP: {a.get('ip')}  Details: {a.get('description')}")
    chat = str(cfg.get("telegram_chat_id") or "")
    tok = str(cfg.get("telegram_token") or "")
    if not tok or not chat:
        return {"sent": False, "reason": "not configured"}
    url = "https://api.telegram.org/bot" + tok + "/sendMessage"
    try:
        status = _post(url, {"chat_id": chat, "text": "\n".join(lines),
                             "parse_mode": "Markdown"}, opener=opener)
        return {"sent": status == 200, "status": status}
    except Exception as e:
        return {"sent": False, "reason": f"send failed: {type(e).__name__}"}
