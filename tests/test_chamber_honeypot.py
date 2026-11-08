import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from php_re.honeypot import LOG_ENTRIES, classify_attempt, honeypot_summary
from php_re.samples import get_sample
from php_re.sandbox import SANITIZED_SNIPPET, sandbox_demo, triage

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_sandbox_reports_never_execute():
    r = triage(get_sample("sqli-01"))
    assert r["executed"] is False and r["network"] == 0 and r["network_access"] is False
    assert r["fs_diff"]["record_only"] is True and r["mode"] == "static-triage"


def test_sandbox_verdicts():
    assert triage(SANITIZED_SNIPPET)["verdict"] == "ALLOW_TO_LAB_TEST"
    for sid in ("code-injection-09", "object-injection-08", "rfi-06", "lfi-05"):
        r = triage(get_sample(sid))
        assert r["verdict"] == "HOLD_IN_SANDBOX" and r["markers"], sid


def test_sandbox_demo_counts():
    d = sandbox_demo()
    assert d["any_executed"] is False and d["allowed"] + d["held"] == d["total"]
    assert d["total"] == 15 and d["held"] == 4 and d["allowed"] == 11


def test_honeypot_classification():
    assert classify_attempt({"path": "/p", "query": "id=1 UNION SELECT a FROM b"}) == "sqli_probe"
    assert classify_attempt({"path": "/i", "query": "f=../../../etc/passwd"}) == "lfi_probe"
    assert classify_attempt({"path": "/.env", "query": ""}) == "env_harvest"
    assert classify_attempt({"path": "/upload.php", "query": "", "filename": "x.php"}) == "upload_attempt"
    assert classify_attempt({"path": "/phpmyadmin/", "query": ""}) == "scanner"


def test_honeypot_summary_no_listener():
    s = honeypot_summary()
    assert s["listener_open"] is False and s["access_granted"] is False
    assert s["attempts"] == len(LOG_ENTRIES) == 12 and s["top_threat_score"] >= 90
    assert s["bursts"] and all(not b["access_granted"] for b in s["bait_sessions"])
    assert set(s["by_class"]) == {"sqli_probe", "lfi_probe", "env_harvest", "upload_attempt", "scanner"}


def test_honeypot_module_has_no_listener_code():
    src = open(os.path.join(ROOT, "php_re", "honeypot.py")).read()
    assert "import socket" not in src and "socket" not in src and "listen(" not in src
