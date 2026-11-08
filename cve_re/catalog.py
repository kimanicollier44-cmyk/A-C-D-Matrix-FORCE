"""CVE catalog -- data only, never exploit code.

Static, synthetic, DEFENSIVE reverse-engineering lab. Each record is a
dict describing a publicly disclosed unauthenticated RCE, pre-auth
memory-disclosure, or auth-bypass-chain vulnerability in a web-facing
product. There are no payloads, no probes and no network calls here.

Remediation nuance encoded in the data: for the CitrixBleed family and
for SharePoint ToolShell, patching alone is NOT closure -- leaked
session tokens (and, for ToolShell, ASP.NET MachineKeys) stay valid
until they are rotated. Those records carry
``requires_session_rotation`` / ``requires_key_rotation``.
"""
from __future__ import annotations

PATCH = "patch"
PATCH_ROTATE_SESSIONS = "patch+rotate_sessions"
PATCH_ROTATE_KEYS = "patch+rotate_keys"
PATCH_ROTATE_BOTH = "patch+rotate_sessions+rotate_keys"


def _r(cve_id, name, vendor, product, vuln_type, cvss, kev, year,
       vuln_class, remediation, sess=False, keys=False):
    return {
        "cve_id": cve_id, "name": name, "vendor": vendor,
        "product": product, "vuln_type": vuln_type, "cvss": cvss,
        "kev": bool(kev), "exploited": bool(kev),
        "unauthenticated": True, "year": year,
        "vuln_class": vuln_class, "remediation": remediation,
        "requires_session_rotation": bool(sess),
        "requires_key_rotation": bool(keys),
    }


CATALOG = [
    # --- Citrix NetScaler ADC / Gateway --------------------------------
    _r("CVE-2026-88771", "", "Citrix", "NetScaler ADC/Gateway", "rce", 9.5, True, 2026, "CWE-20 improper input validation", PATCH),
    _r("CVE-2026-88772", "", "Citrix", "NetScaler ADC/Gateway", "rce", 9.5, True, 2026, "CWE-119 memory overflow (DTLS)", PATCH),
    _r("CVE-2026-88779", "", "Citrix", "NetScaler ADC/Gateway", "auth_bypass_chain", None, True, 2026, "CWE-119 SAML memory overflow", PATCH_ROTATE_SESSIONS, sess=True),
    _r("CVE-2026-107406", "", "Citrix", "NetScaler ADC/Gateway", "rce", 9.5, True, 2026, "CWE-119 SAML memory overflow", PATCH),
    _r("CVE-2025-7775", "", "Citrix", "NetScaler ADC/Gateway", "rce", None, True, 2025, "CWE-119 memory overflow", PATCH),
    _r("CVE-2025-5777", "CitrixBleed 2", "Citrix", "NetScaler ADC/Gateway", "memory_disclosure", 9.3, True, 2025, "CWE-125 out-of-bounds read", PATCH_ROTATE_SESSIONS, sess=True),
    _r("CVE-2023-4966", "CitrixBleed", "Citrix", "NetScaler ADC/Gateway", "memory_disclosure", 7.5, True, 2023, "CWE-119 buffer over-read", PATCH_ROTATE_SESSIONS, sess=True),
    _r("CVE-2026-3055", "", "Citrix", "NetScaler ADC/Gateway", "memory_disclosure", 9.3, True, 2026, "CWE-125 out-of-bounds read (SAML IdP)", PATCH_ROTATE_SESSIONS, sess=True),
    _r("CVE-2023-3519", "", "Citrix", "NetScaler ADC/Gateway", "rce", 9.8, True, 2023, "CWE-94 code injection", PATCH),
    _r("CVE-2019-19781", "Shitrix", "Citrix", "NetScaler ADC/Gateway", "rce", 9.8, True, 2019, "CWE-22 path traversal to RCE", PATCH),
    # --- Ivanti ---------------------------------------------------------
    _r("CVE-2026-104935", "", "Ivanti", "Connect Secure", "auth_bypass_chain", None, True, 2026, "CWE-287 improper authentication", PATCH_ROTATE_SESSIONS, sess=True),
    _r("CVE-2025-0282", "", "Ivanti", "Connect Secure", "rce", 9.0, True, 2025, "CWE-121 stack-based buffer overflow", PATCH),
    _r("CVE-2025-22457", "", "Ivanti", "Connect Secure", "rce", 9.0, True, 2025, "CWE-121 stack-based buffer overflow", PATCH),
    _r("CVE-2023-46805", "", "Ivanti", "Connect Secure", "auth_bypass_chain", None, True, 2023, "CWE-287 authentication bypass (chain)", PATCH_ROTATE_SESSIONS, sess=True),
    # --- Cisco ----------------------------------------------------------
    _r("CVE-2025-20333", "", "Cisco", "Secure Firewall ASA/FTD", "rce", 9.9, True, 2025, "CWE-120 buffer overflow (VPN web server)", PATCH),
    _r("CVE-2025-20362", "", "Cisco", "Secure Firewall ASA/FTD", "auth_bypass_chain", None, True, 2025, "CWE-862 missing authorization", PATCH),
    _r("CVE-2026-76504", "", "Cisco", "SD-WAN Manager", "rce", None, True, 2026, "CWE-78 OS command injection", PATCH),
    _r("CVE-2026-76519", "", "Cisco", "Secure Email Gateway", "rce", None, True, 2026, "CWE-22 path traversal to root commands", PATCH),
    _r("CVE-2023-20198", "", "Cisco", "IOS XE Web UI", "auth_bypass_chain", 10.0, True, 2023, "CWE-284 improper access control", PATCH_ROTATE_SESSIONS, sess=True),
    # --- Fortinet -------------------------------------------------------
    _r("CVE-2026-104286", "", "Fortinet", "FortiMail", "rce", 9.8, True, 2026, "CWE-22 path traversal / arbitrary file write", PATCH),
    _r("CVE-2025-64446", "", "Fortinet", "FortiWeb", "rce", None, True, 2025, "CWE-23 relative path traversal to RCE", PATCH),
    _r("CVE-2025-25257", "", "Fortinet", "FortiWeb", "rce", 9.8, True, 2025, "CWE-89 SQL injection to RCE", PATCH),
    _r("CVE-2024-21762", "", "Fortinet", "FortiOS/FortiProxy sslvpnd", "rce", 9.8, True, 2024, "CWE-787 out-of-bounds write", PATCH),
    _r("CVE-2022-42475", "", "Fortinet", "FortiOS sslvpnd", "rce", 9.8, True, 2022, "CWE-122 heap-based buffer overflow", PATCH),
    _r("CVE-2024-47575", "FortiJump", "Fortinet", "FortiManager", "auth_bypass_chain", 9.8, True, 2024, "CWE-862 missing authentication", PATCH),
    _r("CVE-2018-13379", "", "Fortinet", "FortiOS SSL-VPN", "memory_disclosure", None, True, 2018, "CWE-22 path traversal / file disclosure", PATCH_ROTATE_SESSIONS, sess=True),
    # --- F5 -------------------------------------------------------------
    _r("CVE-2025-53521", "", "F5", "BIG-IP APM", "rce", 9.8, True, 2025, "CWE-770 resource allocation (reclassified RCE)", PATCH),
    _r("CVE-2026-94127", "", "F5", "BIG-IP APM", "rce", None, True, 2026, "CWE-122 heap overflow (OAuth)", PATCH),
    _r("CVE-2020-5902", "", "F5", "BIG-IP TMUI", "rce", 9.8, True, 2020, "CWE-918/22 TMUI RCE", PATCH),
    _r("CVE-2022-1388", "", "F5", "BIG-IP iControl REST", "auth_bypass_chain", 9.8, True, 2022, "CWE-862 missing authentication to RCE", PATCH),
    # --- Palo Alto ------------------------------------------------------
    _r("CVE-2024-3400", "", "Palo Alto Networks", "PAN-OS GlobalProtect", "rce", 10.0, True, 2024, "CWE-78 OS command injection", PATCH),
    # --- BeyondTrust ----------------------------------------------------
    _r("CVE-2026-1731", "", "BeyondTrust", "Privileged Remote Access", "rce", None, True, 2026, "CWE-78 OS command injection", PATCH),
    _r("CVE-2026-102764", "", "BeyondTrust", "Remote Support", "auth_bypass_chain", None, True, 2026, "CWE-290 authentication bypass by spoofing", PATCH),
    # --- Enterprise web -------------------------------------------------
    _r("CVE-2025-55182", "React2Shell", "React", "React Server Components / Next.js", "rce", 10.0, True, 2025, "CWE-502 deserialization of untrusted data", PATCH),
    _r("CVE-2026-109618", "PHP2Shell", "PHP", "PHP interpreter", "rce", 9.2, True, 2026, "CWE-416 use-after-free", PATCH),
    _r("CVE-2026-109619", "PHP2Shell", "PHP", "PHP interpreter", "rce", 9.2, True, 2026, "CWE-416 use-after-free (stale global state)", PATCH),
    _r("CVE-2025-53770", "ToolShell", "Microsoft", "SharePoint Server (on-prem)", "rce", 9.8, True, 2025, "CWE-502 deserialization of untrusted data", PATCH_ROTATE_BOTH, sess=True, keys=True),
    _r("CVE-2025-53771", "ToolShell", "Microsoft", "SharePoint Server (on-prem)", "auth_bypass_chain", None, True, 2025, "CWE-287 authentication bypass (header spoofing)", PATCH_ROTATE_BOTH, sess=True, keys=True),
    _r("CVE-2025-61882", "", "Oracle", "E-Business Suite", "rce", 9.8, True, 2025, "CWE-918/611 XSLT injection to RCE", PATCH),
    _r("CVE-2025-61884", "", "Oracle", "E-Business Suite", "memory_disclosure", None, True, 2025, "CWE-200 information disclosure", PATCH_ROTATE_SESSIONS, sess=True),
    _r("CVE-2025-31324", "", "SAP", "NetWeaver", "rce", 10.0, True, 2025, "CWE-862 missing authentication / file upload", PATCH),
    _r("CVE-2025-10035", "", "Fortra", "GoAnywhere MFT", "rce", 10.0, True, 2025, "CWE-502 deserialization of untrusted data", PATCH),
    # --- Historic -------------------------------------------------------
    _r("CVE-2021-44228", "Log4Shell", "Apache", "Log4j 2", "rce", 10.0, True, 2021, "CWE-502 deserialization / JNDI injection", PATCH),
    _r("CVE-2014-0160", "Heartbleed", "OpenSSL", "OpenSSL", "memory_disclosure", 7.5, True, 2014, "CWE-125 out-of-bounds read (heartbeat)", PATCH_ROTATE_BOTH, sess=True, keys=True),
]

_BY_ID = {r["cve_id"]: r for r in CATALOG}


def get_record(cve_id):
    return _BY_ID.get(cve_id)


def all_ids():
    return [r["cve_id"] for r in CATALOG]
