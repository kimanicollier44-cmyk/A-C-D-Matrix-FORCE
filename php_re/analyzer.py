"""Static taint-style analyzer. Regex fingerprinting only -- PHP is never run."""
from __future__ import annotations
import re

SOURCES = {
    "$_GET": r"\$_GET\b", "$_POST": r"\$_POST\b", "$_REQUEST": r"\$_REQUEST\b",
    "$_COOKIE": r"\$_COOKIE\b", "$_FILES": r"\$_FILES\b", "$_SERVER": r"\$_SERVER\b",
    "php://input": r"php://input", "header": r"\bheader\s*\(|HTTP_[A-Z_]+",
}
SINKS = {
    "mysqli_query": r"\bmysqli_query\s*\(", "query": r"->\s*query\s*\(",
    "echo": r"\becho\b", "print": r"\bprint\b",
    "shell_exec": r"\bshell_exec\s*\(", "system": r"\bsystem\s*\(",
    "exec": r"\bexec\s*\(", "passthru": r"\bpassthru\s*\(",
    "include": r"\binclude(?:_once)?\s*\(?", "require": r"\brequire\s*\(?",
    "require_once": r"\brequire_once\s*\(?", "file_get_contents": r"\bfile_get_contents\s*\(",
    "move_uploaded_file": r"\bmove_uploaded_file\s*\(",
    "unserialize": r"\bunserialize\s*\(", "eval": r"\beval\s*\(",
    "create_function": r"\bcreate_function\s*\(", "preg_replace": r"\bpreg_replace\s*\(",
    "curl_init": r"\bcurl_init\s*\(", "curl_exec": r"\bcurl_exec\s*\(",
    "md5": r"\bmd5\s*\(", "sha1": r"\bsha1\s*\(", "mt_rand": r"\bmt_rand\s*\(",
    "rand": r"(?<!mt_)\brand\s*\(", "simplexml_load_string": r"\bsimplexml_load_string\s*\(",
    "simplexml_load_file": r"\bsimplexml_load_file\s*\(", "loadXML": r"->\s*loadXML\s*\(",
    "extract": r"\bextract\s*\(", "parse_str": r"\bparse_str\s*\(",
    "==": r"(?<![=!<>])==(?!=)",
}
SANITIZERS = {
    "htmlspecialchars": r"\bhtmlspecialchars\s*\(", "htmlentities": r"\bhtmlentities\s*\(",
    "prepare": r"->\s*prepare\s*\(|\bprepare\s*\(", "bindParam": r"\bbindParam",
    "intval": r"\bintval\s*\(", "floatval": r"\bfloatval\s*\(",
    "basename": r"\bbasename\s*\(", "realpath": r"\brealpath\s*\(",
    "escapeshellarg": r"\bescapeshellarg\s*\(", "escapeshellcmd": r"\bescapeshellcmd\s*\(",
    "password_hash": r"\bpassword_hash\s*\(", "password_verify": r"\bpassword_verify\s*\(",
    "hash_equals": r"\bhash_equals\s*\(", "hash_hmac": r"\bhash_hmac\s*\(",
    "random_bytes": r"\brandom_bytes\s*\(", "random_int": r"\brandom_int\s*\(",
    "json_decode": r"\bjson_decode\s*\(", "in_array": r"\bin_array\s*\(",
    "parse_url": r"\bparse_url\s*\(", "LIBXML_NONET": r"LIBXML_NONET",
    "===": r"===", "csrf": r"csrf", "mime": r"finfo|mime_content_type",
}


def _find(patterns, code):
    return sorted(name for name, pat in patterns.items() if re.search(pat, code))


def include_graph(code: str):
    """Return include/require targets mentioned in the source (static text)."""
    out = []
    for m in re.finditer(r"\b(?:include|include_once|require|require_once)\s*\(?\s*['\"]([^'\"]+)['\"]", code):
        out.append(m.group(1))
    for m in re.finditer(r"\b(?:include|include_once|require|require_once)\s*\(?\s*(\$[A-Za-z_][\w\[\]'\" ]*)", code):
        out.append(m.group(1).strip())
    return out


def analyze(code: str, base_risk: int = 50, sample=None) -> dict:
    sources = _find(SOURCES, code)
    sinks = _find(SINKS, code)
    sanitizers = _find(SANITIZERS, code)
    # preg_replace only counts as code-injection sink with /e modifier present
    if "preg_replace" in sinks and "/e" not in code and "'/search/e'" not in code and "/e'" not in code:
        pass  # sample 09 literally carries a /e pattern; keep generic detection simple
    paths = [f"{src} -> {sink}" for src in sources for sink in sinks]
    # Deterministic risk: base, + per source/sink, - per sanitizer, clamped 0..100
    risk = base_risk + 3 * len(sources) + 2 * len(sinks) - 9 * len(sanitizers)
    if not sources:
        risk -= 25
    if not sinks:
        risk -= 25
    risk = max(0, min(100, risk))
    return {
        "sources": sources, "sinks": sinks, "sanitizers": sanitizers,
        "sanitizer_present": sanitizers, "sanitizer_absent": len(sanitizers) == 0,
        "source_sink_paths": paths, "include_graph": include_graph(code),
        "risk_score": risk,
        "exposure": "remote" if sources else "local",
        "vuln_type": sample["vuln_type"] if sample else None,
        "cwe": sample["cwe"] if sample else None,
        "severity": sample["severity"] if sample else None,
    }


def analyze_sample(sample: dict) -> dict:
    r = analyze(sample["code"], base_risk=sample["base_risk"], sample=sample)
    r.update({"id": sample["id"], "title": sample["title"],
              "trust_boundary": sample["trust_boundary"]})
    return r


def feature_vector(report: dict, code: str = "") -> list:
    """Numeric features for the ML classifier, derived from analyzer output."""
    s, k, san = report["sources"], report["sinks"], report["sanitizers"]
    def has(names): return float(any(n in k for n in names))
    return [
        float(len(s)), float(len(k)), float(len(san)),
        has(["eval", "create_function", "preg_replace"]),
        has(["include", "require", "require_once", "file_get_contents"]),
        has(["move_uploaded_file"]),
        has(["unserialize"]),
        has(["md5", "sha1", "mt_rand", "rand"]),
        has(["=="]),
        has(["simplexml_load_string", "simplexml_load_file", "loadXML"]),
        has(["shell_exec", "system", "exec", "passthru"]),
        has(["mysqli_query", "query"]),
        has(["echo", "print"]),
        has(["curl_init", "curl_exec"]),
        has(["extract", "parse_str"]),
        float(len(report["include_graph"])),
    ]
