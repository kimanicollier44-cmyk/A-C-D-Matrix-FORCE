"""Synthetic PHP samples -- DATA ONLY. Never executed, never fetched.

Each sample is a vulnerable PHP source string written for static study,
plus what the analyzer must find and a publisher-side hardening fix.
"""
from __future__ import annotations

SAMPLES = [
    {
        "id": "sqli-01", "title": "SQL injection via string concatenation",
        "vuln_type": "sql_injection", "family": "sqli", "cwe": "CWE-89",
        "severity": "critical", "base_risk": 92,
        "trust_boundary": "anonymous web user -> database query",
        "code": """<?php
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
$result = mysqli_query($conn, $sql);
echo $result;
""",
        "expected_sources": ["$_GET"], "expected_sinks": ["mysqli_query"],
        "expected_sanitizers_absent": ["prepare", "intval"],
        "hardening": "Use PDO prepared statements: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([intval($_GET['id'])]); Never concatenate input into SQL.",
    },
    {
        "id": "xss-reflected-02", "title": "Reflected XSS via echo of query param",
        "vuln_type": "reflected_xss", "family": "xss", "cwe": "CWE-79",
        "severity": "high", "base_risk": 78,
        "trust_boundary": "attacker-supplied URL -> victim browser HTML",
        "code": """<?php
$q = $_GET['q'];
echo "<p>Results for: " . $q . "</p>";
print $q;
""",
        "expected_sources": ["$_GET"], "expected_sinks": ["echo", "print"],
        "expected_sanitizers_absent": ["htmlspecialchars"],
        "hardening": "Encode on output: echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8'); Set a Content-Security-Policy header and validate input against an allowlist.",
    },
    {
        "id": "xss-stored-03", "title": "Stored XSS via comment saved then printed raw",
        "vuln_type": "stored_xss", "family": "xss", "cwe": "CWE-79",
        "severity": "high", "base_risk": 85,
        "trust_boundary": "attacker account -> database -> every visitor browser",
        "code": """<?php
$comment = $_POST['comment'];
mysqli_query($conn, "INSERT INTO comments(body) VALUES('$comment')");
$row = mysqli_fetch_assoc($res);
echo $row['body'];
""",
        "expected_sources": ["$_POST"], "expected_sinks": ["mysqli_query", "echo"],
        "expected_sanitizers_absent": ["htmlspecialchars", "prepare"],
        "hardening": "Store raw, encode on every output with htmlspecialchars(..., ENT_QUOTES, 'UTF-8'); insert with a prepared statement; add CSP as defence in depth.",
    },
    {
        "id": "cmdi-04", "title": "OS command injection via shell_exec",
        "vuln_type": "command_injection", "family": "command_injection", "cwe": "CWE-78",
        "severity": "critical", "base_risk": 95,
        "trust_boundary": "anonymous web user -> operating system shell",
        "code": """<?php
$host = $_REQUEST['host'];
$output = shell_exec("ping -c1 " . $host);
system("nslookup " . $host);
echo $output;
""",
        "expected_sources": ["$_REQUEST"], "expected_sinks": ["shell_exec", "system"],
        "expected_sanitizers_absent": ["escapeshellarg"],
        "hardening": "Avoid the shell entirely (use a native library). If unavoidable: validate against an allowlist and wrap each argument with escapeshellarg(). Run with least privilege.",
    },
    {
        "id": "lfi-05", "title": "Local file inclusion / path traversal",
        "vuln_type": "path_traversal_lfi", "family": "file_inclusion", "cwe": "CWE-22",
        "severity": "high", "base_risk": 88,
        "trust_boundary": "web user -> server filesystem outside web root",
        "code": """<?php
$page = $_GET['page'];
include($page . ".php");
$data = file_get_contents($page);
""",
        "expected_sources": ["$_GET"], "expected_sinks": ["include", "file_get_contents"],
        "expected_sanitizers_absent": ["basename", "realpath"],
        "hardening": "Never include user-named files. Map a short allowlist key to a fixed path, or use basename() + realpath() and verify the result stays inside the intended directory. (CWE-22; include abuse is also CWE-98.)",
    },
    {
        "id": "rfi-06", "title": "Remote file inclusion",
        "vuln_type": "remote_file_inclusion", "family": "file_inclusion", "cwe": "CWE-98",
        "severity": "critical", "base_risk": 93,
        "trust_boundary": "attacker-controlled remote server -> PHP interpreter",
        "code": """<?php
$module = $_GET['module'];
include($module);
require_once $_COOKIE['theme'];
""",
        "expected_sources": ["$_GET", "$_COOKIE"], "expected_sinks": ["include", "require_once"],
        "expected_sanitizers_absent": ["in_array"],
        "hardening": "Set allow_url_include=Off, use a fixed allowlist map of module names to local paths, and never pass a URL or user value to include/require.",
    },
    {
        "id": "upload-07", "title": "Arbitrary file upload without type check",
        "vuln_type": "arbitrary_file_upload", "family": "file_inclusion", "cwe": "CWE-434",
        "severity": "critical", "base_risk": 90,
        "trust_boundary": "web user -> executable web directory",
        "code": """<?php
$name = $_FILES['f']['name'];
move_uploaded_file($_FILES['f']['tmp_name'], "uploads/" . $name);
echo "uploaded";
""",
        "expected_sources": ["$_FILES"], "expected_sinks": ["move_uploaded_file"],
        "expected_sanitizers_absent": ["mime", "random_bytes"],
        "hardening": "Verify MIME with finfo, allowlist extensions, rename to a random_bytes() name, store outside the web root (or a no-exec directory), and enforce size limits.",
    },
    {
        "id": "object-injection-08", "title": "PHP object injection via unserialize",
        "vuln_type": "object_injection", "family": "object_injection", "cwe": "CWE-502",
        "severity": "critical", "base_risk": 91,
        "trust_boundary": "attacker cookie -> object graph / __wakeup/__destruct",
        "code": """<?php
$data = $_COOKIE['prefs'];
$obj = unserialize($data);
echo $obj->name;
""",
        "expected_sources": ["$_COOKIE"], "expected_sinks": ["unserialize"],
        "expected_sanitizers_absent": ["hash_hmac", "json_decode"],
        "hardening": "Never unserialize() user input. Use json_decode() for data, or sign the payload with hash_hmac() and verify with hash_equals() first; if unserialize is unavoidable pass allowed_classes.",
    },
    {
        "id": "code-injection-09", "title": "Code injection: eval / preg_replace /e",
        "vuln_type": "code_injection", "family": "code_injection", "cwe": "CWE-94",
        "severity": "critical", "base_risk": 96,
        "trust_boundary": "web user -> PHP interpreter itself",
        "code": """<?php
$expr = $_POST['expr'];
eval($expr);
$out = preg_replace('/search/e', $expr, $_POST['text']);
$fn = create_function('$x', $expr);
""",
        "expected_sources": ["$_POST"], "expected_sinks": ["eval", "preg_replace", "create_function"],
        "expected_sanitizers_absent": [],
        "hardening": "Remove eval/create_function and the preg_replace /e modifier (removed in PHP 7; use preg_replace_callback). Parse expressions with a real, allowlisted parser -- never the interpreter.",
    },
    {
        "id": "ssrf-10", "title": "Server-side request forgery",
        "vuln_type": "ssrf", "family": "ssrf", "cwe": "CWE-918",
        "severity": "high", "base_risk": 84,
        "trust_boundary": "web user -> server's internal network / cloud metadata",
        "code": """<?php
$url = $_GET['url'];
$body = file_get_contents($url);
$ch = curl_init($url); curl_exec($ch);
echo $body;
""",
        "expected_sources": ["$_GET"], "expected_sinks": ["file_get_contents", "curl_exec", "curl_init"],
        "expected_sanitizers_absent": ["in_array", "parse_url"],
        "hardening": "Allowlist hosts with parse_url(), block private/reserved IPs after DNS resolution, disable redirects to internal targets, and set short timeouts. Never fetch a raw user URL server-side.",
    },
    {
        "id": "type-juggling-11", "title": "Type juggling loose == auth bypass",
        "vuln_type": "type_juggling_auth_bypass", "family": "auth_logic", "cwe": "CWE-697",
        "severity": "high", "base_risk": 82,
        "trust_boundary": "attacker JSON/form types -> authentication decision",
        "code": """<?php
$in = json_decode(file_get_contents('php://input'), true);
if ($in['token'] == $expected_token) { echo "admin"; }
if ($_POST['pin'] == 0) { echo "ok"; }
""",
        "expected_sources": ["php://input", "$_POST"], "expected_sinks": ["=="],
        "expected_sanitizers_absent": ["hash_equals", "==="],
        "hardening": "Use strict === comparison and hash_equals() for secrets, cast/validate types explicitly, and reject non-string token types before comparing.",
    },
    {
        "id": "weak-crypto-12", "title": "Weak crypto + weak randomness",
        "vuln_type": "weak_crypto_randomness", "family": "crypto", "cwe": "CWE-327",
        "severity": "high", "base_risk": 80,
        "trust_boundary": "passwords / reset tokens -> attacker offline guessing",
        "code": """<?php
$hash = md5($_POST['password']);
$weak = sha1($_POST['password']);
$token = mt_rand(1000, 9999);
$code = rand();
setcookie('reset', $token);
""",
        "expected_sources": ["$_POST"], "expected_sinks": ["md5", "sha1", "mt_rand", "rand"],
        "expected_sanitizers_absent": ["password_hash", "random_bytes"],
        "hardening": "Hash passwords with password_hash() (Argon2id/bcrypt), verify with password_verify(); generate tokens with random_bytes()/random_int(). md5/sha1/mt_rand are not for secrets. (Weak crypto CWE-327; weak randomness CWE-338.)",
    },
    {
        "id": "xxe-13", "title": "XML external entity via simplexml",
        "vuln_type": "xxe", "family": "xxe", "cwe": "CWE-611",
        "severity": "high", "base_risk": 83,
        "trust_boundary": "attacker XML document -> server filesystem / SSRF",
        "code": """<?php
$xml = file_get_contents('php://input');
$data = simplexml_load_string($xml);
$doc = new DOMDocument(); $doc->loadXML($xml);
echo $data->name;
""",
        "expected_sources": ["php://input"], "expected_sinks": ["simplexml_load_string", "loadXML"],
        "expected_sanitizers_absent": ["LIBXML_NONET"],
        "hardening": "Parse with LIBXML_NONET and no entity expansion: simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NONET | LIBXML_NOENT_OFF); on modern libxml external entities are off by default -- keep it that way and reject DOCTYPE.",
    },
    {
        "id": "extract-csrf-14", "title": "extract()/parse_str overwrite + missing CSRF token",
        "vuln_type": "variable_overwrite_csrf", "family": "auth_logic", "cwe": "CWE-352",
        "severity": "high", "base_risk": 79,
        "trust_boundary": "attacker request variables -> app variables + forged state change",
        "code": """<?php
extract($_REQUEST);
parse_str($_SERVER['QUERY_STRING']);
if ($_POST['action'] == 'transfer') { $is_admin = $is_admin; echo "done"; }
// state-changing form handler with no CSRF token check at all
""",
        "expected_sources": ["$_REQUEST", "$_SERVER"], "expected_sinks": ["extract", "parse_str"],
        "expected_sanitizers_absent": ["csrf", "hash_equals"],
        "hardening": "Never extract()/parse_str() request data into scope (CWE-915 mass-assignment/overwrite). Read named fields explicitly, and require a per-session CSRF token verified with hash_equals() on every state-changing request (CWE-352).",
    },
]


def get_sample(sample_id: str):
    for s in SAMPLES:
        if s["id"] == sample_id:
            return s
    return None


def sample_ids():
    return [s["id"] for s in SAMPLES]
