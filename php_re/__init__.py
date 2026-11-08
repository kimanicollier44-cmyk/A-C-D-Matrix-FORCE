"""php_re subset — Sandbox-API chamber + honeypot, decompressed into
A-C-D-Matrix-FORCE from Darion's PHP-Vuln-RE lab (the in-repo embodiment of
his Docker Hub images credkellar/sandbox-api, 8,467 pulls, and
credkellar/honeyroot-x, 325 pulls).

Only the modules those two features need are vendored, verbatim:
analyzer.py (static taint analysis the chamber reports), samples.py (the
14 synthetic samples), sandbox.py (the chamber), honeypot.py (log analysis).
The rest of PHP-Vuln-RE stays in its own repo — it is a different lab.
"""
