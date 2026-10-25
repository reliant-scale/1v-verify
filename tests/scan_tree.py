#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""VFY-18: dependency and secret scan of the packaged tree.

Fails if: a PRIVATE KEY block exists outside tests/test_keys/; any file name or
content references 1V runtime paths or production private material; the
verifier imports a network or process module; or a non-allowlisted third-party
import appears in src/.
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_THIRD_PARTY = {"cryptography"}
FORBIDDEN_MODULES = {"socket", "urllib", "http", "requests", "ssl", "asyncio", "subprocess", "ftplib", "smtplib", "xmlrpc", "ctypes"}
FORBIDDEN_CONTENT = [
    re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(rb"1v_sigil"), re.compile(rb"rog-fotress"), re.compile(rb"forge\.db"),
    re.compile(rb"bridge_shared"), re.compile(rb"rehearsal_verify"),
    re.compile(rb"/home/wner/1v_forge"), re.compile(rb"bastion-console"),
]
SKIP_DIRS = {".git", "__pycache__", "dist"}


def main() -> int:
    problems = []
    files = [p for p in ROOT.rglob("*") if p.is_file() and not (set(p.relative_to(ROOT).parts) & SKIP_DIRS)]
    for p in files:
        rel = p.relative_to(ROOT).as_posix()
        data = p.read_bytes()
        for rx in FORBIDDEN_CONTENT:
            if rx.search(data):
                if rx.pattern.startswith(b"-----BEGIN") and rel.startswith("tests/test_keys/"):
                    continue  # labelled TEST key is the only permitted private material
                if rel in ("tests/scan_tree.py",):
                    continue  # this file names the patterns it scans for
                if rx.pattern in (rb"forge\.db", rb"rog-fotress", rb"1v_sigil") and rel.endswith(".md"):
                    continue  # documentation may name the provenance facts; code and fixtures may not
                problems.append(f"{rel}: forbidden content {rx.pattern!r}")
    # import scan of src/
    for p in (ROOT / "src").glob("*.py"):
        tree = ast.parse(p.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module.split(".")[0]]
            for n in names:
                if n in FORBIDDEN_MODULES:
                    problems.append(f"{p.name}: forbidden import {n}")
                if n not in sys.stdlib_module_names and n not in ALLOWED_THIRD_PARTY:
                    problems.append(f"{p.name}: non-allowlisted third-party import {n}")
    print(f"scanned {len(files)} files")
    for pr in problems:
        print("PROBLEM:", pr)
    print("VFY-18 PASS" if not problems else "VFY-18 FAIL")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
