#!/usr/bin/env python3
"""
redact_trivy_secrets.py — Trivy secret scan report-undan secret fraqmentlərini silir.

Eyni prinsip `redact_gitleaks.py`-dakı kimidir (bax Phase 2 Gate 3):
Trivy `--scanners secret` çıxışında hər finding üçün `Match` sahəsi tapılan
sətrin məzmununu (yəni secret-in özünü və ya bir hissəsini) saxlayır, `Code`
sahəsi isə ətraf sətirləri.

Bu report-u GitHub Actions artifact kimi yükləmək o deməkdir ki, repo-ya read
çıxışı olan hər kəs onu 30 gün ərzində endirə bilər — yəni secret scanner-in
özü sızma kanalına çevrilir.

Ona görə:
  XAM report      → yalnız DefectDojo (autentifikasiyalı, RBAC-lı store)
  REDAKTƏ EDİLMİŞ → artifact (yer, rule ID, severity qalır; dəyər getmir)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

SENSITIVE_KEYS = ("Match", "Code")


def _redact_value(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
    return f"[REDACTED sha256:{digest} len={len(value)}]"


def redact_secret(secret: dict) -> dict:
    out = dict(secret)
    for key in SENSITIVE_KEYS:
        if key not in out or not out[key]:
            continue
        # `Match` string-dir; `Code` isə sətir siyahısı saxlayan obyektdir.
        if isinstance(out[key], str):
            out[key] = _redact_value(out[key])
        else:
            out[key] = "[REDACTED code context]"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Trivy secret report redaction")
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    if not args.input.exists():
        print(f"ERROR: input tapılmadı: {args.input}", file=sys.stderr)
        return 2

    raw = args.input.read_text(encoding="utf-8").strip()
    if not raw:
        args.output.write_text('{"Results":[]}', encoding="utf-8")
        return 0

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ERROR: JSON parse xətası: {exc}", file=sys.stderr)
        return 2

    count = 0
    for result in doc.get("Results", []) or []:
        secrets = result.get("Secrets")
        if not secrets:
            continue
        result["Secrets"] = [redact_secret(s) for s in secrets if isinstance(s, dict)]
        count += len(result["Secrets"])

    args.output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{count} secret finding redaktə edildi → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
