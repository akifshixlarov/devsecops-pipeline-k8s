#!/usr/bin/env python3
"""
redact_gitleaks.py — Gitleaks JSON report-undan secret dəyərlərini silir.

PROBLEM (əksər tutorial-larda buraxılan ciddi səhv):
    Gitleaks JSON report-u tapılan secret-in ÖZ DƏYƏRİNİ `Secret` və `Match`
    sahələrində saxlayır. Bu report-u olduğu kimi GitHub Actions artifact kimi
    yükləmək o deməkdir ki:
      - repo-ya read çıxışı olan HƏR KƏS artifact-i endirib secret-i oxuya bilər;
      - artifact default olaraq 90 gün saxlanılır;
      - yəni "secret detection" alətinin özü secret leak kanalına çevrilir.

HƏLL (defense in depth):
    İki fərqli fayl istehsal edirik:
      1. RAW report  → yalnız DefectDojo-ya (autentifikasiyalı, RBAC-lı store)
                       göndərilir, artifact kimi YÜKLƏNMİR, job sonunda silinir.
      2. REDACTED report → artifact kimi yüklənir; finding-in yeri, rule-u və
                       fingerprint-i qalır (triage üçün kifayətdir), dəyəri isə yox.

Bu, threat model-dəki T7 (CI/CD-də secret sızması) mitiqasiyasının bir hissəsidir.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

# Secret dəyəri saxlaya bilən bütün sahələr.
SENSITIVE_FIELDS = ("Secret", "Match", "Line", "secret", "match", "line")


def redact_finding(finding: dict) -> dict:
    out = dict(finding)
    for field in SENSITIVE_FIELDS:
        if field in out and out[field]:
            value = str(out[field])
            # Dəyərin özü deyil, yalnız onun hash-i və uzunluğu qalır.
            # Bu, eyni secret-in müxtəlif fayllarda təkrarlandığını korrelyasiya
            # etməyə imkan verir, amma dəyəri bərpa etməyə imkan vermir.
            digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:16]
            out[field] = f"[REDACTED sha256:{digest} len={len(value)}]"
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Gitleaks report redaction")
    ap.add_argument("--input", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    if not args.input.exists():
        print(f"ERROR: input tapılmadı: {args.input}", file=sys.stderr)
        return 2

    raw = args.input.read_text(encoding="utf-8").strip()
    if not raw:
        args.output.write_text("[]", encoding="utf-8")
        print("Input boşdur → boş redacted report yazıldı.")
        return 0

    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"ERROR: JSON parse xətası: {exc}", file=sys.stderr)
        return 2

    if isinstance(doc, list):
        redacted = [redact_finding(f) for f in doc if isinstance(f, dict)]
        count = len(redacted)
    elif isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        redacted = dict(doc)
        redacted["findings"] = [redact_finding(f) for f in doc["findings"] if isinstance(f, dict)]
        count = len(redacted["findings"])
    else:
        print("ERROR: gözlənilməyən Gitleaks report strukturu", file=sys.stderr)
        return 2

    args.output.write_text(json.dumps(redacted, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"{count} finding redaktə edildi → {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
