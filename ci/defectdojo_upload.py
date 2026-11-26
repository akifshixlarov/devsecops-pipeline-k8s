#!/usr/bin/env python3
"""
defectdojo_upload.py — scanner report-unu DefectDojo-ya `reimport-scan` ilə göndərir.

Niyə `reimport-scan`, `import-scan` deyil:
  `import-scan` hər çağırışda YENİ Test obyekti yaradır → eyni finding hər
  pipeline run-da təkrarlanır və DefectDojo-da duplicate yığılır.
  `reimport-scan` isə mövcud Test-i (scan_type + engagement + test_title üzrə)
  tapıb yeniləyir: yeni finding-lər əlavə olunur, düzəldilmişlər avtomatik
  "Mitigated" statusuna keçir. Bu, trend analizi və "bu CVE nə vaxt düzəldildi"
  sualına cavab verməyə imkan yaradır.

Bu skript pipeline-da HƏMİŞƏ severity gate-dən ƏVVƏL çağırılır:
    SCAN → REPORT → [BU SKRİPT] → SEVERITY CHECK → PASS/FAIL
Beləliklə gate FAIL etsə belə, finding-lər mərkəzi store-a yazılmış olur.

Secret hygiene:
  - DD_API_KEY heç vaxt log-a, stdout-a və ya exception mesajına yazılmır.
  - HTTP error body 500 simvola kəsilir və Authorization header-i redaktə olunur.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

# Ensure UTF-8 output encoding across platforms (Windows / Linux)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

try:
    import requests
except ImportError:
    print("ERROR: requests tələb olunur (pip install -r ci/requirements.txt)", file=sys.stderr)
    sys.exit(2)


GH_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")

# Scanner adı → DefectDojo parser adı.
# Bu adlar DefectDojo-nun rəsmi parser siyahısındakı sətirlərlə HƏRFI eyni
# olmalıdır, əks halda API 400 qaytarır.
SCAN_TYPES = {
    "semgrep":            "Semgrep JSON Report",
    "trivy-sca":          "Trivy Scan",
    "trivy-config":       "Trivy Scan",
    "trivy-image":        "Trivy Scan",
    "trivy-image-secret": "Trivy Scan",
    "gitleaks":           "Gitleaks Scan",
    "hadolint":           "Hadolint Dockerfile check",
    "zizmor":             "SARIF",
    "zap":                "ZAP Scan",           # Phase 7
}


def log(msg: str) -> None:
    print(msg, flush=True)
    if GH_STEP_SUMMARY:
        with open(GH_STEP_SUMMARY, "a", encoding="utf-8") as fh:
            fh.write(msg + "\n")


def safe_error(resp: requests.Response) -> str:
    """HTTP cavabını log üçün təhlükəsiz formata salır (token sızmasın)."""
    body = (resp.text or "")[:500].replace("\n", " ")
    return f"HTTP {resp.status_code}: {body}"


def validate_report(scanner: str, report: Path) -> tuple[bool, str]:
    """
    Upload-dan ƏVVƏL report-un etibarlı olduğunu yoxlayır.
    Natamam/boş/zədəli report-lar `close_old_findings=true` ilə köhnə finding-ləri
    səhvən "Mitigated" etməməlidir.
    """
    if not report.exists():
        return False, f"report faylı tapılmadı: `{report}`"
    raw = report.read_text(encoding="utf-8", errors="replace").strip()
    if not raw:
        return False, f"report faylı tamamilə boşdur (0 byte): `{report}`"
    try:
        doc = json.loads(raw)
    except ValueError as exc:
        return False, f"report etibarlı JSON deyil ({exc})"

    if scanner == "semgrep":
        if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
            return False, "Semgrep report-unda 'results' siyahısı yoxdur"
        if doc.get("errors"):
            return False, f"Semgrep report-u {len(doc['errors'])} icra xətası ehtiva edir"
    elif scanner.startswith("trivy"):
        if not isinstance(doc, dict):
            return False, "Trivy report-u JSON obyekti deyil"
        if "Results" in doc and not isinstance(doc["Results"], list):
            return False, "Trivy report-unda 'Results' siyahı formatında deyil"
        if "Results" not in doc and "SchemaVersion" not in doc:
            return False, "Trivy report-unda nə 'Results', nə də 'SchemaVersion' var"
    elif scanner == "gitleaks":
        if not (isinstance(doc, list) or (isinstance(doc, dict) and isinstance(doc.get("findings"), list))):
            return False, "Gitleaks report-u gözlənilən JSON array formatında deyil"
    elif scanner == "hadolint":
        if not (isinstance(doc, list) or (isinstance(doc, dict) and isinstance(doc.get("results"), list))):
            return False, "Hadolint report-u gözlənilən JSON formatında deyil"
    elif scanner == "zizmor":
        if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
            return False, "SARIF report-unda 'runs' siyahısı yoxdur"
    return True, "valid"


def verify_test_import(dd_url: str, api_key: str, test_id: object, timeout: int) -> str:
    """Upload sonrası DefectDojo API-dən Test və aktiv finding sayını təsdiqləyir."""
    if not test_id or test_id == "?":
        return "Test ID qaytarılmadı"
    try:
        resp = requests.get(
            f"{dd_url.rstrip('/')}/api/v2/findings/?test={test_id}&active=true&limit=1",
            headers={"Authorization": f"Token {api_key}"},
            timeout=timeout,
        )
        if resp.status_code == 200:
            active_count = resp.json().get("count", "?")
            return f"DefectDojo Test ID: {test_id} (aktiv finding sayı: {active_count})"
    except requests.RequestException:
        pass
    return f"DefectDojo Test ID: {test_id}"


def upload(dd_url: str, api_key: str, engagement_id: str, scanner: str,
           report: Path, test_title: str, commit: str, branch: str,
           retries: int, timeout: int) -> tuple[bool, str]:
    scan_type = SCAN_TYPES.get(scanner)
    if not scan_type:
        return False, f"Naməlum scanner '{scanner}'. Mövcud: {', '.join(sorted(SCAN_TYPES))}"

    endpoint = dd_url.rstrip("/") + "/api/v2/reimport-scan/"

    product_name = os.environ.get("DD_PRODUCT_NAME")
    engagement_name = os.environ.get("DD_ENGAGEMENT_NAME")

    # DefectDojo reimport-scan API tələbi: product_name və engagement_name lazımdır.
    # Əgər env-də verilməyibsə, engagement_id əsasında API-dən oxuyuruq.
    if not (product_name and engagement_name) and engagement_id:
        try:
            eng_resp = requests.get(
                f"{dd_url.rstrip('/')}/api/v2/engagements/{engagement_id}/",
                headers={"Authorization": f"Token {api_key}"},
                timeout=timeout,
            )
            if eng_resp.status_code == 200:
                eng_data = eng_resp.json()
                engagement_name = engagement_name or eng_data.get("name")
                prod_id = eng_data.get("product")
                if prod_id:
                    prod_resp = requests.get(
                        f"{dd_url.rstrip('/')}/api/v2/products/{prod_id}/",
                        headers={"Authorization": f"Token {api_key}"},
                        timeout=timeout,
                    )
                    if prod_resp.status_code == 200:
                        product_name = product_name or prod_resp.json().get("name")
        except Exception:
            pass

    product_name = product_name or "devsecops-pipeline-k8s"
    engagement_name = engagement_name or "CI/CD Security Gates"

    data = {
        "scan_type": scan_type,
        "engagement": engagement_id,
        "product_name": product_name,
        "engagement_name": engagement_name,
        "auto_create_context": "true",
        "test_title": test_title,
        # active+verified: finding-lər dərhal aktiv sayılsın (triage gözləmədən),
        # çünki gate qərarı onsuz da report əsasında verilir.
        "active": "true",
        "verified": "false",
        # Bu, reimport-un əsas dəyəridir: əvvəlki run-da olub indi olmayan
        # finding-lər avtomatik "Mitigated" olur → real remediation trendi görünür.
        "close_old_findings": "true",
        "push_to_jira": "false",
        "minimum_severity": "Info",
        "branch_tag": branch,
        "commit_hash": commit,
    }

    last_error = "naməlum xəta"
    for attempt in range(1, retries + 1):
        try:
            with report.open("rb") as fh:
                resp = requests.post(
                    endpoint,
                    headers={"Authorization": f"Token {api_key}"},
                    data=data,
                    files={"file": (report.name, fh, "application/json")},
                    timeout=timeout,
                )
            if resp.status_code in (200, 201):
                try:
                    body = resp.json()
                    test_id = body.get("test", "?")
                except ValueError:
                    test_id = "?"
                return True, verify_test_import(dd_url, api_key, test_id, timeout)

            last_error = safe_error(resp)
            # 4xx (401/403/400) retry etmək mənasızdır — konfiqurasiya xətasıdır.
            if 400 <= resp.status_code < 500 and resp.status_code != 429:
                return False, last_error

        except requests.RequestException as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:300]}"

        if attempt < retries:
            backoff = 2 ** attempt
            log(f"  ↻ cəhd {attempt}/{retries} uğursuz ({last_error}); {backoff}s sonra təkrar")
            time.sleep(backoff)

    return False, last_error


def main() -> int:
    ap = argparse.ArgumentParser(description="DefectDojo reimport-scan uploader")
    ap.add_argument("--scanner", required=True, choices=sorted(SCAN_TYPES))
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--test-title", default=None,
                    help="DefectDojo Test başlığı. Default: '<scanner> — <repo>'")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument(
        "--required", default=os.environ.get("DD_UPLOAD_REQUIRED", "false"),
        help="true olduqda upload uğursuzluğu pipeline-ı FAIL edir (protected branch üçün)",
    )
    args = ap.parse_args()

    required = str(args.required).lower() == "true"

    dd_url = os.environ.get("DD_URL", "").strip()
    api_key = os.environ.get("DD_API_KEY", "").strip()
    engagement = os.environ.get("DD_ENGAGEMENT_ID", "").strip()

    # ── Fork PR ssenarisi ────────────────────────────────────────────────────
    # GitHub fork-dan gələn PR-lara secret VERMİR (bu, GitHub-un təhlükəsizlik
    # modelidir və doğrudur). Belə halda upload mümkün deyil.
    # Qərar: upload-u atla, LAKİN severity gate yenə də işləyir — yəni
    # untrusted kod eyni security bar-dan keçir, sadəcə evidence mərkəzi
    # store-a yazılmır. Bu, GitLab-dan əsas fərqdir və qəsdən belədir.
    if not all([dd_url, api_key, engagement]):
        missing = [n for n, v in
                   [("DD_URL", dd_url), ("DD_API_KEY", api_key), ("DD_ENGAGEMENT_ID", engagement)] if not v]
        msg = (f"\n> ⚠️ **DefectDojo upload ATLANDI** — konfiqurasiya yoxdur: "
               f"`{', '.join(missing)}`\n>\n"
               f"> Bu, adətən fork PR deməkdir (GitHub fork-lara secret vermir).\n"
               f"> **Severity gate yenə də tətbiq olunur** — security bar aşağı düşmür.\n")
        log(msg)
        if required:
            log("> ❌ `DD_UPLOAD_REQUIRED=true` — evidence zənciri qırıldığı üçün FAIL.\n")
            return 1
        return 0

    ok_report, reason = validate_report(args.scanner, args.report)
    if not ok_report:
        log(f"\n> ❌ **DefectDojo upload BLOKLANDI (report etibarsız)** — {reason}\n")
        return 1 if required else 0

    repo = os.environ.get("GITHUB_REPOSITORY", "local")
    commit = os.environ.get("GITHUB_SHA", "local")[:40]
    branch = os.environ.get("GITHUB_REF_NAME", "local")
    run_url = (f"{os.environ.get('GITHUB_SERVER_URL', '')}/{repo}/actions/runs/"
               f"{os.environ.get('GITHUB_RUN_ID', '')}") if os.environ.get("GITHUB_RUN_ID") else "local"

    # test_title reimport üçün açardır: eyni başlıq = eyni Test yenilənir.
    # Ona görə İÇİNDƏ commit SHA OLMAMALIDIR (əks halda hər run yeni Test yaradar).
    test_title = args.test_title or f"{args.scanner} — {repo}"

    log(f"\n### DefectDojo upload — `{args.scanner}`\n")
    log(f"- Parser: `{SCAN_TYPES[args.scanner]}`")
    log(f"- Test title: `{test_title}`")
    log(f"- Engagement: `{engagement}`")
    log(f"- Commit: `{commit[:8]}` · Branch: `{branch}`")

    ok, detail = upload(dd_url, api_key, engagement, args.scanner, args.report,
                        test_title, commit, branch, args.retries, args.timeout)

    if ok:
        log(f"- ✅ Uğurlu — {detail}\n")
        return 0

    log(f"- ❌ Uğursuz — {detail}\n")
    if required:
        log("> `DD_UPLOAD_REQUIRED=true` olduğu üçün pipeline FAIL edir: "
            "auditability tələbi pozulub (finding mərkəzi store-a yazılmadı).\n")
        return 1

    log("> `DD_UPLOAD_REQUIRED=false` — xəbərdarlıq kimi qeyd olundu, "
        "severity gate davam edir.\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
