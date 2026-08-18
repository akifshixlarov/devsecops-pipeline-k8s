#!/usr/bin/env python3
"""
severity_gate.py — vahid security gate qərar mühərriki.

Bütün scanner-lərin fərqli JSON/SARIF formatlarını tək bir normalized finding
siyahısına çevirir, `ci/policy.yaml`-dakı siyasəti tətbiq edir və exit code
qaytarır.

Dizayn prinsipi (capstone tələbi):
    SCAN → REPORT → DEFECTDOJO → SEVERITY CHECK → PASS/FAIL

Bu skript zəncirin YALNIZ "SEVERITY CHECK" hissəsidir. O, HEÇ VAXT scan
işlətmir və HEÇ VAXT upload etmir. Bu ayrılıq qəsdəndir: workflow-da upload
addımı bu skriptdən ƏVVƏL gəlir, ona görə də gate FAIL etsə belə finding-lər
artıq DefectDojo-ya yazılmış olur.

Exit codes:
    0 → PASS (block-səviyyəli finding yoxdur)
    1 → FAIL (policy pozulub — pipeline dayanmalıdır)
    2 → ERROR (report oxunmadı / parse edilmədi / policy yanlışdır)

Qeyd: exit 2 də pipeline-ı dayandırır. Bu qəsdəndir — "report parse edilmədi"
halı "finding yoxdur" kimi interpretasiya edilməməlidir (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML tələb olunur (pip install -r ci/requirements.txt)", file=sys.stderr)
    sys.exit(2)


SEVERITIES = ["critical", "high", "medium", "low", "unknown"]

# GitHub Actions job summary və annotation-lar üçün.
GH_STEP_SUMMARY = os.environ.get("GITHUB_STEP_SUMMARY")


# ─────────────────────────────────────────────────────────────────────────────
# Normalization
# ─────────────────────────────────────────────────────────────────────────────

def _norm_sev(value: Any, default: str = "unknown") -> str:
    """İstənilən scanner-in severity string-ini normalize edir."""
    if value is None:
        return default
    s = str(value).strip().lower()
    mapping = {
        "critical": "critical", "crit": "critical", "blocker": "critical",
        "high": "high", "error": "high", "important": "high",
        "medium": "medium", "moderate": "medium", "warning": "medium", "warn": "medium",
        "low": "low", "info": "low", "informational": "low", "note": "low", "minor": "low",
        "unknown": "unknown", "none": "unknown",
    }
    return mapping.get(s, default)


def scanner_errors(fmt: str, doc: Any) -> list[str]:
    """
    Scanner-in ÖZ icrasında baş verən xətaları çıxarır.

    NİYƏ BU KRİTİKDİR (real testdə aşkarlanmış fail-open deşiyi):
        Əgər Semgrep rule faylı yanlış YAML-dırsa, Semgrep `--json` çıxışında
        `{"results": [], "errors": [...]}` qaytarır və exit code 0 verir.
        Naive gate bunu "0 finding → PASS" kimi oxuyur və pipeline yaşıl olur —
        halbuki HEÇ BİR QAYDA İCRA OLUNMAYIB. Yəni SAST tamamilə söndürülüb,
        amma dashboard yaşıl görünür. Bu, ən təhlükəli gate nasazlığıdır:
        səssiz fail-open.

        Ona görə gate scanner error-larını finding qədər ciddi qəbul edir və
        exit 2 (ERROR) qaytarır — pipeline dayanır.
    """
    errs: list[str] = []
    if fmt == "semgrep" and isinstance(doc, dict):
        for e in doc.get("errors", []) or []:
            if isinstance(e, dict):
                msg = e.get("message") or e.get("long_msg") or e.get("short_msg") or str(e)
            else:
                msg = str(e)
            errs.append(str(msg).strip().split("\n")[0][:200])
    elif fmt == "trivy" and isinstance(doc, dict):
        # Trivy heç bir target tapmadıqda `Results` yoxdur/boşdur.
        # Bu, "zəiflik yoxdur" DEYİL, "scan edəcək heç nə tapılmadı" deməkdir.
        if "Results" not in doc:
            errs.append("Trivy çıxışında 'Results' sahəsi yoxdur — scan hədəfi tapılmayıb?")
    elif fmt == "sarif" and isinstance(doc, dict):
        for run in doc.get("runs", []) or []:
            for notif in (run.get("invocations") or [{}])[0].get("toolExecutionNotifications", []) or []:
                if str(notif.get("level", "")).lower() == "error":
                    errs.append(str((notif.get("message") or {}).get("text", ""))[:200])
    return errs


def parse_semgrep(doc: dict) -> list[dict]:
    """
    Semgrep JSON (`semgrep --json`).

    Severity mənbəyi prioriteti:
      1. extra.metadata.impact  (Semgrep-in security impact reytinqi — daha dəqiq)
      2. extra.severity         (ERROR/WARNING/INFO — linter səviyyəsi)
    Səbəb: `extra.severity` rule-un "nə qədər əminəm" göstəricisidir, security
    impact deyil. Metadata mövcud olduqda ona üstünlük veririk.
    """
    out = []
    for r in doc.get("results", []) or []:
        extra = r.get("extra", {}) or {}
        meta = extra.get("metadata", {}) or {}
        sev = _norm_sev(meta.get("impact")) if meta.get("impact") else _norm_sev(extra.get("severity"))
        out.append({
            "severity": sev,
            "id": r.get("check_id", "unknown-rule"),
            "location": f"{r.get('path', '?')}:{(r.get('start') or {}).get('line', '?')}",
            "title": (extra.get("message") or "").strip().split("\n")[0][:160],
        })
    return out


def parse_trivy(doc: dict) -> list[dict]:
    """
    Trivy JSON — həm `trivy fs` (Vulnerabilities), həm `trivy config`
    (Misconfigurations), həm də `trivy image` üçün eyni parser işləyir,
    çünki Trivy hər üçündə eyni `Results[]` zərfini istifadə edir.
    """
    out = []
    for res in doc.get("Results", []) or []:
        target = res.get("Target", "?")

        for v in res.get("Vulnerabilities", []) or []:
            out.append({
                "severity": _norm_sev(v.get("Severity")),
                "id": v.get("VulnerabilityID", "unknown-cve"),
                "location": f"{target} → {v.get('PkgName', '?')}@{v.get('InstalledVersion', '?')}",
                "title": (v.get("Title") or v.get("Description") or "")[:160],
                "fixed_version": v.get("FixedVersion") or "",
            })

        for m in res.get("Misconfigurations", []) or []:
            out.append({
                "severity": _norm_sev(m.get("Severity")),
                "id": m.get("ID", "unknown-misconfig"),
                "location": f"{target}:{((m.get('CauseMetadata') or {}).get('StartLine')) or '?'}",
                "title": (m.get("Title") or "")[:160],
            })

        # Trivy secret scanning (image layer / fs) — Gate 6-da istifadə olunacaq.
        for s in res.get("Secrets", []) or []:
            out.append({
                "severity": _norm_sev(s.get("Severity"), default="critical"),
                "id": s.get("RuleID", "unknown-secret"),
                "location": f"{target}:{s.get('StartLine', '?')}",
                "title": (s.get("Title") or "secret detected")[:160],
            })
    return out


def parse_gitleaks(doc: Any) -> list[dict]:
    """
    Gitleaks JSON — top-level array.

    KRİTİK: Gitleaks severity anlayışı vermir. Biz hər finding-i CRITICAL kimi
    normalize edirik. Səbəb (threat model T1): repo-ya commit edilmiş credential
    git history-də immutable qalır; sadəcə növbəti commit-də silmək onu
    ləğv etmir. Ona görə "aşağı riskli secret" kateqoriyası yaratmırıq.

    Bu funksiya finding-in ÖZ DƏYƏRİNİ (Secret/Match) HEÇ VAXT output-a çıxarmır.
    """
    findings = doc if isinstance(doc, list) else (doc.get("findings", []) if isinstance(doc, dict) else [])
    out = []
    for f in findings or []:
        out.append({
            "severity": "critical",
            "id": f.get("RuleID") or f.get("ruleID") or "gitleaks-finding",
            "location": f"{f.get('File', '?')}:{f.get('StartLine', '?')}"
                        + (f" (commit {str(f.get('Commit', ''))[:8]})" if f.get("Commit") else ""),
            # Secret dəyəri deyil, YALNIZ rule təsviri.
            "title": (f.get("Description") or "secret detected")[:160],
        })
    return out


def parse_sarif(doc: dict) -> list[dict]:
    """
    SARIF 2.1.0 — zizmor (GitHub Actions audit) və SARIF verən digər alətlər üçün.

    Severity mənbəyi:
      1. result.properties.security-severity (CVSS-bənzər rəqəm, GitHub konvensiyası)
      2. rule.defaultConfiguration.level / result.level (error/warning/note)
    """
    out = []
    for run in doc.get("runs", []) or []:
        tool = ((run.get("tool") or {}).get("driver") or {})
        rules = {r.get("id"): r for r in (tool.get("rules") or [])}

        for res in run.get("results", []) or []:
            rule_id = res.get("ruleId", "unknown-rule")
            rule = rules.get(rule_id, {})
            props = res.get("properties") or rule.get("properties") or {}

            sev = None
            ss = props.get("security-severity")
            if ss is not None:
                try:
                    score = float(ss)
                    sev = ("critical" if score >= 9.0 else
                           "high" if score >= 7.0 else
                           "medium" if score >= 4.0 else "low")
                except (TypeError, ValueError):
                    sev = None
            if sev is None:
                level = res.get("level") or (rule.get("defaultConfiguration") or {}).get("level")
                sev = _norm_sev(level)

            loc = "?"
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0].get("physicalLocation") or {})
                uri = ((phys.get("artifactLocation") or {}).get("uri")) or "?"
                line = ((phys.get("region") or {}).get("startLine")) or "?"
                loc = f"{uri}:{line}"

            msg = ((res.get("message") or {}).get("text") or "").strip().split("\n")[0]
            out.append({"severity": sev, "id": rule_id, "location": loc, "title": msg[:160]})
    return out


PARSERS = {
    "semgrep": parse_semgrep,
    "trivy": parse_trivy,
    "gitleaks": parse_gitleaks,
    "sarif": parse_sarif,
}


# ─────────────────────────────────────────────────────────────────────────────
# Policy
# ─────────────────────────────────────────────────────────────────────────────

def load_policy(path: Path, scanner: str) -> dict:
    with path.open(encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    policy = dict(cfg.get("default") or {})
    override = (cfg.get("scanners") or {}).get(scanner)
    if override:
        policy.update(override)

    resolved = {}
    for sev in SEVERITIES:
        rule = policy.get(sev) or {"action": "warn"}
        action = str(rule.get("action", "warn")).lower()
        if action not in ("block", "warn", "ignore"):
            raise ValueError(f"policy.yaml: '{scanner}.{sev}.action' yanlışdır: {action}")
        resolved[sev] = {"action": action, "max_allowed": rule.get("max_allowed")}
    return resolved


def evaluate(findings: list[dict], policy: dict) -> tuple[bool, list[str]]:
    """(passed, violation_messages) qaytarır."""
    counts = Counter(f["severity"] for f in findings)
    violations = []

    for sev in SEVERITIES:
        n = counts.get(sev, 0)
        if n == 0:
            continue
        rule = policy[sev]
        if rule["action"] == "block":
            violations.append(f"{n} × {sev.upper()} finding (policy: BLOCK — tolerantlıq yoxdur)")
        elif rule["action"] == "warn" and rule["max_allowed"] is not None and n > rule["max_allowed"]:
            violations.append(
                f"{n} × {sev.upper()} finding, icazə verilən maksimum {rule['max_allowed']} (policy: threshold aşıldı)"
            )
    return (len(violations) == 0), violations


# ─────────────────────────────────────────────────────────────────────────────
# Output
# ─────────────────────────────────────────────────────────────────────────────

def write_summary(text: str) -> None:
    print(text)
    if GH_STEP_SUMMARY:
        with open(GH_STEP_SUMMARY, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")


def build_report(scanner: str, findings: list[dict], policy: dict,
                 passed: bool, violations: list[str], show: int) -> str:
    counts = Counter(f["severity"] for f in findings)
    lines = [
        "",
        f"## Security Gate — `{scanner}`",
        "",
        "| Severity | Count | Policy | Max allowed |",
        "|---|---:|---|---|",
    ]
    for sev in SEVERITIES:
        rule = policy[sev]
        maxa = rule["max_allowed"] if rule["max_allowed"] is not None else "—"
        lines.append(f"| {sev.upper()} | {counts.get(sev, 0)} | {rule['action'].upper()} | {maxa} |")

    lines += ["", f"**Ümumi finding sayı:** {len(findings)}", ""]

    if violations:
        lines += ["### Policy pozuntuları", ""] + [f"- {v}" for v in violations] + [""]

    blocking = [f for f in findings if policy[f["severity"]]["action"] == "block"]
    if blocking:
        lines += [f"### Bloklayan finding-lər (ilk {min(show, len(blocking))} / {len(blocking)})", ""]
        for f in blocking[:show]:
            lines.append(f"- `{f['severity'].upper()}` **{f['id']}** — {f['location']}")
            if f.get("title"):
                lines.append(f"  - {f['title']}")
            if f.get("fixed_version"):
                lines.append(f"  - Düzəliş mövcuddur: `{f['fixed_version']}`")
        lines.append("")

    lines += [f"### Nəticə: {'✅ PASS' if passed else '❌ FAIL'}", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Security gate — report → policy → exit code")
    ap.add_argument("--report", required=True, type=Path, help="Scanner report faylı")
    ap.add_argument("--format", required=True, choices=sorted(PARSERS), help="Report formatı")
    ap.add_argument("--scanner", required=True, help="policy.yaml-dakı scanner açarı (məs. trivy-sca)")
    ap.add_argument("--policy", default=Path("ci/policy.yaml"), type=Path)
    ap.add_argument("--show", type=int, default=20, help="Summary-də göstəriləcək finding sayı")
    ap.add_argument("--allow-scanner-errors", action="store_true",
                    help="Scanner error-larını görməzdən gəl (fail-open! yalnız debug üçün)")
    args = ap.parse_args()

    if not args.report.exists():
        # Fail-closed: report yoxdursa, scan işləməyib deməkdir.
        write_summary(f"\n## Security Gate — `{args.scanner}`\n\n"
                      f"❌ **ERROR:** report faylı tapılmadı: `{args.report}`\n\n"
                      f"Bu, 'finding yoxdur' kimi qəbul EDİLMİR — scan addımı uğursuz olub.\n")
        return 2

    try:
        raw = args.report.read_text(encoding="utf-8").strip()
        doc = json.loads(raw) if raw else {}
    except json.JSONDecodeError as exc:
        write_summary(f"\n## Security Gate — `{args.scanner}`\n\n"
                      f"❌ **ERROR:** report JSON kimi parse edilmədi: {exc}\n")
        return 2

    # ── FAIL-CLOSED: scanner öz-özünə uğursuz olubsa, "0 finding" yalandır ──
    if not args.allow_scanner_errors:
        errs = scanner_errors(args.format, doc)
        if errs:
            detail = "\n".join(f"> - `{e}`" for e in errs[:10])
            write_summary(
                f"\n## Security Gate — `{args.scanner}`\n\n"
                f"❌ **ERROR: scanner {len(errs)} xəta bildirdi — nəticə ETİBARSIZDIR.**\n\n"
                f"{detail}\n\n"
                f"> Bu vəziyyət 'finding yoxdur' kimi qəbul EDİLMİR.\n"
                f"> Scanner qaydaları yüklənməyibsə, 0 finding sadəcə o deməkdir ki,\n"
                f"> heç nə yoxlanmayıb — bu, səssiz fail-open olardı.\n"
            )
            return 2

    try:
        findings = PARSERS[args.format](doc)
        policy = load_policy(args.policy, args.scanner)
    except Exception as exc:  # noqa: BLE001 — gate həmişə fail-closed olmalıdır
        write_summary(f"\n## Security Gate — `{args.scanner}`\n\n❌ **ERROR:** {type(exc).__name__}: {exc}\n")
        return 2

    passed, violations = evaluate(findings, policy)
    write_summary(build_report(args.scanner, findings, policy, passed, violations, args.show))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
