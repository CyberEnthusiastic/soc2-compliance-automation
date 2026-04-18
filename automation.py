"""
SOC 2 Compliance Automation
Automated SOC 2 Trust Services Criteria (TSC) control checks with
evidence collection and gap-report generation.

Modes:
  python automation.py run           # execute all controls against local evidence
  python automation.py run --tsc CC6 # run only CC6.x (Logical Access) controls
  python automation.py list          # list controls
  python automation.py map csv       # export SOC2 <-> ISO 27001 <-> NIST CSF mapping

Evidence sources:
  - evidence/*.json        - simulated control evidence (git log, config dumps, etc.)
  - evidence/system.json   - system metadata (MFA setting, encryption, backups)

Author: Mohith Vasamsetti (CyberEnthusiastic)
"""
import os
import re
import sys
import json
import argparse
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import List, Dict, Optional, Any

from report_generator import generate_html


# -------------------------------------------------------------
# Control catalog: SOC 2 Trust Services Criteria
# (subset - 20 representative controls covering all 5 TSC categories)
# -------------------------------------------------------------
CONTROLS = [
    # -------- Security (CC1-CC9) --------
    {"id": "CC1.1", "tsc": "CC1", "category": "Security",
     "name": "Commitment to integrity and ethical values",
     "description": "Organization demonstrates commitment to integrity and ethical values via code of conduct, training, and disciplinary actions.",
     "iso27001": ["A.7.2.2"], "nist_csf": ["GV.OC-03"],
     "evidence_key": "code_of_conduct",
     "rule": lambda ev, sys: bool(ev.get("code_of_conduct", {}).get("published"))
                              and ev.get("code_of_conduct", {}).get("annual_training", 0) > 0},
    {"id": "CC2.1", "tsc": "CC2", "category": "Security",
     "name": "Internal communication of security objectives",
     "description": "Security objectives are communicated to internal users via policy, onboarding, and ongoing comms.",
     "iso27001": ["A.6.2.1"], "nist_csf": ["GV.PO-01"],
     "evidence_key": "security_policies",
     "rule": lambda ev, sys: len(ev.get("security_policies", [])) >= 3},
    {"id": "CC5.2", "tsc": "CC5", "category": "Security",
     "name": "Deployment of technology-based security controls",
     "description": "Logical and physical access controls are deployed via technology.",
     "iso27001": ["A.9.1.1"], "nist_csf": ["PR.AC-01"],
     "evidence_key": "idp",
     "rule": lambda ev, sys: sys.get("sso_enforced") is True},
    {"id": "CC6.1", "tsc": "CC6", "category": "Security",
     "name": "Logical access restricted based on role",
     "description": "Least-privilege access based on role / business need (RBAC + periodic review).",
     "iso27001": ["A.9.2.3"], "nist_csf": ["PR.AC-04"],
     "evidence_key": "access_reviews",
     "rule": lambda ev, sys: len(ev.get("access_reviews", [])) >= 2},
    {"id": "CC6.2", "tsc": "CC6", "category": "Security",
     "name": "Registration and authorization of new users",
     "description": "New users are registered and authorized before access is granted. Evidence: ticketed access provisioning.",
     "iso27001": ["A.9.2.1"], "nist_csf": ["PR.AC-01"],
     "evidence_key": "provisioning_tickets",
     "rule": lambda ev, sys: ev.get("provisioning_tickets", {}).get("with_approval_pct", 0) >= 95},
    {"id": "CC6.3", "tsc": "CC6", "category": "Security",
     "name": "Revocation of access upon termination",
     "description": "Access is revoked within defined SLA (e.g. 24h) of termination. Evidence: offboarding audit log.",
     "iso27001": ["A.9.2.6"], "nist_csf": ["PR.AC-01"],
     "evidence_key": "offboarding",
     "rule": lambda ev, sys: ev.get("offboarding", {}).get("max_hours_to_revoke", 99) <= 24},
    {"id": "CC6.6", "tsc": "CC6", "category": "Security",
     "name": "Multi-factor authentication enforced",
     "description": "MFA is enforced for all privileged and remote users.",
     "iso27001": ["A.9.4.2"], "nist_csf": ["PR.AC-07"],
     "evidence_key": "mfa",
     "rule": lambda ev, sys: sys.get("mfa_enforced") is True
                              and sys.get("mfa_coverage_pct", 0) >= 98},
    {"id": "CC6.7", "tsc": "CC6", "category": "Security",
     "name": "Encryption of data at rest and in transit",
     "description": "All customer data encrypted at rest (AES-256) and in transit (TLS 1.2+).",
     "iso27001": ["A.10.1.1"], "nist_csf": ["PR.DS-01", "PR.DS-02"],
     "evidence_key": "encryption",
     "rule": lambda ev, sys: sys.get("encryption_at_rest") == "AES-256"
                              and sys.get("tls_min_version", "1.0") in ("1.2", "1.3")},
    {"id": "CC6.8", "tsc": "CC6", "category": "Security",
     "name": "Prevention and detection of malicious software",
     "description": "Endpoint protection (EDR) deployed on all production servers and workstations.",
     "iso27001": ["A.12.2.1"], "nist_csf": ["DE.CM-04"],
     "evidence_key": "edr",
     "rule": lambda ev, sys: sys.get("edr_coverage_pct", 0) >= 95},
    {"id": "CC7.1", "tsc": "CC7", "category": "Security",
     "name": "Detection of anomalies and security events",
     "description": "SIEM / monitoring in place with documented alerting rules.",
     "iso27001": ["A.12.4.1"], "nist_csf": ["DE.AE-01", "DE.CM-01"],
     "evidence_key": "siem",
     "rule": lambda ev, sys: bool(sys.get("siem_vendor")) and sys.get("alerting_rules", 0) >= 10},
    {"id": "CC7.2", "tsc": "CC7", "category": "Security",
     "name": "Monitoring of system components for vulnerabilities",
     "description": "Regular vulnerability scans against production; critical CVEs patched within SLA.",
     "iso27001": ["A.12.6.1"], "nist_csf": ["ID.RA-01", "PR.IP-12"],
     "evidence_key": "vuln_scans",
     "rule": lambda ev, sys: ev.get("vuln_scans", {}).get("critical_overdue", 99) == 0},
    {"id": "CC7.3", "tsc": "CC7", "category": "Security",
     "name": "Incident response procedures",
     "description": "Documented incident response plan; tabletop exercise completed within last 12 months.",
     "iso27001": ["A.16.1.1"], "nist_csf": ["RS.RP-01"],
     "evidence_key": "ir_plan",
     "rule": lambda ev, sys: bool(ev.get("ir_plan", {}).get("last_tabletop_date"))
                              and _days_ago(ev.get("ir_plan", {}).get("last_tabletop_date")) <= 365},
    {"id": "CC8.1", "tsc": "CC8", "category": "Security",
     "name": "Change management process",
     "description": "Production changes follow documented change-management workflow with approval + rollback plan.",
     "iso27001": ["A.12.1.2"], "nist_csf": ["PR.IP-03"],
     "evidence_key": "change_mgmt",
     "rule": lambda ev, sys: ev.get("change_mgmt", {}).get("changes_with_approval_pct", 0) >= 98},
    {"id": "CC9.1", "tsc": "CC9", "category": "Security",
     "name": "Risk assessment process",
     "description": "Annual risk assessment is documented; treatment plan tracked.",
     "iso27001": ["A.6.1.1"], "nist_csf": ["ID.RA-01"],
     "evidence_key": "risk_assessment",
     "rule": lambda ev, sys: bool(ev.get("risk_assessment", {}).get("last_completed"))
                              and _days_ago(ev.get("risk_assessment", {}).get("last_completed")) <= 365},
    # -------- Availability (A1) --------
    {"id": "A1.1", "tsc": "A1", "category": "Availability",
     "name": "Backup and recovery procedures",
     "description": "Regular backups with tested restore procedure. RTO/RPO documented.",
     "iso27001": ["A.12.3.1"], "nist_csf": ["PR.IP-04"],
     "evidence_key": "backups",
     "rule": lambda ev, sys: bool(ev.get("backups", {}).get("last_restore_test"))
                              and _days_ago(ev.get("backups", {}).get("last_restore_test")) <= 90},
    {"id": "A1.2", "tsc": "A1", "category": "Availability",
     "name": "Capacity planning and monitoring",
     "description": "Capacity is monitored against SLA; alerts when approaching thresholds.",
     "iso27001": ["A.12.1.3"], "nist_csf": ["PR.DS-04"],
     "evidence_key": "capacity_monitoring",
     "rule": lambda ev, sys: sys.get("capacity_alerting") is True},
    # -------- Confidentiality (C1) --------
    {"id": "C1.1", "tsc": "C1", "category": "Confidentiality",
     "name": "Confidential data classified and protected",
     "description": "Customer PII/PHI/PCI data is classified, labelled, and access-controlled.",
     "iso27001": ["A.8.2.1"], "nist_csf": ["ID.AM-05"],
     "evidence_key": "data_classification",
     "rule": lambda ev, sys: ev.get("data_classification", {}).get("labelled_pct", 0) >= 90},
    # -------- Processing Integrity (PI1) --------
    {"id": "PI1.1", "tsc": "PI1", "category": "Processing Integrity",
     "name": "Input/output validation",
     "description": "Automated validation on data inputs and outputs to ensure completeness and accuracy.",
     "iso27001": ["A.14.1.1"], "nist_csf": ["PR.DS-06"],
     "evidence_key": "input_validation",
     "rule": lambda ev, sys: ev.get("input_validation", {}).get("coverage_pct", 0) >= 85},
    # -------- Privacy (P1-P8) --------
    {"id": "P1.1", "tsc": "P1", "category": "Privacy",
     "name": "Privacy notice and choice",
     "description": "Privacy notice is available to users; consent captured for personal data collection.",
     "iso27001": ["A.18.1.4"], "nist_csf": ["ID.GV-03"],
     "evidence_key": "privacy_notice",
     "rule": lambda ev, sys: bool(ev.get("privacy_notice", {}).get("published_url"))},
    {"id": "P4.2", "tsc": "P4", "category": "Privacy",
     "name": "Data retention and disposal",
     "description": "Data retention policy is documented and enforced; deletion is verifiable.",
     "iso27001": ["A.11.2.7"], "nist_csf": ["PR.IP-06"],
     "evidence_key": "data_retention",
     "rule": lambda ev, sys: bool(ev.get("data_retention", {}).get("policy_document"))
                              and ev.get("data_retention", {}).get("auto_delete_enabled") is True},
]


def _days_ago(iso_date: Optional[str]) -> int:
    if not iso_date:
        return 10**9
    try:
        d = datetime.fromisoformat(iso_date.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return max(0, (now - d).days)
    except Exception:
        return 10**9


# -------------------------------------------------------------
# Evidence loader
# -------------------------------------------------------------
def load_evidence(evidence_dir: Path) -> Dict[str, Any]:
    ev: Dict[str, Any] = {}
    if not evidence_dir.exists():
        return ev
    for p in evidence_dir.glob("*.json"):
        if p.name == "system.json":
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            key = p.stem
            ev[key] = data
        except Exception as e:
            print(f"[!] Bad evidence file {p}: {e}", file=sys.stderr)
    return ev


def load_system(evidence_dir: Path) -> Dict[str, Any]:
    sysfile = evidence_dir / "system.json"
    if sysfile.exists():
        try:
            return json.loads(sysfile.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


# -------------------------------------------------------------
# Control runner
# -------------------------------------------------------------
@dataclass
class Result:
    id: str
    name: str
    category: str
    tsc: str
    iso27001: List[str]
    nist_csf: List[str]
    description: str
    status: str  # PASS / FAIL / NO_EVIDENCE
    evidence_hash: str
    evidence_preview: str
    remediation: str = ""


SYSTEM_KEY_MAP = {
    "idp": ["sso_enforced"],
    "mfa": ["mfa_enforced", "mfa_coverage_pct"],
    "encryption": ["encryption_at_rest", "tls_min_version"],
    "edr": ["edr_coverage_pct"],
    "siem": ["siem_vendor", "alerting_rules"],
    "capacity_monitoring": ["capacity_alerting"],
}


def run_controls(ev: Dict, sys: Dict, filt: Optional[str]) -> List[Result]:
    out: List[Result] = []
    for c in CONTROLS:
        if filt and not c["id"].startswith(filt):
            continue
        ev_key = c["evidence_key"]
        in_ev = ev_key in ev
        sys_keys = SYSTEM_KEY_MAP.get(ev_key, [])
        in_sys = any(k in sys for k in sys_keys) if sys_keys else False
        have_ev = in_ev or in_sys
        if not have_ev:
            status = "NO_EVIDENCE"
            remediation = f"Upload {ev_key}.json to evidence/ with the required fields."
        else:
            try:
                ok = bool(c["rule"](ev, sys))
            except Exception:
                ok = False
            status = "PASS" if ok else "FAIL"
            remediation = "" if ok else _remediation_hint(c)

        evidence_blob = json.dumps({"sys": sys.get(ev_key), "ev": ev.get(ev_key)}, sort_keys=True)
        h = hashlib.sha256(evidence_blob.encode("utf-8")).hexdigest()[:16]

        out.append(Result(
            id=c["id"], name=c["name"], category=c["category"], tsc=c["tsc"],
            iso27001=c["iso27001"], nist_csf=c["nist_csf"],
            description=c["description"],
            status=status, evidence_hash=h,
            evidence_preview=(evidence_blob[:220]),
            remediation=remediation,
        ))
    return out


def _remediation_hint(c: dict) -> str:
    m = {
        "CC6.6": "Turn on MFA in your IdP; require for all users; coverage >=98%.",
        "CC6.7": "Enable AES-256 at rest on DBs/S3; enforce TLS 1.2+ on LBs.",
        "CC6.3": "Integrate IdP deprovisioning with HRIS termination event; target revoke-SLA <=24h.",
        "CC7.2": "Run weekly vuln scans; track open criticals in a dashboard; SLA 30 days.",
        "CC7.3": "Schedule IR tabletop exercise; update last_tabletop_date.",
        "A1.1":  "Run quarterly restore-from-backup test; record last_restore_test.",
    }
    return m.get(c["id"], "Review control description and collect supporting evidence.")


def build_summary(results):
    by_status = {"PASS": 0, "FAIL": 0, "NO_EVIDENCE": 0}
    by_cat = {}
    for r in results:
        by_status[r.status] = by_status.get(r.status, 0) + 1
        by_cat.setdefault(r.category, {"PASS": 0, "FAIL": 0, "NO_EVIDENCE": 0})
        by_cat[r.category][r.status] += 1
    total = len(results)
    passed = by_status["PASS"]
    score = round((passed / total) * 100, 1) if total else 0.0
    return {
        "tool": "SOC 2 Compliance Automation",
        "version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_controls": total,
        "by_status": by_status,
        "by_category": by_cat,
        "overall_score": score,
    }


def print_report(summary, results):
    print("=" * 60)
    print("  SOC 2 Compliance Automation v1.0")
    print("=" * 60)
    print(f"[*] Controls evaluated: {summary['total_controls']}")
    print(f"[*] Overall score     : {summary['overall_score']}%")
    print(f"[*] Status            : {summary['by_status']}")
    print()
    for r in sorted(results, key=lambda x: (x.status, x.id)):
        icon = {"PASS": "[+]", "FAIL": "[x]", "NO_EVIDENCE": "[?]"}[r.status]
        print(f"{icon} {r.id}  {r.category:<22} {r.name}")
        if r.status != "PASS":
            print(f"       {r.remediation}")


def cmd_list():
    print(f"{'ID':<8} {'TSC':<6} {'CATEGORY':<24} TITLE")
    print("-" * 100)
    for c in CONTROLS:
        print(f"{c['id']:<8} {c['tsc']:<6} {c['category']:<24} {c['name']}")


def cmd_map(fmt: str):
    if fmt == "csv":
        print("SOC2_ID,TSC,Category,Name,ISO27001,NIST_CSF")
        for c in CONTROLS:
            iso = " / ".join(c["iso27001"])
            nist = " / ".join(c["nist_csf"])
            print(f'{c["id"]},{c["tsc"]},"{c["category"]}","{c["name"]}","{iso}","{nist}"')
    else:
        print(json.dumps([{
            "soc2_id": c["id"], "tsc": c["tsc"], "category": c["category"],
            "name": c["name"], "iso27001": c["iso27001"], "nist_csf": c["nist_csf"],
        } for c in CONTROLS], indent=2))


def main():
    ap = argparse.ArgumentParser(description="SOC 2 Compliance Automation")
    sub = ap.add_subparsers(dest="cmd", required=True)

    spr = sub.add_parser("run", help="execute all controls")
    spr.add_argument("--evidence", default="evidence/", help="evidence directory")
    spr.add_argument("--tsc", default=None, help="filter by TSC prefix, e.g. CC6")
    spr.add_argument("--output", default="reports/soc2_report.json")
    spr.add_argument("--html", default="reports/soc2_report.html")

    sub.add_parser("list", help="list controls")
    spm = sub.add_parser("map", help="export SOC2 <-> ISO27001 <-> NIST CSF mapping")
    spm.add_argument("fmt", choices=["csv", "json"], default="csv", nargs="?")

    args = ap.parse_args()
    if args.cmd == "list":
        cmd_list(); return
    if args.cmd == "map":
        cmd_map(args.fmt); return

    # run
    evdir = Path(args.evidence)
    ev = load_evidence(evdir)
    sys_ = load_system(evdir)
    results = run_controls(ev, sys_, args.tsc)
    summary = build_summary(results)

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "controls": [asdict(r) for r in results]}, fh, indent=2)

    generate_html(summary, results, args.html)
    print_report(summary, results)
    print(f"\n[*] JSON report: {args.output}")
    print(f"[*] HTML report: {args.html}")


if __name__ == "__main__":
    try:
        from license_guard import verify_license
        verify_license()
    except Exception:
        pass
    main()
