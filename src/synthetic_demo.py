import csv
from collections import Counter
from pathlib import Path

if __package__:
    from .audit_engine import audit_case
    from .config import ROOT
    from .evidence_loader import load_evidence
    from .output_writer import write_output
else:
    from audit_engine import audit_case
    from config import ROOT
    from evidence_loader import load_evidence
    from output_writer import write_output

SYNTHETIC_DIR = ROOT / "dataset" / "synthetic"
OUTPUT_PATH = ROOT / "simulated_output.csv"
REPORT_PATH = ROOT / "evaluation" / "synthetic_evaluation_report.md"


def _read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def run_synthetic_demo(output_path=OUTPUT_PATH, report_path=REPORT_PATH):
    requests = _read_csv(SYNTHETIC_DIR / "deletion_requests.csv")
    identity_rows = _read_csv(SYNTHETIC_DIR / "user_identities.csv")
    audit_rows = _read_csv(SYNTHETIC_DIR / "user_audit_log.csv")
    evidence = load_evidence(SYNTHETIC_DIR)
    results = [
        audit_case(
            request,
            identities=identity_rows,
            audit_log=audit_rows,
            evidence=evidence,
            rules=evidence.tables["deletion_rules"],
        )
        for request in requests
    ]
    write_output(
        results,
        Path(output_path),
        expected_case_ids=[request["case_id"] for request in requests],
    )

    counts = Counter(result["deletion_status"] for result in results)
    report_path = Path(report_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SYNTHETIC SIMULATION — NOT VERIFIED FINDINGS",
        "",
        "> Every identity, record, activity, policy, and result in this report is fictional. "
        "These simulated cases are not derived from or evidence about the supplied 518 requests.",
        "",
        "## Run summary",
        "",
        f"- Synthetic scenarios: {len(results)}",
        f"- Status counts: {dict(sorted(counts.items()))}",
        f"- Simulated output: `{Path(output_path).name}`",
        "- This is a functional simulation, not an independent ground-truth accuracy measurement.",
        "",
        "## Scenario results",
        "",
        "| Synthetic case | Scenario | Result | Steps |",
        "|---|---|---|---:|",
    ]
    for result in results:
        case_id = result["case_id"]
        request = next(
            request for request in requests if request["case_id"] == case_id
        )
        lines.append(
            f"| {case_id} | {request.get('scenario', 'Synthetic audit scenario')} | "
            f"{result['deletion_status']} | "
            f"{len(result['steps'])} |"
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "These scenarios exercise identity history, record deletion, retention, active sync/restore risks, and a non-request. The case-to-scenario mapping comes from the fixture CSV, not from case-specific decision logic.",
            "",
            "All steps and statuses in `simulated_output.csv` are demonstrations against fabricated test fixtures only. Do not represent them as findings about actual users or the supplied request CSV.",
            "",
            "## Fixture evidence gaps",
            "",
        ]
    )
    lines.extend(f"- {gap}" for gap in evidence.gaps)
    if not evidence.gaps:
        lines.append("- None in this synthetic fixture.")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return results


def main():
    results = run_synthetic_demo()
    print("SYNTHETIC SIMULATION ONLY - NOT VERIFIED REAL-WORLD FINDINGS")
    print(f"Cases: {len(results)}")
    print(f"Simulated output: {OUTPUT_PATH}")
    print(f"Simulated report: {REPORT_PATH}")


if __name__ == "__main__":
    main()
