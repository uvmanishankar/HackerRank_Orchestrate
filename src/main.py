
import csv
import json
import zipfile
from datetime import datetime
from pathlib import Path

if __package__:
    from .audit_engine import audit_case
    from .config import DATASET_DIR, EVALUATION_DIR, EVIDENCE_DIR, OUTPUT_PATH, ROOT
    from .evidence_loader import load_evidence
    from .evaluation_workflow import evaluate_sample_requests
    from .output_writer import write_output
else:
    from audit_engine import audit_case
    from config import DATASET_DIR, EVALUATION_DIR, EVIDENCE_DIR, OUTPUT_PATH, ROOT
    from evidence_loader import load_evidence
    from evaluation_workflow import evaluate_sample_requests
    from output_writer import write_output

REQUIRED_COLUMNS = (
    "case_id",
    "email",
    "requested_at",
    "reported_status",
    "reported_at",
    "audit_at",
    "request_text",
)


def load_requests():
    paths = (
        EVIDENCE_DIR / "deletion_requests.csv",
        ROOT / "dataset" / "deletion_requests.csv",
    )
    path = next((candidate for candidate in paths if candidate.is_file()), None)
    if path is None:
        raise FileNotFoundError(
            "Missing deletion requests file; checked "
            + ", ".join(str(candidate) for candidate in paths)
        )

    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise ValueError(f"Input file has no header: {path}")
        missing = set(REQUIRED_COLUMNS) - set(reader.fieldnames)
        if missing:
            raise ValueError(f"Missing required columns: {sorted(missing)}")
        requests = list(reader)

    seen = set()
    for row_number, request in enumerate(requests, start=2):
        case_id = request["case_id"].strip()
        if not case_id:
            raise ValueError(f"Empty case_id at row {row_number}")
        if case_id in seen:
            raise ValueError(f"Duplicate case_id value: {case_id}")
        seen.add(case_id)
        for column in ("requested_at", "reported_at", "audit_at"):
            try:
                datetime.fromisoformat(
                    request[column].strip().replace("Z", "+00:00")
                )
            except ValueError as error:
                raise ValueError(
                    f"Invalid timestamp in {column} at row {row_number}"
                ) from error
    return sorted(requests, key=lambda row: row["case_id"])


def _write_evaluation(rows, evidence_gaps, sample_metrics):
    counts = {}
    for row in rows:
        counts[row["deletion_status"]] = (
            counts.get(row["deletion_status"], 0) + 1
        )

    EVALUATION_DIR.mkdir(parents=True, exist_ok=True)
    evaluation = [
        "# Evaluation report",
        "",
        "## Run summary",
        "",
        f"- Cases audited: {len(rows)}",
        f"- Status counts: {json.dumps(counts, sort_keys=True)}",
        (
            "- Ground-truth sample output: available for comparison."
            if sample_metrics
            else "- Ground-truth sample output: not supplied; accuracy cannot be measured."
        ),
        "- Evaluation uses the supplied source data only; no status is inferred from `reported_status`.",
        "",
        "## Evidence limitations",
        "",
    ]
    evaluation.extend(f"- {gap}" for gap in evidence_gaps)
    if not evidence_gaps:
        evaluation.append("- None reported.")
    evaluation.extend(
        [
            "",
            "## Accuracy metrics",
            "",
        ]
    )
    if sample_metrics:
        evaluation.extend(
            [
                f"- Evaluation sample size: {sample_metrics['cases']} cases.",
                f"- Case/status accuracy: {sample_metrics['status_accuracy']}% "
                "(correct deletion_status / sample cases).",
                f"- Exact output-row accuracy: {sample_metrics['row_accuracy']}% "
                "(status and complete steps_json array both match).",
                f"- Exact step accuracy: {sample_metrics['step_exact_accuracy']}% "
                "(exact step objects / expected steps).",
                f"- Step-field accuracy: {sample_metrics['step_field_accuracy']}% "
                "(matching required step fields / expected step fields).",
                f"- Sequence accuracy: {sample_metrics['sequence_accuracy']}% "
                "(exact ordered steps_json arrays / sample cases).",
                f"- Expected reference steps: {sample_metrics['expected_steps']}; "
                f"positionally aligned actual steps: {sample_metrics['aligned_steps']}.",
            ]
        )
    else:
        evaluation.extend(
            [
                "- Case/status accuracy: not measurable; no canonical sample answers were supplied.",
                "- Exact output-row accuracy: not measurable without canonical answers.",
                "- Exact step and step-field accuracy: not measurable without canonical answers.",
                "- Sequence accuracy: not measurable without canonical answers.",
            ]
        )
    evaluation.extend(
        [
            "",
            "## Additional team evaluation cases",
            "",
            "| Case | Expected behavior |",
            "|---|---|",
            "| Synthetic deleted record | COMPLETE with evidence-backed absence verification |",
            "| Synthetic record still present | INCOMPLETE with ordered delete and verification plan |",
            "| Synthetic retained record | COMPLETE only when permitted identifiers remain |",
            "| Synthetic active sync | INCOMPLETE with disable-flow and verification steps |",
            "| Synthetic active restore | INCOMPLETE with block-restore and verification steps |",
            "| Synthetic non-request | NOT_APPLICABLE with an empty steps array |",
            "",
            "These are fictional scenarios from `dataset/synthetic/`; they are not findings about supplied requests.",
            "",
            "## Failures found",
            "",
        ]
    )
    if sample_metrics:
        evaluation.extend(
            [
                f"- The {sample_metrics['cases']}-case canonical sample scored "
                f"{sample_metrics['row_accuracy']}% exact output-row accuracy; "
                f"{sample_metrics['sequence_accuracy']}% of ordered step sequences matched.",
                f"- Exact step accuracy was {sample_metrics['step_exact_accuracy']}% "
                f"and required step-field accuracy was {sample_metrics['step_field_accuracy']}%; "
                f"only {sample_metrics['aligned_steps']} of "
                f"{sample_metrics['expected_steps']} expected steps aligned by position.",
                "- These sample mismatches show the current discovery and remediation planning do not yet reproduce the reference answers; passing unit tests is not evidence of hidden-set accuracy.",
            ]
        )
    else:
        evaluation.append(
            "- No canonical sample answers were available to identify answer-level failures."
        )
    if evidence_gaps:
        evaluation.append(
            f"- The run reported {len(evidence_gaps)} source/evidence ingestion gaps; these limit verification."
        )
    else:
        evaluation.append(
            "- No source-level evidence ingestion gaps were detected; per-case evidence sufficiency is still checked independently."
        )
    evaluation.extend(
        [
            "",
            "## Improvements made",
            "",
            "- Added strict allowed phase/operation/state and exact output-step schema validation.",
            "- Added manifest and recursive local evidence ingestion for structured files, logs, PDFs, SQLite snapshots, and OCR-capable images.",
            "- Preserved nested JSON service context and interpreted structured lookup results and contact-lookup rows using their observed states.",
            "- Used record-level observation timestamps ahead of manifest export time, with manifest capture time as a fallback for untimestamped records.",
            "- Removed unsupported numeric user/resource-ID suffix inference so it cannot fabricate absence findings.",
            "- Required identity-linked primary-profile evidence before declaring the deletion complete.",
            "- Resolved uniquely matching evidence files nested below an additional directory when their manifest-relative path was not present directly.",
            "- Accepted the supplied SQL snapshot foreign-key pragma and trailing metadata comments while continuing to reject unsupported SQL statements.",
            "- Added optional canonical sample comparison for case status, step fields, and sequence.",
            "- Evaluation reports case/status, exact output-row, exact-step, step-field, and ordered-sequence metrics separately; sample metrics do not represent hidden-set accuracy.",
            "",
        ]
    )
    evaluation.extend(
        [
            "- Verified request timestamps and unique case identifiers.",
            "- Tested missing identity, policy, and evidence sources as evidence gaps.",
            "- Tested CSV/JSON/log/SQLite/PDF evidence ingestion and audit-time filtering.",
            "- Tested output JSON, status, exact fields, operation/state, and step-order validation.",
        ]
    )
    (EVALUATION_DIR / "evaluation_report.md").write_text(
        "\n".join(evaluation) + "\n", encoding="utf-8"
    )
    return counts


def _write_usage_report(case_count, artifact_count):
    run_timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    request_count = case_count
    total_tokens = 0
    total_cost = 0.0
    average_tokens = total_tokens / request_count if request_count else 0
    average_cost = total_cost / request_count if request_count else 0.0
    usage = [
        "# Full-dataset model usage report",
        "",
        "## Run scope",
        "",
        f"- Run timestamp: {run_timestamp}",
        f"- Dataset requests processed: {request_count}",
        f"- Local evidence artifacts loaded: {artifact_count}",
        "- Run type: deterministic, offline audit; no generative model was invoked.",
        "",
        "## Provider and model usage",
        "",
        "| Provider | Model | Calls | Input tokens | Output tokens | Total tokens | Estimated cost (USD) |",
        "|---|---|---:|---:|---:|---:|---:|",
        "| None (offline) | None | 0 | 0 | 0 | 0 | $0.00 |",
        "",
        "## Per-model and overall totals",
        "",
        "| Scope | Calls | Input tokens | Output tokens | Total tokens | Average input tokens per request | Average output tokens per request | Average total tokens per request | Estimated total cost (USD) | Estimated cost per request (USD) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| Offline pipeline / overall | 0 | 0 | 0 | {total_tokens} | 0.00 | 0.00 | {average_tokens:.2f} | ${total_cost:.2f} | ${average_cost:.4f} |",
        "",
        "Token counts and model costs are zero because this full-dataset run used no model provider or API calls. Per-request averages divide the totals by all requests processed.",
    ]
    (EVALUATION_DIR / "usage_report.md").write_text(
        "\n".join(usage) + "\n", encoding="utf-8"
    )


def _package_project():
    package_path = ROOT / "code.zip"
    include = [
        ROOT / "README.md",
        ROOT / "requirements.txt",
        ROOT / ".env.example",
        ROOT / "src",
        ROOT / "tests",
        EVALUATION_DIR,
        ROOT / "dataset" / "synthetic",
        ROOT / "simulated_output.csv",
    ]
    with zipfile.ZipFile(
        package_path, "w", compression=zipfile.ZIP_DEFLATED
    ) as archive:
        for path in include:
            if path.is_file():
                archive.write(
                    path,
                    Path("code") / path.relative_to(ROOT),
                )
            elif path.is_dir():
                for file_path in sorted(path.rglob("*")):
                    if file_path.is_file() and "__pycache__" not in file_path.parts:
                        archive.write(
                            file_path,
                            Path("code") / file_path.relative_to(ROOT),
                        )
    return package_path


def main():
    requests = load_requests()
    evidence = load_evidence(DATASET_DIR)
    rules = evidence.tables["deletion_rules"]
    identity_rows = evidence.tables["user_identities"]
    audit_rows = evidence.tables["user_audit_log"]
    results = [
        audit_case(
            request,
            identities=identity_rows,
            audit_log=audit_rows,
            evidence=evidence,
            rules=rules,
        )
        for request in requests
    ]
    sample_metrics = evaluate_sample_requests(
        DATASET_DIR,
        identity_rows,
        audit_rows,
        evidence,
        rules,
        audit_case,
    )
    write_output(
        results,
        OUTPUT_PATH,
        expected_case_ids=[request["case_id"] for request in requests],
    )
    _write_evaluation(results, evidence.gaps, sample_metrics)
    _write_usage_report(len(requests), len(evidence.artifacts))
    package_path = _package_project()

    print(f"Audited {len(results)} cases.")
    print(
        "Status counts: "
        + json.dumps(
            {
                status: sum(
                    row["deletion_status"] == status for row in results
                )
                for status in ("COMPLETE", "INCOMPLETE", "NOT_APPLICABLE")
            },
            sort_keys=True,
        )
    )
    print(f"Output: {OUTPUT_PATH}")
    print(f"Evaluation: {EVALUATION_DIR}")
    print(f"Package: {package_path}")
    if evidence.gaps:
        print("Evidence gaps:")
        for gap in evidence.gaps:
            print(f"- {gap}")


if __name__ == "__main__":
    main()
