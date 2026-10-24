
import csv
import json
from pathlib import Path

if __package__:
    from .remediation_planner import (
        OPERATION_ORDER,
        OPERATION_PHASES,
        OPERATION_STATES,
        PHASE_ORDER,
    )
else:
    from remediation_planner import (
        OPERATION_ORDER,
        OPERATION_PHASES,
        OPERATION_STATES,
        PHASE_ORDER,
    )

OUTPUT_COLUMNS = [
    "case_id",
    "deletion_status",
    "steps_json",
]
ALLOWED_STATUSES = {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"}
STEP_FIELDS = {
    "step_no",
    "phase",
    "operation",
    "state",
    "system_id",
    "resource_id",
    "evidence_id",
}


def _step_sort_key(step):
    return (
        PHASE_ORDER[step["phase"]],
        OPERATION_ORDER[step["operation"]],
        str(step["system_id"]),
        str(step["resource_id"]),
        str(step["evidence_id"]),
    )


def validate_results(rows, expected_case_ids=None):
    rows = list(rows)
    case_ids = [str(row.get("case_id", "")) for row in rows]
    if any(not case_id for case_id in case_ids):
        raise ValueError("Every output row must have a case_id")
    if len(set(case_ids)) != len(case_ids):
        raise ValueError("Duplicate case_id values found in output")
    if expected_case_ids is not None:
        expected = {str(case_id) for case_id in expected_case_ids}
        actual = set(case_ids)
        if actual != expected:
            raise ValueError(
                "Output case IDs do not match inputs "
                f"(missing={sorted(expected - actual)}, "
                f"unexpected={sorted(actual - expected)})"
            )

    for row in rows:
        status = row.get("deletion_status")
        if status not in ALLOWED_STATUSES:
            raise ValueError(f"Unsupported deletion status: {status}")
        steps = row.get("steps")
        if not isinstance(steps, list):
            raise ValueError(f"steps must be a list for case {row['case_id']}")
        if status == "NOT_APPLICABLE" and steps:
            raise ValueError(
                f"NOT_APPLICABLE case {row['case_id']} must have no steps"
            )
        if status == "COMPLETE" and (
            not steps
            or any(step.get("phase") != "VERIFICATION" for step in steps)
        ):
            raise ValueError(
                f"COMPLETE case {row['case_id']} must contain verification steps only"
            )

        for expected_step_no, step in enumerate(steps, start=1):
            if set(step) != STEP_FIELDS:
                raise ValueError(
                    f"Step {expected_step_no} in case {row['case_id']} "
                    "does not match the required step schema"
                )
            missing = STEP_FIELDS - set(step)
            if missing:
                raise ValueError(
                    f"Step {expected_step_no} in case {row['case_id']} "
                    f"is missing fields: {sorted(missing)}"
                )
            if step["step_no"] != expected_step_no:
                raise ValueError(
                    f"Step numbers must be consecutive in case {row['case_id']}"
                )
            operation = step["operation"]
            if operation not in OPERATION_ORDER:
                raise ValueError(f"Unsupported operation: {operation}")
            if step["phase"] not in PHASE_ORDER:
                raise ValueError(f"Unsupported phase: {step['phase']}")
            if OPERATION_PHASES[operation] != step["phase"]:
                raise ValueError(
                    f"{operation} is not valid in {step['phase']} phase"
                )
            if step["state"] not in OPERATION_STATES[operation]:
                raise ValueError(
                    f"Invalid state for {operation}: {step['state']}"
                )
            if not all(
                isinstance(step[field], str)
                for field in ("system_id", "resource_id", "evidence_id")
            ):
                raise ValueError("Step identifiers must be strings")
            if (
                step["phase"] == "FINDING"
                and not step["evidence_id"]
            ):
                raise ValueError("Finding steps must cite supporting evidence")
            if (
                status == "INCOMPLETE"
                and step["phase"] in {"REMEDIATION", "VERIFICATION"}
                and step["evidence_id"]
            ):
                raise ValueError(
                    "Proposed remediation and verification steps must have an empty evidence_id"
                )
            if (
                status == "COMPLETE"
                and step["phase"] == "VERIFICATION"
                and not step["evidence_id"]
            ):
                raise ValueError(
                    "COMPLETE verification steps must reference supporting evidence"
                )
        if steps != sorted(steps, key=_step_sort_key):
            raise ValueError(f"Steps are incorrectly ordered for case {row['case_id']}")
    return rows


def write_output(rows, output_path: Path, expected_case_ids=None):
    rows = validate_results(rows, expected_case_ids)
    output_path.parent.mkdir(
        parents=True, exist_ok=True
    )

    ordered_rows = sorted(
        rows, key=lambda row: row["case_id"]
    )

    with output_path.open(
        "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=OUTPUT_COLUMNS,
        )
        writer.writeheader()

        for row in ordered_rows:
            writer.writerow({
                "case_id": row["case_id"],
                "deletion_status": row["deletion_status"],
                "steps_json": json.dumps(
                    row["steps"],
                    separators=(",", ":"),
                    ensure_ascii=False,
                ),
            })
