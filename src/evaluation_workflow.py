import csv
import json
from pathlib import Path


STEP_FIELDS = (
    "step_no",
    "phase",
    "system_id",
    "resource_id",
    "operation",
    "state",
    "evidence_id",
)


def _read_rows(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as source:
        return list(csv.DictReader(source))


def compare_results(actual_rows, expected_rows):
    actual = {str(row["case_id"]): row for row in actual_rows}
    expected = {str(row["case_id"]): row for row in expected_rows}
    case_ids = sorted(expected)
    if not case_ids:
        return {
            "cases": 0,
            "status_accuracy": None,
            "row_accuracy": None,
            "step_exact_accuracy": None,
            "step_field_accuracy": None,
            "sequence_accuracy": None,
        }

    status_correct = 0
    row_correct = 0
    sequence_correct = 0
    exact_steps = 0
    expected_step_count = 0
    matching_step_count = 0
    field_correct = 0
    field_total = 0
    for case_id in case_ids:
        expected_row = expected[case_id]
        actual_row = actual.get(case_id)
        if actual_row is None:
            expected_steps = json.loads(expected_row.get("steps_json", "[]"))
            expected_step_count += len(expected_steps)
            field_total += sum(len(step) for step in expected_steps)
            continue
        expected_steps = json.loads(expected_row.get("steps_json", "[]"))
        actual_steps = actual_row.get("steps", [])
        if isinstance(actual_steps, str):
            actual_steps = json.loads(actual_steps)
        status_matches = (
            actual_row["deletion_status"] == expected_row["deletion_status"]
        )
        if status_matches:
            status_correct += 1
        if status_matches and actual_steps == expected_steps:
            row_correct += 1
        if actual_steps == expected_steps:
            sequence_correct += 1

        aligned = min(len(actual_steps), len(expected_steps))
        expected_step_count += len(expected_steps)
        for index in range(aligned):
            expected_step = expected_steps[index]
            actual_step = actual_steps[index]
            if actual_step == expected_step:
                exact_steps += 1
            for field in STEP_FIELDS:
                field_total += 1
                if actual_step.get(field) == expected_step.get(field):
                    field_correct += 1
        matching_step_count += aligned
        field_total += (len(expected_steps) - aligned) * len(STEP_FIELDS)

    def percentage(correct, total):
        return round(correct / total * 100, 2) if total else None

    return {
        "cases": len(case_ids),
        "status_accuracy": percentage(status_correct, len(case_ids)),
        "row_accuracy": percentage(row_correct, len(case_ids)),
        "step_exact_accuracy": percentage(exact_steps, expected_step_count),
        "step_field_accuracy": percentage(field_correct, field_total),
        "sequence_accuracy": percentage(sequence_correct, len(case_ids)),
        "expected_steps": expected_step_count,
        "aligned_steps": matching_step_count,
    }


def evaluate_sample_requests(
    dataset_dir,
    identities,
    audit_log,
    evidence,
    rules,
    audit_case,
):
    dataset_dir = Path(dataset_dir)
    request_path = next(
        (
            path
            for path in (
                dataset_dir / "sample_deletion_requests.csv",
                dataset_dir / "evidence" / "sample_deletion_requests.csv",
            )
            if path.is_file()
        ),
        None,
    )
    output_path = next(
        (
            path
            for path in (
                dataset_dir / "sample_output.csv",
                dataset_dir / "evidence" / "sample_output.csv",
            )
            if path.is_file()
        ),
        None,
    )
    if request_path is None or output_path is None:
        return None

    requests = _read_rows(request_path)
    expected = _read_rows(output_path)
    actual = [
        audit_case(
            request,
            identities=identities,
            audit_log=audit_log,
            evidence=evidence,
            rules=rules,
        )
        for request in requests
    ]
    return compare_results(actual, expected)
