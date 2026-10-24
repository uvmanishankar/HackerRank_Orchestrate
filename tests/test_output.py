import csv
import json

import pytest

from src.output_writer import validate_results, write_output
from src.remediation_planner import order_steps


def _step(phase, operation, state, evidence_id=""):
    return {
        "step_no": 1,
        "phase": phase,
        "operation": operation,
        "state": state,
        "system_id": "crm",
        "resource_id": "r-1",
        "evidence_id": evidence_id,
    }


def test_planner_sorts_by_phase_and_declared_operation_order():
    steps = [
        _step("REMEDIATION", "DELETE_RECORD", "ABSENT"),
        _step("FINDING", "REPORT_ACTIVE_DATA_FLOW", "ACTIVE", "activity-1"),
        _step("FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "file-1"),
    ]
    ordered = order_steps(steps)
    assert [step["operation"] for step in ordered] == [
        "REPORT_REMAINING_RECORD",
        "REPORT_ACTIVE_DATA_FLOW",
        "DELETE_RECORD",
    ]
    assert [step["step_no"] for step in ordered] == [1, 2, 3]


def test_output_writer_serializes_exact_columns_and_json(tmp_path):
    rows = [
        {
            "case_id": "case_1",
            "deletion_status": "COMPLETE",
            "steps": [
                _step(
                    "VERIFICATION",
                    "VERIFY_RECORD_ABSENT",
                    "ABSENT",
                    "file-1",
                )
            ],
        }
    ]
    path = tmp_path / "output.csv"
    write_output(rows, path, expected_case_ids=["case_1"])

    with path.open(encoding="utf-8", newline="") as file:
        reader = csv.DictReader(file)
        assert reader.fieldnames == ["case_id", "deletion_status", "steps_json"]
        written = next(reader)
    assert json.loads(written["steps_json"])[0]["evidence_id"] == "file-1"


def test_output_rejects_invalid_status_and_step_order():
    with pytest.raises(ValueError, match="Unsupported deletion status"):
        validate_results([{"case_id": "case_1", "deletion_status": "DONE", "steps": []}])

    steps = [
        _step("REMEDIATION", "DELETE_RECORD", "ABSENT"),
        _step("FINDING", "REPORT_REMAINING_RECORD", "PRESENT", "file-1"),
    ]
    steps[1]["step_no"] = 2
    with pytest.raises(ValueError, match="incorrectly ordered"):
        validate_results(
            [{"case_id": "case_1", "deletion_status": "INCOMPLETE", "steps": steps}]
        )


def test_steps_must_match_exact_required_fields():
    step = _step("VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", "file-1")
    step["unexpected"] = "not part of the submission schema"
    with pytest.raises(ValueError, match="required step schema"):
            validate_results(
                [
                    {
                        "case_id": "case_1",
                        "deletion_status": "COMPLETE",
                        "steps": [step],
                    }
                ]
            )


def test_not_applicable_must_have_no_steps():
    with pytest.raises(ValueError, match="must have no steps"):
        validate_results(
            [
                {
                    "case_id": "case_1",
                    "deletion_status": "NOT_APPLICABLE",
                    "steps": [
                        _step(
                            "VERIFICATION",
                            "VERIFY_RECORD_ABSENT",
                            "ABSENT",
                            "file-1",
                        )
                    ],
                }
            ]
        )