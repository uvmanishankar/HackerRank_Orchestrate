from src.evaluation_workflow import compare_results
from src.evaluation_workflow import evaluate_sample_requests
from src.evidence_loader import EvidenceBundle


def test_comparison_reports_status_step_field_and_sequence_accuracy():
    expected = [
        {
            "case_id": "c-1",
            "deletion_status": "COMPLETE",
            "steps_json": (
                '[{"step_no":1,"phase":"VERIFICATION","system_id":"crm",'
                '"resource_id":"r-1","operation":"VERIFY_RECORD_ABSENT",'
                '"state":"ABSENT","evidence_id":"f-1"}]'
            ),
        }
    ]
    actual = [
        {
            "case_id": "c-1",
            "deletion_status": "COMPLETE",
            "steps": [
                {
                    "step_no": 1,
                    "phase": "VERIFICATION",
                    "system_id": "crm",
                    "resource_id": "r-1",
                    "operation": "VERIFY_RECORD_ABSENT",
                    "state": "ABSENT",
                    "evidence_id": "f-1",
                }
            ],
        }
    ]

    metrics = compare_results(actual, expected)

    assert metrics["cases"] == 1
    assert metrics["status_accuracy"] == 100
    assert metrics["row_accuracy"] == 100
    assert metrics["step_exact_accuracy"] == 100
    assert metrics["step_field_accuracy"] == 100
    assert metrics["sequence_accuracy"] == 100


def test_comparison_handles_missing_reference_matches():
    metrics = compare_results(
        [],
        [{"case_id": "c-1", "deletion_status": "INCOMPLETE", "steps_json": "[]"}],
    )
    assert metrics["status_accuracy"] == 0
    assert metrics["row_accuracy"] == 0
    assert metrics["sequence_accuracy"] == 0
    assert metrics["step_field_accuracy"] is None


def test_row_accuracy_requires_both_status_and_exact_steps():
    expected = [
        {
            "case_id": "c-1",
            "deletion_status": "COMPLETE",
            "steps_json": "[]",
        }
    ]
    actual = [
        {
            "case_id": "c-1",
            "deletion_status": "INCOMPLETE",
            "steps": [],
        }
    ]

    metrics = compare_results(actual, expected)

    assert metrics["status_accuracy"] == 0
    assert metrics["sequence_accuracy"] == 100
    assert metrics["row_accuracy"] == 0


def test_sample_evaluation_workflow_uses_supplied_reference_files(tmp_path):
    request_fields = [
        "case_id",
        "email",
        "requested_at",
        "reported_status",
        "reported_at",
        "audit_at",
        "request_text",
    ]
    with (tmp_path / "sample_deletion_requests.csv").open(
        "w", encoding="utf-8", newline=""
    ) as source:
        import csv

        writer = csv.DictWriter(source, fieldnames=request_fields)
        writer.writeheader()
        writer.writerow(
            {
                "case_id": "sample-1",
                "email": "one@example.test",
                "requested_at": "2026-01-01T00:00:00Z",
                "reported_status": "COMPLETE",
                "reported_at": "2026-01-02T00:00:00Z",
                "audit_at": "2026-01-03T00:00:00Z",
                "request_text": "Please delete my account.",
            }
        )
    with (tmp_path / "sample_output.csv").open(
        "w", encoding="utf-8", newline=""
    ) as source:
        import csv

        writer = csv.DictWriter(
            source,
            fieldnames=["case_id", "deletion_status", "steps_json"],
        )
        writer.writeheader()
        writer.writerow(
            {
                "case_id": "sample-1",
                "deletion_status": "INCOMPLETE",
                "steps_json": "[]",
            }
        )

    def expected_audit(request, **kwargs):
        return {
            "case_id": request["case_id"],
            "deletion_status": "INCOMPLETE",
            "steps": [],
        }

    metrics = evaluate_sample_requests(
        tmp_path,
        identities=[],
        audit_log=[],
        evidence=EvidenceBundle(),
        rules=[],
        audit_case=expected_audit,
    )

    assert metrics["status_accuracy"] == 100
    assert metrics["sequence_accuracy"] == 100
