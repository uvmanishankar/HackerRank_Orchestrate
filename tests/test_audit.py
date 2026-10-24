from src.audit_engine import (
    NEGATIVE_REQUEST,
    _artifact_record,
    audit_case,
    classify_deletion,
)
from src.evidence_loader import EvidenceBundle
from src.main import load_requests


def _request(text="Please delete my account and personal data."):
    return {
        "case_id": "case_1",
        "email": "one@example.test",
        "audit_at": "2026-01-03T00:00:00Z",
        "request_text": text,
    }


def test_not_requested_returns_no_steps():
    result = audit_case(
        _request("I do not request deletion."),
        identities=[],
        audit_log=[],
        evidence=EvidenceBundle(),
        rules=[],
    )
    assert result["deletion_status"] == "NOT_APPLICABLE"
    assert result["steps"] == []


def test_missing_sources_never_claim_completion_and_report_gap():
    result = audit_case(
        _request(),
        identities=[],
        audit_log=[],
        evidence=EvidenceBundle(
            tables={},
            gaps=["Identity source is empty.", "No evidence manifest."],
        ),
        rules=[],
    )
    assert result["deletion_status"] == "INCOMPLETE"
    assert result["steps"] == []


def test_complete_requires_sufficient_evidence_and_no_unresolved_requirements():
    assert classify_deletion(True, [], True) == "COMPLETE"
    assert classify_deletion(True, ["missing evidence"], True) == "INCOMPLETE"
    assert classify_deletion(True, [], False) == "INCOMPLETE"
    assert classify_deletion(False, ["anything"], False) == "NOT_APPLICABLE"


def test_complete_case_has_evidence_linked_verification_only():
    identity_row = {
        "user_id": "u-1",
        "email": "one@example.test",
    }
    evidence = EvidenceBundle(
        tables={
            "user_identities": [identity_row],
            "user_audit_log": [],
            "system_activity": [],
            "deletion_rules": [],
            "evidence_files": [],
        },
        artifacts=[
            {
                "file_id": "file-1",
                "path": "profile.json",
                "records": [
                    {
                        "user_id": "u-1",
                        "email": "one@example.test",
                        "category": "profile",
                        "state": "deleted",
                        "system_id": "crm",
                        "resource_id": "r-1",
                        "recorded_at": "2026-01-02T00:00:00Z",
                    }
                ],
            }
        ],
    )
    result = audit_case(
        _request(),
        identities=[identity_row],
        audit_log=[],
        evidence=evidence,
        rules=[{"category": "profile", "treatment": "DELETE"}],
    )

    assert result["deletion_status"] == "COMPLETE"
    assert len(result["steps"]) == 1
    assert result["steps"][0]["phase"] == "VERIFICATION"
    assert result["steps"][0]["evidence_id"] == "file-1"


def test_retained_audit_record_alone_cannot_prove_primary_account_deletion():
    identity = {"user_id": "u-1", "email": "one@example.test"}
    evidence = EvidenceBundle(
        tables={
            "user_identities": [identity],
            "user_audit_log": [],
            "system_activity": [],
            "deletion_rules": [],
            "evidence_files": [],
        },
        artifacts=[
            {
                "file_id": "audit-file",
                "path": "audit.json",
                "records": [
                    {
                        "user_id": "u-1",
                        "category": "SECURITY_AUDIT_LOG",
                        "system_id": "security_service",
                        "resource_id": "audit-1",
                        "record_state": "RETAINED",
                        "retention_until": "2030-01-01T00:00:00Z",
                        "recorded_at": "2026-01-02T00:00:00Z",
                    }
                ],
            }
        ],
    )

    result = audit_case(
        _request(),
        identities=[identity],
        audit_log=[],
        evidence=evidence,
        rules=[
            {
                "category": "SECURITY_AUDIT_LOG",
                "treatment": "RETAIN",
                "condition": "Record is within the supplied retention period",
                "allowed_identifiers": "user_id",
            }
        ],
    )

    assert result["deletion_status"] == "INCOMPLETE"


def test_retained_record_with_prohibited_email_gets_redaction_plan():
    identity = {"user_id": "u-1", "email": "one@example.test"}
    evidence = EvidenceBundle(
        tables={
            "user_identities": [identity],
            "user_audit_log": [],
            "system_activity": [],
            "deletion_rules": [],
            "evidence_files": [],
        },
        artifacts=[
            {
                "file_id": "file-1",
                "path": "snapshot.json",
                "records": [
                    {
                        "user_id": "u-1",
                        "email": "one@example.test",
                        "category": "billing",
                        "system_id": "ledger",
                        "resource_id": "r-1",
                        "state": "retained",
                        "recorded_at": "2026-01-02T00:00:00Z",
                    }
                ],
            }
        ],
    )
    result = audit_case(
        _request(),
        identities=[identity],
        audit_log=[],
        evidence=evidence,
        rules=[
            {
                "category": "billing",
                "system_id": "ledger",
                "treatment": "RETAIN",
                "allowed_identifiers": "user_id",
            }
        ],
    )

    assert result["deletion_status"] == "INCOMPLETE"
    assert [step["operation"] for step in result["steps"]] == [
        "REPORT_EXPOSED_PII",
        "REDACT_RECORD",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
    ]
    assert all(
        not step["evidence_id"]
        for step in result["steps"]
        if step["phase"] != "FINDING"
    )


def test_contact_lookup_rows_are_treated_as_a_remaining_identifier():
    normalized = _artifact_record(
        {
            "service": "analytics_platform",
            "event": "contact_lookup_completed",
            "resource_id": "contact-1",
            "rows": "1",
            "correlation_key": "hash-value",
        }
    )

    assert normalized["category"] == "SECONDARY_IDENTIFIER"
    assert normalized["record_state"] == "PRESENT"


def test_nested_profile_lookup_metadata_identifies_system_and_absence():
    normalized = _artifact_record(
        {
            "__source_path": "service_exports.account_service.profile_lookups",
            "resource_id": "account-1",
            "status_code": 404,
        }
    )

    assert normalized["system_id"] == "account_service"
    assert normalized["category"] == "USER_PROFILE"
    assert normalized["record_state"] == "NOT_FOUND"


def test_supplied_multilingual_deletion_requests_are_not_marked_na():
    requests = load_requests()
    assert len(requests) == 518
    non_requests = [
        request
        for request in requests
        if NEGATIVE_REQUEST.search(request["request_text"])
    ]
    assert len(non_requests) == 1
    result = audit_case(
        non_requests[0],
        identities=[],
        audit_log=[],
        evidence=EvidenceBundle(),
        rules=[],
    )
    assert result["deletion_status"] == "NOT_APPLICABLE"
    assert result["steps"] == []
