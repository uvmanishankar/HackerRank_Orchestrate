import pytest

from src.policy_engine import evaluate_record, policy_for


@pytest.mark.parametrize(
    ("treatment", "state", "identifiers", "satisfied"),
    [
        ("DELETE", "deleted", (), True),
        ("DELETE", "present", (), False),
        ("REDACT", "redacted", (), True),
        ("REDACT", "redacted", ("email",), False),
        ("ANONYMIZE", "anonymized", (), True),
        ("RETAIN", "retained", (), True),
    ],
)
def test_policy_treatments_are_evaluated_from_rule(treatment, state, identifiers, satisfied):
    record = {"category": "profile", "state": state}
    rules = [{"category": "profile", "treatment": treatment}]
    if treatment == "RETAIN":
        record["user_id"] = "SIM-U1"
        rules[0]["allowed_identifiers"] = "user_id"
    result = evaluate_record(record, rules, identifiers)

    assert result["treatment"] == treatment
    assert result["satisfied"] is satisfied


def test_policy_matches_category_and_system_and_rejects_conflicts():
    record = {"category": "profile", "system_id": "crm"}
    assert policy_for(
        record,
        [
            {"category": "profile", "system_id": "crm", "treatment": "REDACT"},
            {"category": "profile", "system_id": "archive", "treatment": "RETAIN"},
        ],
    ) == "REDACT"
    assert policy_for(
        {"category": "profile"},
        [
            {"category": "profile", "treatment": "DELETE"},
            {"category": "profile", "treatment": "RETAIN"},
        ],
    ) is None


def test_missing_policy_is_an_unresolved_requirement():
    result = evaluate_record({"category": "profile", "state": "deleted"}, [])
    assert result["unresolved"] is True
    assert "No unambiguous" in result["reason"]


def test_retained_record_must_contain_only_rule_permitted_identifiers():
    rules = [
        {
            "category": "billing",
            "system_id": "ledger",
            "treatment": "RETAIN",
            "allowed_identifiers": "user_id",
        }
    ]
    allowed = evaluate_record(
        {
            "category": "billing",
            "system_id": "ledger",
            "state": "retained",
            "user_id": "SIM-U1",
        },
        rules,
    )
    disallowed = evaluate_record(
        {
            "category": "billing",
            "system_id": "ledger",
            "state": "retained",
            "user_id": "SIM-U1",
            "email": "person@example.test",
        },
        rules,
    )

    assert allowed["satisfied"] is True
    assert disallowed["unresolved"] is True