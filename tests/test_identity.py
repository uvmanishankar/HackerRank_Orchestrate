from src.identity_resolver import resolve_identity


def test_resolves_historical_email_and_all_supported_identifiers():
    identities = [
        {
            "user_id": "u-1",
            "email": "new@example.test",
            "phone": "555-0101",
            "email_hash": "hash-new",
        }
    ]
    audit_log = [
        {
            "user_id": "u-1",
            "old_email": "old@example.test",
            "new_email": "new@example.test",
            "old_phone": "555-0100",
            "old_email_hash": "hash-old",
        }
    ]

    resolved = resolve_identity("old@example.test", identities, audit_log)

    assert resolved["user_ids"] == {"u-1"}
    assert resolved["emails"] == {"old@example.test", "new@example.test"}
    assert resolved["phones"] == {"555-0100", "555-0101"}
    assert resolved["email_hashes"] == {"hash-old", "hash-new"}
    assert resolved["matched"] is True
    assert resolved["ambiguous"] is False


def test_does_not_link_unrelated_people_by_name():
    resolved = resolve_identity(
        "missing@example.test",
        [{"user_id": "u-1", "email": "other@example.test", "name": "Same Name"}],
        [{"user_id": "u-2", "email": "another@example.test", "name": "Same Name"}],
    )
    assert resolved["user_ids"] == set()
    assert resolved["emails"] == {"missing@example.test"}
    assert resolved["matched"] is False


def test_flags_an_email_linked_to_multiple_stable_users():
    resolved = resolve_identity(
        "shared@example.test",
        [
            {"user_id": "u-1", "email": "shared@example.test"},
            {"user_id": "u-2", "email": "shared@example.test"},
        ],
        [],
    )
    assert resolved["ambiguous"] is True
    assert resolved["user_ids"] == {"u-1", "u-2"}


def test_resolves_old_and_new_values_in_field_based_audit_log_as_of_time():
    resolved = resolve_identity(
        "old@example.test",
        [{"user_id": "u-1", "email": "new@example.test"}],
        [
            {
                "audit_id": "audit-1",
                "user_id": "u-1",
                "event_time": "2026-01-02T00:00:00Z",
                "field_name": "email",
                "old_value": "old@example.test",
                "new_value": "new@example.test",
            },
            {
                "audit_id": "audit-2",
                "user_id": "u-1",
                "event_time": "2026-01-04T00:00:00Z",
                "field_name": "email",
                "old_value": "new@example.test",
                "new_value": "future@example.test",
            },
        ],
        as_of="2026-01-03T00:00:00Z",
    )

    assert resolved["matched"] is True
    assert resolved["user_ids"] == {"u-1"}
    assert resolved["emails"] == {"old@example.test", "new@example.test"}
    assert "future@example.test" not in resolved["emails"]