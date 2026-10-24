from collections.abc import Mapping
from datetime import datetime, timezone

EMAIL_FIELDS = ("email", "email_address", "old_email", "new_email")
USER_ID_FIELDS = ("user_id", "customer_id", "subject_id", "account_id")
PHONE_FIELDS = ("phone", "phone_number", "mobile", "old_phone", "new_phone")
HASH_FIELDS = ("email_hash", "hashed_email", "old_email_hash", "new_email_hash")
TIMESTAMP_FIELDS = (
    "timestamp",
    "event_at",
    "event_time",
    "activity_at",
    "created_at",
    "updated_at",
    "occurred_at",
    "recorded_at",
)


def _records(rows):
    if rows is None:
        return []
    if hasattr(rows, "to_dict"):
        return rows.to_dict("records")
    if isinstance(rows, Mapping):
        return [rows]
    return list(rows)


def _normalized_row(row):
    return {
        str(key).strip().casefold(): value
        for key, value in row.items()
        if key is not None
    }


def _values(row, aliases):
    normalized = _normalized_row(row)
    return {
        str(normalized[alias.casefold()]).strip()
        for alias in aliases
        if normalized.get(alias.casefold()) is not None
        and str(normalized[alias.casefold()]).strip()
    }


def _email_values(row):
    return {value.casefold() for value in _values(row, EMAIL_FIELDS)}


def _user_id_values(row):
    return _values(row, USER_ID_FIELDS)


def _audit_values(row, field_name):
    normalized = _normalized_row(row)
    if str(normalized.get("field_name", "")).strip().casefold() != field_name:
        return set()
    return {
        str(normalized[key]).strip()
        for key in ("old_value", "new_value")
        if normalized.get(key) is not None and str(normalized[key]).strip()
    }


def _row_identifier_values(row, aliases, audit_field):
    return _values(row, aliases) | _audit_values(row, audit_field)


def _parse_datetime(value):
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _filter_as_of(rows, as_of, source_name, gaps):
    if not as_of:
        return rows
    cutoff = _parse_datetime(as_of)
    if cutoff is None:
        gaps.append(f"Invalid audit timestamp for {source_name}.")
        return []
    filtered = []
    for row in rows:
        normalized = _normalized_row(row)
        timestamp = next(
            (
                normalized[field]
                for field in TIMESTAMP_FIELDS
                if normalized.get(field)
            ),
            None,
        )
        if timestamp is None:
            gaps.append(
                f"Identity history row has no timestamp and cannot be placed at audit time."
            )
            filtered.append(row)
            continue
        parsed = _parse_datetime(timestamp)
        if parsed is None:
            gaps.append(
                f"Identity history row has an invalid timestamp in {source_name}."
            )
            continue
        if parsed <= cutoff:
            filtered.append(row)
    return filtered


def resolve_identity(request_email, user_identities, user_audit_log, as_of=None):
    request_email = (request_email or "").strip().casefold()
    identity_rows = _records(user_identities)
    history_gaps = []
    audit_rows = _filter_as_of(
        _records(user_audit_log), as_of, "user_audit_log", history_gaps
    )

    result = {
        "user_ids": set(),
        "emails": {request_email} if request_email else set(),
        "phones": set(),
        "email_hashes": set(),
        "matched": False,
        "ambiguous": False,
        "history_gaps": history_gaps,
    }

    historical_email_rows = [
        row
        for row in audit_rows
        if request_email
        in {
            value.casefold()
            for value in _audit_values(row, "email")
        }
    ]
    direct_rows = [
        row for row in identity_rows if request_email in _email_values(row)
    ]
    result["matched"] = bool(direct_rows or historical_email_rows) or any(
        request_email in _email_values(row) for row in audit_rows
    )
    for row in direct_rows:
        result["user_ids"].update(_user_id_values(row))
        result["emails"].update(_email_values(row))
        result["phones"].update(_values(row, PHONE_FIELDS))
        result["email_hashes"].update(_values(row, HASH_FIELDS))

    if request_email:
        changed = True
        while changed:
            changed = False
            for row in audit_rows:
                row_users = _user_id_values(row)
                row_emails = _row_identifier_values(row, EMAIL_FIELDS, "email")
                row_phones = _row_identifier_values(row, PHONE_FIELDS, "phone")
                row_hashes = _row_identifier_values(row, HASH_FIELDS, "email_hash")
                linked = bool(row_users & result["user_ids"]) or bool(
                    {value.casefold() for value in row_emails} & result["emails"]
                )
                if not linked:
                    continue
                before = (
                    len(result["user_ids"]),
                    len(result["emails"]),
                    len(result["phones"]),
                    len(result["email_hashes"]),
                )
                result["user_ids"].update(row_users)
                result["emails"].update(value.casefold() for value in row_emails)
                result["phones"].update(row_phones)
                result["email_hashes"].update(row_hashes)
                changed |= before != (
                    len(result["user_ids"]),
                    len(result["emails"]),
                    len(result["phones"]),
                    len(result["email_hashes"]),
                )

            for row in identity_rows:
                linked = bool(_user_id_values(row) & result["user_ids"]) or bool(
                    _email_values(row) & result["emails"]
                )
                if not linked:
                    continue
                before = (
                    len(result["user_ids"]),
                    len(result["emails"]),
                    len(result["phones"]),
                    len(result["email_hashes"]),
                )
                result["user_ids"].update(_user_id_values(row))
                result["emails"].update(_email_values(row))
                result["phones"].update(_values(row, PHONE_FIELDS))
                result["email_hashes"].update(_values(row, HASH_FIELDS))
                changed |= before != (
                    len(result["user_ids"]),
                    len(result["emails"]),
                    len(result["phones"]),
                    len(result["email_hashes"]),
                )

    result["ambiguous"] = len(result["user_ids"]) > 1
    return result
