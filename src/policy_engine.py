from collections.abc import Mapping

TREATMENTS = {"DELETE", "REDACT", "ANONYMIZE", "RETAIN"}
CATEGORY_FIELDS = (
    "category",
    "data_category",
    "record_type",
    "data_type",
)
SYSTEM_FIELDS = ("system_id", "system", "system_name")
TREATMENT_FIELDS = (
    "treatment",
    "required_treatment",
    "required_action",
    "action",
    "disposition",
)
ALLOWED_IDENTIFIER_FIELDS = (
    "allowed_identifiers",
    "permitted_identifiers",
    "retain_identifiers",
)
PERSONAL_IDENTIFIER_FIELDS = {
    "email",
    "email_address",
    "old_email",
    "new_email",
    "phone",
    "phone_number",
    "mobile",
    "email_hash",
    "hashed_email",
    "name",
    "first_name",
    "last_name",
    "full_name",
    "address",
}
CONDITION_FIELDS = ("condition", "rule_condition", "when")


def _records(rows):
    if rows is None:
        return []
    if hasattr(rows, "to_dict"):
        return rows.to_dict("records")
    if isinstance(rows, Mapping):
        return [rows]
    return list(rows)


def _get(row, aliases):
    normalized = {str(key).strip().casefold(): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(alias.casefold())
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _condition_applies(record, condition):
    condition = (condition or "").strip()
    if not condition or condition.casefold() == "always":
        return True
    normalized_condition = condition.casefold()
    normalized_record = {
        str(key).strip().casefold(): str(value).strip()
        for key, value in record.items()
        if value is not None
    }
    context = " ".join(
        normalized_record.values()
    ).casefold()
    if normalized_condition in context:
        return True
    if normalized_condition == "record is still attributable to a user":
        if (
            normalized_record.get("category", "").casefold()
            in {"analytics_profile", "product_telemetry"}
            and normalized_record.get("record_state", "").casefold()
            in {"anonymized", "anonymised", "deidentified"}
        ):
            return True
        return any(
            normalized_record.get(field)
            for field in (
                "user_id",
                "customer_id",
                "subject_id",
                "account_id",
                "email",
                "email_address",
                "email_hash",
                "phone",
                "phone_number",
            )
        )
    if normalized_condition == (
        "conversation contains shared customer, agent, or order context that must be retained"
    ) and normalized_record.get("category", "").casefold() == "support_message":
        return True
    if normalized_condition == "attachment belongs only to the deletion subject":
        if normalized_record.get("subject_only", "").casefold() in {
            "true",
            "yes",
            "1",
        }:
            return True
    if normalized_condition == "record is within the supplied retention period":
        category = normalized_record.get(
            "category", normalized_record.get("data_category", "")
        ).casefold()
        if category == "security_audit_log" and (
            "retention_until" in normalized_record
            or normalized_record.get("record_state", "").casefold()
            in {"found", "present", "retained"}
        ):
            return True

    condition_markers = {
        "still attributable to a user": (
            "attributable",
            "identified",
            "linked",
        ),
        "contains shared customer, agent, or order context that must be retained": (
            "shared",
            "agent",
            "order",
            "retain",
        ),
        "attachment belongs only to the deletion subject": ("belongs only", "solely"),
        "log contains a user email address": ("email",),
        "record is within the supplied retention period": (
            "within retention",
            "retention period",
            "retained",
        ),
        "a supplied legal hold is active": ("legal hold", "hold active"),
        "restore access can be blocked": ("restore access", "block restore"),
        "account is deleted and only a stable internal user_id is needed to preserve references to retained records": (
            "account deleted",
            "stable user_id",
            "tombstone",
        ),
    }
    markers = condition_markers.get(normalized_condition)
    if markers is None:
        return False
    return any(marker in context for marker in markers)


def normalize_treatment(value):
    normalized = (value or "").strip().upper().replace("-", "_").replace(" ", "_")
    aliases = {
        "DELETE": "DELETE",
        "ERASE": "DELETE",
        "REDACT": "REDACT",
        "REDACTION": "REDACT",
        "ANONYMIZE": "ANONYMIZE",
        "ANONYMISE": "ANONYMIZE",
        "RETAIN": "RETAIN",
        "KEEP": "RETAIN",
    }
    return aliases.get(normalized)


def policy_for(record, rules):
    category = _get(record, CATEGORY_FIELDS).casefold()
    system = _get(record, SYSTEM_FIELDS).casefold()
    if not category:
        return None

    candidates = []
    for rule in _records(rules):
        rule_category = _get(rule, CATEGORY_FIELDS).casefold()
        rule_system = _get(rule, SYSTEM_FIELDS).casefold()
        treatment = normalize_treatment(_get(rule, TREATMENT_FIELDS))
        if not treatment or rule_category != category:
            continue
        if not _condition_applies(record, _get(rule, CONDITION_FIELDS)):
            continue
        if rule_system and system and rule_system != system:
            continue
        candidates.append((rule_system, treatment))

    if not candidates:
        return None
    treatments = {treatment for _, treatment in candidates}
    if len(treatments) != 1:
        return None
    system_specific = [item for item in candidates if item[0] == system]
    return system_specific[0][1] if system_specific else candidates[0][1]


def allowed_identifiers_for(record, rules):
    matching_rules = [
        rule
        for rule in _records(rules)
        if _get(rule, CATEGORY_FIELDS).casefold()
        == _get(record, CATEGORY_FIELDS).casefold()
        and normalize_treatment(_get(rule, TREATMENT_FIELDS)) == "RETAIN"
        and _condition_applies(record, _get(rule, CONDITION_FIELDS))
        and (
            not _get(rule, SYSTEM_FIELDS)
            or not _get(record, SYSTEM_FIELDS)
            or _get(rule, SYSTEM_FIELDS).casefold()
            == _get(record, SYSTEM_FIELDS).casefold()
        )
    ]
    allowed = set()
    for rule in matching_rules:
        raw_allowed = _get(rule, ALLOWED_IDENTIFIER_FIELDS)
        allowed.update(
            item.strip().casefold()
            for item in raw_allowed.replace(";", ",").split(",")
            if item.strip()
        )
    return allowed


def present_identifiers_in(record):
    return {
        str(key).strip().casefold()
        for key, value in record.items()
        if str(key).strip().casefold() in PERSONAL_IDENTIFIER_FIELDS
        and value is not None
        and str(value).strip()
    }


def disallowed_identifiers_for(record, rules):
    return present_identifiers_in(record) - allowed_identifiers_for(record, rules)


def evaluate_record(record, rules, identifiers=()):
    treatment = policy_for(record, rules)
    if treatment is None:
        return {
            "treatment": None,
            "unresolved": True,
            "reason": "No unambiguous deletion rule applies to this data category.",
        }

    present = _get(record, ("record_state", "state", "status")).casefold()
    contains_identifiers = bool(identifiers)
    if treatment == "DELETE":
        satisfied = present in {"deleted", "absent", "removed", "not_found"}
    elif treatment == "REDACT":
        satisfied = present in {"redacted", "deidentified"} and not contains_identifiers
    elif treatment == "ANONYMIZE":
        satisfied = present in {
            "anonymized",
            "anonymised",
            "deidentified",
        } and not contains_identifiers
    else:
        allowed = allowed_identifiers_for(record, rules)
        present_identifiers = present_identifiers_in(record)
        identifiers_permitted = present_identifiers <= allowed
        satisfied = (
            present in {"retained", "present", "active", "found"}
            and identifiers_permitted
        )

    return {
        "treatment": treatment,
        "satisfied": satisfied,
        "unresolved": not satisfied,
        "reason": (
            "The observed state or identifier set does not prove the required policy treatment."
            if not satisfied
            else ""
        ),
    }