
import re

if __package__:
    from .evidence_loader import records_for_identity
    from .identity_resolver import resolve_identity
    from .policy_engine import (
        disallowed_identifiers_for,
        evaluate_record,
        policy_for,
    )
    from .remediation_planner import order_steps
else:
    from evidence_loader import records_for_identity
    from identity_resolver import resolve_identity
    from policy_engine import (
        disallowed_identifiers_for,
        evaluate_record,
        policy_for,
    )
    from remediation_planner import order_steps

NEGATIVE_REQUEST = re.compile(
    r"\b(?:did not|didn't|do not|don't|does not|doesn't|never|"
    r"not requesting|not seeking|no request|withdraw|cancel)\b"
    r".{0,50}\b(?:delet\w*|eras\w*|remov\w*)\b",
    re.IGNORECASE,
)


def classify_deletion(
    deletion_requested, unresolved_requirements, evidence_sufficient
):
    if not deletion_requested:
        return "NOT_APPLICABLE"
    if unresolved_requirements or not evidence_sufficient:
        return "INCOMPLETE"
    return "COMPLETE"


def _value(record, aliases, default=""):
    normalized = {str(key).strip().casefold(): value for key, value in record.items()}
    for alias in aliases:
        value = normalized.get(alias.casefold())
        if value is not None and str(value).strip():
            return str(value).strip()
    return default


def _system_resource(record, source):
    system = _value(
        record,
        (
            "system_id",
            "system",
            "system_name",
            "service",
            "target_system",
            "source_system",
        ),
        source,
    )
    resource = _value(
        record,
        (
            "resource_id",
            "record_id",
            "object_id",
            "file_id",
            "activity_id",
            "audit_id",
            "page_number",
            "line_number",
            "source_page_or_record",
        ),
        "unknown",
    )
    if resource == "unknown" and source == "evidence_artifact":
        resource = _value(record, ("page_number", "line_number"), "unknown")
    evidence_id = _value(record, ("evidence_id", "file_id", "activity_id", "audit_id"))
    return system, resource, evidence_id


def _step(phase, operation, state, system_id, resource_id, evidence_id, _description):
    return {
        "phase": phase,
        "operation": operation,
        "state": state,
        "system_id": system_id or "unknown",
        "resource_id": resource_id or "unknown",
        "evidence_id": evidence_id or "",
    }


def _record_state(record):
    return _value(
        record, ("record_state", "state", "status", "account_status", "record_status")
    ).casefold()


def _observed_identifiers(record):
    identifier_fields = {
        "email",
        "email_address",
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
    return [
        str(value).strip()
        for key, value in record.items()
        if str(key).strip().casefold() in identifier_fields
        and value is not None
        and str(value).strip()
        and str(value).strip().casefold() not in {"null", "none", "n/a", "unknown"}
    ]


def _artifact_record(record):
    normalized = dict(record)
    service = _value(normalized, ("system_id", "system", "service"))
    if not service or not service.casefold().endswith(
        ("_service", "_platform")
    ):
        service = ""
    if not service:
        source = " ".join(
            _value(normalized, (field,))
            for field in (
                "__source_path",
                "__source_table",
                "collection",
                "data_store",
                "source_artifact",
            )
        ).casefold()
        system_markers = (
            ("account_service", "account_service"),
            ("customer_profiles", "account_service"),
            ("search_service", "search_service"),
            ("search_documents", "search_service"),
            ("analytics_platform", "analytics_platform"),
            ("customer_analytics", "analytics_platform"),
            ("analytics_profile", "analytics_platform"),
            ("customer_export", "export_service"),
            ("backup_service", "backup_service"),
            ("backup_restore", "backup_service"),
            ("support_platform", "support_platform"),
            ("support_replica", "support_platform"),
            ("support_records", "support_platform"),
            ("security_service", "security_service"),
            ("security_audit", "security_service"),
        )
        service = next(
            (
                candidate
                for marker, candidate in system_markers
                if marker in source
            ),
            "",
        )
    if service:
        normalized.setdefault("system_id", service)

    event = _value(normalized, ("event", "event_type")).casefold()
    category = _value(
        normalized, ("category", "data_category", "record_type", "data_type")
    ).upper()
    source = " ".join(
        _value(normalized, (field,))
        for field in (
            "__source_path",
            "__source_table",
            "collection",
            "data_store",
            "source_artifact",
        )
    ).casefold()

    if not category:
        event_categories = {
            "profile_lookup_completed": "USER_PROFILE",
            "index_query_completed": "SEARCH_INDEX_ENTRY",
            "analytics_profile_read_completed": "ANALYTICS_PROFILE",
            "contact_lookup_completed": "SECONDARY_IDENTIFIER",
            "audit_record_read_completed": "SECURITY_AUDIT_LOG",
            "support_ticket_read_completed": "SUPPORT_MESSAGE",
            "message_pii_scan": "SUPPORT_MESSAGE",
            "attachment_pii_scan": "SUPPORT_ATTACHMENT",
            "contact_query_completed": "SECONDARY_IDENTIFIER",
            "deletion_marker_check": "SECONDARY_IDENTIFIER",
            "connector_config_read_completed": "DATA_FLOW",
            "connector_heartbeat": "DATA_FLOW",
            "restore_policy_read_completed": "BACKUP_ARCHIVE",
            "restore_policy_check_completed": "BACKUP_ARCHIVE",
        }
        category = event_categories.get(event, "")
    if not category:
        source_categories = (
            ("profile_lookups", "USER_PROFILE"),
            ("customer_profiles", "USER_PROFILE"),
            ("search_documents", "SEARCH_INDEX_ENTRY"),
            ("customer_analytics", "ANALYTICS_PROFILE"),
            ("analytics_profile", "ANALYTICS_PROFILE"),
            ("analytics_platform.profiles", "ANALYTICS_PROFILE"),
            ("customer_export", "USER_EXPORT"),
            ("backup_restore", "BACKUP_ARCHIVE"),
            ("backup_catalog", "BACKUP_ARCHIVE"),
            ("support_conversations", "SUPPORT_MESSAGE"),
            ("support_records", "SUPPORT_MESSAGE"),
            ("security_audit_events", "SECURITY_AUDIT_LOG"),
            ("deleted_customer_references", "ACCOUNT_TOMBSTONE"),
        )
        category = next(
            (
                candidate
                for marker, candidate in source_categories
                if marker in source
            ),
            "",
        )
    if category:
        normalized["category"] = category

    if not _record_state(normalized):
        if _value(normalized, ("status_code",)) == "404":
            normalized["record_state"] = "NOT_FOUND"
        elif event == "profile_lookup_completed":
            normalized["record_state"] = (
                "NOT_FOUND"
                if _value(normalized, ("rows",)) == "0"
                or _value(normalized, ("http_status",)) == "404"
                else "PRESENT"
            )
        elif event == "index_query_completed":
            normalized["record_state"] = (
                "FOUND"
                if _value(normalized, ("result",)).casefold() == "hit"
                or _value(normalized, ("total_hits",)) not in {"", "0"}
                else "NOT_FOUND"
            )
        elif event == "analytics_profile_read_completed":
            direct_identifiers = (
                "customer_reference",
                "user_id",
                "email",
                "phone",
                "email_hash",
            )
            normalized["record_state"] = (
                "IDENTIFIABLE"
                if any(_observed_identifiers({key: normalized.get(key)}) for key in direct_identifiers)
                else "ANONYMIZED"
            )
        elif event == "audit_record_read_completed":
            normalized["record_state"] = (
                "PRESENT"
                if _value(normalized, ("rows",)) not in {"", "0"}
                else "NOT_FOUND"
            )
        elif event == "support_ticket_read_completed":
            normalized["record_state"] = (
                "IDENTIFIABLE"
                if _observed_identifiers(normalized)
                else "REDACTED"
            )
        elif event in {"message_pii_scan", "attachment_pii_scan"}:
            normalized["record_state"] = "IDENTIFIABLE"
        elif event == "contact_query_completed":
            normalized["record_state"] = (
                "PRESENT"
                if _value(normalized, ("rows",)) not in {"", "0"}
                else "NOT_FOUND"
            )
        elif event == "contact_lookup_completed":
            normalized["record_state"] = (
                "PRESENT"
                if _value(normalized, ("rows",)) not in {"", "0"}
                else "NOT_FOUND"
            )
        elif event in {"connector_config_read_completed", "connector_heartbeat"}:
            enabled = _value(normalized, ("enabled",)).casefold()
            normalized["record_state"] = (
                "ACTIVE" if enabled in {"true", "1", "yes"} else "DISABLED"
            )
        elif event in {"restore_policy_read_completed", "restore_policy_check_completed"}:
            allowed = _value(normalized, ("restore_allowed",)).casefold()
            normalized["record_state"] = (
                "ACTIVE" if allowed in {"true", "1", "yes"} else "BLOCKED"
            )
        elif _value(normalized, ("resource_id",)):
            normalized["record_state"] = "PRESENT"

    text = _value(normalized, ("text",))
    if text and not _value(normalized, ("resource_id",)):
        resource_match = re.search(
            r"\b(?:account|search|analytics|audit_record|support|export|"
            r"backup|data_flow|tombstone)_[-A-Za-z0-9]+\b",
            text,
            re.IGNORECASE,
        )
        if resource_match:
            normalized["resource_id"] = resource_match.group(0)
    if text and not _value(normalized, ("system_id",)):
        system_match = re.search(
            r"\b(?:account|search|analytics|security|support|export|backup|"
            r"integration)_(?:service|platform)\b",
            text,
            re.IGNORECASE,
        )
        if system_match:
            normalized["system_id"] = system_match.group(0)
    source_artifact = _value(normalized, ("source_artifact",))
    if (
        not category
        and "attachment" in source_artifact.casefold()
        and text
    ):
        normalized["category"] = "SUPPORT_ATTACHMENT"
        normalized["system_id"] = "support_platform"
        normalized["record_state"] = "PRESENT"
        normalized["subject_only"] = "true"
    return normalized


def _flow_kind(record):
    text = " ".join(
        _value(record, (field,))
        for field in (
            "activity_type",
            "event_type",
            "job_type",
            "operation",
            "process_type",
            "description",
            "status",
            "text",
            "content",
            "message",
            "details",
            "category",
            "data_category",
            "resource_id",
        )
    ).casefold()
    if any(word in text for word in ("restore", "recovery", "backup")):
        return "restore"
    if any(
        word in text
        for word in ("sync", "import", "replication", "export", "data_flow")
    ):
        return "flow"
    return ""


def _is_active(record):
    status = _record_state(record)
    if status in {"active", "running", "enabled", "scheduled", "pending"}:
        return True
    event_type = _value(record, ("event_type",)).strip().upper()
    result = _value(record, ("reported_result",)).strip().upper()
    if event_type == "RESTORE_BACKUP" and result in {"SUCCESS", "PARTIAL"}:
        return True
    text = " ".join(
        _value(record, (field,))
        for field in ("text", "content", "message", "description", "details")
    ).casefold()
    return bool(re.search(r"\b(active|running|enabled|scheduled)\b", text))


def _treatment_operation(treatment):
    return {
        "DELETE": ("DELETE_RECORD", "ABSENT", "VERIFY_RECORD_ABSENT", "ABSENT"),
        "REDACT": (
            "REDACT_RECORD",
            "REDACTED",
            "VERIFY_RECORD_REDACTED",
            "REDACTED",
        ),
        "ANONYMIZE": (
            "ANONYMIZE_RECORD",
            "ANONYMIZED",
            "VERIFY_RECORD_ANONYMIZED",
            "ANONYMIZED",
        ),
        "RETAIN": (
            "VERIFY_RECORD_PRESENT",
            "PRESENT",
            "VERIFY_RECORD_PRESENT",
            "PRESENT",
        ),
    }.get(treatment)


def _activity_treatment_operation(record):
    action = _value(record, ("event_type",)).strip().upper()
    return {
        "DELETE_RECORD": (
            "DELETE",
            "REPORT_REMAINING_RECORD",
            "DELETE_RECORD",
            "ABSENT",
            "VERIFY_RECORD_ABSENT",
            "ABSENT",
        ),
        "REDACT_RECORD": (
            "REDACT",
            "REPORT_EXPOSED_PII",
            "REDACT_RECORD",
            "REDACTED",
            "VERIFY_RECORD_REDACTED",
            "REDACTED",
        ),
        "ANONYMIZE_RECORD": (
            "ANONYMIZE",
            "REPORT_EXPOSED_PII",
            "ANONYMIZE_RECORD",
            "ANONYMIZED",
            "VERIFY_RECORD_ANONYMIZED",
            "ANONYMIZED",
        ),
        "RETAIN_RECORD": (
            "RETAIN",
            "",
            "",
            "",
            "VERIFY_RECORD_PRESENT",
            "PRESENT",
        ),
    }.get(action)


def audit_case(request, identities, audit_log, evidence, rules):
    case_id = request["case_id"]
    request_text = request.get("request_text", "")
    requested = not NEGATIVE_REQUEST.search(request_text)
    if not requested:
        return {
            "case_id": case_id,
            "deletion_status": "NOT_APPLICABLE",
            "steps": [],
        }

    identity = resolve_identity(
        request.get("email", ""),
        identities,
        audit_log,
        as_of=request.get("audit_at"),
    )
    matched_records = records_for_identity(
        evidence,
        identity,
        audit_at=request.get("audit_at"),
    )
    unresolved = list(evidence.gaps)
    unresolved.extend(identity["history_gaps"])
    if not identity["matched"]:
        unresolved.append("No identity record supports the request email.")
    if identity["ambiguous"]:
        unresolved.append(
            "The request email resolves to multiple stable user IDs."
        )
    if not rules:
        unresolved.append("No deletion policy rules are available.")
    if not any(match["source"] == "evidence_artifact" for match in matched_records):
        unresolved.append("No identity-linked evidence artifacts are available.")

    findings = []
    remediation = []
    verification = []
    known_record_count = 0
    primary_profile_evidence = False
    action_history = {}
    for match in matched_records:
        if match["source"] != "system_activity":
            continue
        record = match["record"]
        operation = _activity_treatment_operation(record)
        if not operation:
            continue
        system, resource, evidence_id = _system_resource(record, "system_activity")
        timestamp = _value(record, ("event_time", "timestamp", "activity_at"))
        key = (system, resource, operation[0])
        previous = action_history.get(key)
        if previous is None or timestamp > previous[0]:
            action_history[key] = (timestamp, record, evidence_id)

    handled_activity_operations = set()
    for (system, resource, _), (_, record, evidence_id) in action_history.items():
        treatment, finding_operation, remediation_operation, remediation_state, verify_operation, verify_state = (
            _activity_treatment_operation(record)
        )
        result = _value(record, ("reported_result",)).strip().upper()
        if result not in {"FAILED", "PARTIAL"}:
            continue
        if finding_operation:
            findings.append(
                _step(
                    "FINDING",
                    finding_operation,
                    "PRESENT",
                    system,
                    resource,
                    evidence_id,
                    "The latest recorded treatment operation failed or was partial; verify the resource state.",
                )
            )
        if remediation_operation:
            remediation.append(
                _step(
                    "REMEDIATION",
                    remediation_operation,
                    remediation_state,
                    system,
                    resource,
                    "",
                    "Retry the policy treatment for this resource.",
                )
            )
        verification.append(
            _step(
                "VERIFICATION",
                verify_operation,
                verify_state,
                system,
                resource,
                "",
                "Verify the required resource state after remediation.",
            )
        )
        unresolved.append(
            f"The latest {treatment} activity for resource {resource} was {result}."
        )
        handled_activity_operations.add((system, resource, treatment))

    for match in matched_records:
        source = match["source"]
        record = (
            _artifact_record(match["record"])
            if source == "evidence_artifact"
            else match["record"]
        )
        if source == "evidence_artifact":
            if not _value(record, ("category", "data_category", "record_type", "data_type")):
                source_path = next(
                    (
                        artifact["path"]
                        for artifact in evidence.artifacts
                        if artifact["file_id"] == match.get("file_id")
                    ),
                    "",
                )
                if source_path:
                    record["source_artifact"] = source_path
                    record = _artifact_record(record)
            record_category = _value(
                record,
                ("category", "data_category", "record_type", "data_type"),
            ).casefold()
            if record_category in {
                "profile",
                "user_profile",
                "customer_profile",
                "customer_profiles",
            }:
                primary_profile_evidence = True
        system, resource, evidence_id = _system_resource(record, source)
        evidence_id = evidence_id or match.get("file_id", "")
        if source == "system_activity":
            treatment_steps = _activity_treatment_operation(record)
            if treatment_steps:
                treatment = treatment_steps[0]
                if (system, resource, treatment) in handled_activity_operations:
                    continue
                _, _, _, _, verify_operation, verify_state = treatment_steps
                result = _value(record, ("reported_result",)).strip().upper()
                if result in {"SUCCESS", "PARTIAL"}:
                    verification.append(
                        _step(
                            "VERIFICATION",
                            verify_operation,
                            verify_state,
                            system,
                            resource,
                            evidence_id,
                            "Verify the claimed operation result against current record evidence.",
                        )
                    )
            if _flow_kind(record) and _is_active(record):
                unresolved.append(
                    "An active process can recreate data and must be addressed."
                )
                flow_kind = _flow_kind(record)
                if flow_kind == "restore":
                    findings.append(
                        _step(
                            "FINDING",
                            "REPORT_RESTORE_RISK",
                            "ACTIVE",
                            system,
                            resource,
                            evidence_id,
                            "A restore operation or active restore path may reintroduce data.",
                        )
                    )
                    remediation.append(
                        _step(
                            "REMEDIATION",
                            "BLOCK_RESTORE",
                            "BLOCKED",
                            system,
                            resource,
                            "",
                            "Block the affected restore path.",
                        )
                    )
                    verification.append(
                        _step(
                            "VERIFICATION",
                            "VERIFY_RESTORE_BLOCKED",
                            "BLOCKED",
                            system,
                            resource,
                            "",
                            "Verify the affected restore path is blocked.",
                        )
                    )
                else:
                    findings.append(
                        _step(
                            "FINDING",
                            "REPORT_ACTIVE_DATA_FLOW",
                            "ACTIVE",
                            system,
                            resource,
                            evidence_id,
                            "An active synchronization process can recreate data.",
                        )
                    )
                    remediation.append(
                        _step(
                            "REMEDIATION",
                            "DISABLE_DATA_FLOW",
                            "DISABLED",
                            system,
                            resource,
                            "",
                            "Disable the identified synchronization or import flow.",
                        )
                    )
                    verification.append(
                        _step(
                            "VERIFICATION",
                            "VERIFY_DATA_FLOW_DISABLED",
                            "DISABLED",
                            system,
                            resource,
                            "",
                            "Verify the identified data flow is disabled.",
                        )
                    )
            continue
        category = _value(
            record, ("category", "data_category", "record_type", "data_type")
        )
        if category:
            if category.upper() in {"DATA_FLOW", "BACKUP_ARCHIVE"}:
                flow_kind = _flow_kind(record)
                if flow_kind and _is_active(record):
                    unresolved.append(
                        "An active process can recreate data and must be addressed."
                    )
                    operation = (
                        "REPORT_RESTORE_RISK"
                        if flow_kind == "restore"
                        else "REPORT_ACTIVE_DATA_FLOW"
                    )
                    findings.append(
                        _step(
                            "FINDING",
                            operation,
                            "ACTIVE",
                            system,
                            resource,
                            evidence_id,
                            "An active process may recreate data after deletion.",
                        )
                    )
                    remediation_operation = (
                        "BLOCK_RESTORE"
                        if flow_kind == "restore"
                        else "DISABLE_DATA_FLOW"
                    )
                    remediation_state = (
                        "BLOCKED" if flow_kind == "restore" else "DISABLED"
                    )
                    verify_operation = (
                        "VERIFY_RESTORE_BLOCKED"
                        if flow_kind == "restore"
                        else "VERIFY_DATA_FLOW_DISABLED"
                    )
                    remediation.append(
                        _step(
                            "REMEDIATION",
                            remediation_operation,
                            remediation_state,
                            system,
                            resource,
                            "",
                            "Stop the identified process from recreating deleted data.",
                        )
                    )
                    verification.append(
                        _step(
                            "VERIFICATION",
                            verify_operation,
                            remediation_state,
                            system,
                            resource,
                            "",
                            "Verify the identified recreation path is disabled or blocked.",
                        )
                    )
                elif flow_kind and _record_state(record) in {
                    "disabled",
                    "blocked",
                    "stopped",
                    "inactive",
                }:
                    verification.append(
                        _step(
                            "VERIFICATION",
                            (
                                "VERIFY_RESTORE_BLOCKED"
                                if flow_kind == "restore"
                                else "VERIFY_DATA_FLOW_DISABLED"
                            ),
                            (
                                "BLOCKED"
                                if flow_kind == "restore"
                                else "DISABLED"
                            ),
                            system,
                            resource,
                            evidence_id,
                            "Verify the recreation path is inactive.",
                        )
                    )
                continue
            known_record_count += 1
            policy = policy_for(record, rules)
            outcome = evaluate_record(
                record, rules, identifiers=_observed_identifiers(record)
            )
            if policy and outcome.get("unresolved"):
                unresolved.append(
                    f"Record {resource} has not received its required {policy} treatment."
                )
                state = _record_state(record)
                finding_operation = (
                    "REPORT_EXPOSED_PII"
                    if policy in {"REDACT", "ANONYMIZE", "RETAIN"}
                    and _observed_identifiers(record)
                    else "REPORT_REMAINING_RECORD"
                )
                if (
                    state in {"present", "active", "retained", "found"}
                    or finding_operation == "REPORT_EXPOSED_PII"
                ):
                    findings.append(
                        _step(
                            "FINDING",
                            finding_operation,
                            "PRESENT",
                            system,
                            resource,
                            evidence_id,
                            outcome["reason"],
                        )
                    )
                treatment_steps = _treatment_operation(policy)
                if treatment_steps:
                    action, action_state, verify, verify_state = treatment_steps
                    if policy == "RETAIN":
                        if disallowed_identifiers_for(record, rules):
                            remediation.append(
                                _step(
                                    "REMEDIATION",
                                    "REDACT_RECORD",
                                    "REDACTED",
                                    system,
                                    resource,
                                    "",
                                    "Remove identifiers not permitted by the retention rule.",
                                )
                            )
                            verification.append(
                                _step(
                                    "VERIFICATION",
                                    "VERIFY_RECORD_REDACTED",
                                    "REDACTED",
                                    system,
                                    resource,
                                    "",
                                    "Verify disallowed identifiers were removed.",
                                )
                            )
                    else:
                        remediation.append(
                            _step(
                                "REMEDIATION",
                                action,
                                action_state,
                                system,
                                resource,
                                "",
                                f"Apply the {policy.lower()} treatment required by policy.",
                            )
                        )
                    verification.append(
                        _step(
                            "VERIFICATION",
                            verify,
                            verify_state,
                            system,
                            resource,
                            "",
                            "Confirm the required record state after remediation.",
                        )
                    )
            elif policy and outcome.get("satisfied"):
                _, _, verify, verify_state = _treatment_operation(policy)
                verification.append(
                    _step(
                        "VERIFICATION",
                        verify,
                        verify_state,
                        system,
                        resource,
                        evidence_id,
                        "Verify the policy-compliant state using the linked evidence.",
                    )
                )
            else:
                unresolved.append(
                    f"No unambiguous deletion rule for category {category}."
                )

        flow_kind = _flow_kind(record)
        if flow_kind and _is_active(record):
            unresolved.append(
                "An active process can recreate data and must be addressed."
            )
            operation = (
                "REPORT_RESTORE_RISK"
                if flow_kind == "restore"
                else "REPORT_ACTIVE_DATA_FLOW"
            )
            findings.append(
                _step(
                    "FINDING",
                    operation,
                    "ACTIVE",
                    system,
                    resource,
                    evidence_id,
                    "An active process may recreate data after deletion.",
                )
            )
            if flow_kind == "restore":
                remediation.append(
                    _step(
                        "REMEDIATION",
                        "BLOCK_RESTORE",
                        "BLOCKED",
                        system,
                        resource,
                        "",
                        "Block the identified restore path before deleting affected data.",
                    )
                )
                verification.append(
                    _step(
                        "VERIFICATION",
                        "VERIFY_RESTORE_BLOCKED",
                        "BLOCKED",
                        system,
                        resource,
                        "",
                        "Verify the restore path is blocked.",
                    )
                )
            else:
                remediation.append(
                    _step(
                        "REMEDIATION",
                        "DISABLE_DATA_FLOW",
                        "DISABLED",
                        system,
                        resource,
                        "",
                        "Disable the identified synchronization or import flow.",
                    )
                )
                verification.append(
                    _step(
                        "VERIFICATION",
                        "VERIFY_DATA_FLOW_DISABLED",
                        "DISABLED",
                        system,
                        resource,
                        "",
                        "Verify the data flow is disabled.",
                    )
                )

    if not primary_profile_evidence:
        unresolved.append(
            "No identity-linked primary profile evidence establishes the account state."
        )
    evidence_sufficient = bool(
        identity["matched"]
        and not identity["ambiguous"]
        and rules
        and evidence.artifacts
        and known_record_count
        and not unresolved
    )
    status = classify_deletion(requested, unresolved, evidence_sufficient)
    if status == "COMPLETE":
        steps = order_steps(verification)
    else:
        for step in verification:
            step["evidence_id"] = ""
        steps = order_steps(findings + remediation + verification)

    return {
        "case_id": case_id,
        "deletion_status": status,
        "steps": steps,
    }
