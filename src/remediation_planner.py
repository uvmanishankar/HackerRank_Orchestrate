
OPERATION_ORDER = {
    "REPORT_REMAINING_RECORD": 1,
    "REPORT_EXPOSED_PII": 2,
    "REPORT_ACTIVE_DATA_FLOW": 3,
    "REPORT_RESTORE_RISK": 4,
    "DISABLE_DATA_FLOW": 5,
    "BLOCK_RESTORE": 6,
    "DELETE_RECORD": 7,
    "REDACT_RECORD": 8,
    "ANONYMIZE_RECORD": 9,
    "VERIFY_RECORD_ABSENT": 10,
    "VERIFY_RECORD_PRESENT": 11,
    "VERIFY_RECORD_REDACTED": 12,
    "VERIFY_RECORD_ANONYMIZED": 13,
    "VERIFY_DATA_FLOW_DISABLED": 14,
    "VERIFY_RESTORE_BLOCKED": 15,
}

PHASE_ORDER = {
    "FINDING": 1,
    "REMEDIATION": 2,
    "VERIFICATION": 3,
}

OPERATION_STATES = {
    "REPORT_REMAINING_RECORD": {"PRESENT"},
    "REPORT_EXPOSED_PII": {"PRESENT"},
    "REPORT_ACTIVE_DATA_FLOW": {"ACTIVE"},
    "REPORT_RESTORE_RISK": {"ACTIVE"},
    "DISABLE_DATA_FLOW": {"DISABLED"},
    "BLOCK_RESTORE": {"BLOCKED"},
    "DELETE_RECORD": {"ABSENT"},
    "REDACT_RECORD": {"REDACTED"},
    "ANONYMIZE_RECORD": {"ANONYMIZED"},
    "VERIFY_RECORD_ABSENT": {"ABSENT"},
    "VERIFY_RECORD_PRESENT": {"PRESENT"},
    "VERIFY_RECORD_REDACTED": {"REDACTED"},
    "VERIFY_RECORD_ANONYMIZED": {"ANONYMIZED"},
    "VERIFY_DATA_FLOW_DISABLED": {"DISABLED"},
    "VERIFY_RESTORE_BLOCKED": {"BLOCKED"},
}

OPERATION_PHASES = {
    operation: "FINDING" for operation in (
        "REPORT_REMAINING_RECORD",
        "REPORT_EXPOSED_PII",
        "REPORT_ACTIVE_DATA_FLOW",
        "REPORT_RESTORE_RISK",
    )
}
OPERATION_PHASES.update(
    {operation: "REMEDIATION" for operation in (
        "DISABLE_DATA_FLOW",
        "BLOCK_RESTORE",
        "DELETE_RECORD",
        "REDACT_RECORD",
        "ANONYMIZE_RECORD",
    )}
)
OPERATION_PHASES.update(
    {operation: "VERIFICATION" for operation in (
        "VERIFY_RECORD_ABSENT",
        "VERIFY_RECORD_PRESENT",
        "VERIFY_RECORD_REDACTED",
        "VERIFY_RECORD_ANONYMIZED",
        "VERIFY_DATA_FLOW_DISABLED",
        "VERIFY_RESTORE_BLOCKED",
    )}
)

def order_steps(steps):
    normalized_steps = []
    for original in steps:
        step = dict(original)
        phase = step.get("phase")
        operation = step.get("operation")
        if phase not in PHASE_ORDER:
            raise ValueError(f"Unsupported step phase: {phase}")
        if operation not in OPERATION_ORDER:
            raise ValueError(f"Unsupported step operation: {operation}")
        if OPERATION_PHASES[operation] != phase:
            raise ValueError(
                f"{operation} is not valid in the {phase} phase"
            )
        if step.get("state") not in OPERATION_STATES[operation]:
            raise ValueError(
                f"Invalid state for {operation}: {step.get('state')}"
            )
        for field in ("system_id", "resource_id", "evidence_id"):
            if field not in step:
                raise ValueError(f"Step is missing required field: {field}")
        normalized_steps.append(step)
    ordered = sorted(
        normalized_steps,
        key=lambda step: (
            PHASE_ORDER[step["phase"]],
            OPERATION_ORDER[step["operation"]],
            str(step["system_id"]),
            str(step["resource_id"]),
            str(step.get("evidence_id", "")),
        ),
    )

    for index, step in enumerate(ordered, start=1):
        step["step_no"] = index

    return ordered
