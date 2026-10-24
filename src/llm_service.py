import json

from .remediation_planner import OPERATION_ORDER, OPERATION_STATES


class LLMNotConfiguredError(RuntimeError):
    pass


def request_structured_analysis(client, prompt, allowed_evidence_ids):
    if client is None:
        raise LLMNotConfiguredError(
            "No LLM provider is configured; deterministic audit mode remains available."
        )
    response = client(prompt)
    try:
        result = json.loads(response)
    except (TypeError, json.JSONDecodeError) as error:
        raise ValueError("LLM response must be valid JSON") from error
    if not isinstance(result, list):
        raise ValueError("LLM response must be a JSON array of proposed findings")

    allowed_evidence_ids = {str(item) for item in allowed_evidence_ids}
    for index, finding in enumerate(result):
        if not isinstance(finding, dict):
            raise ValueError(f"Finding {index} must be a JSON object")
        operation = finding.get("operation")
        if operation not in OPERATION_ORDER:
            raise ValueError(f"Unsupported operation in LLM response: {operation}")
        if finding.get("state") not in OPERATION_STATES[operation]:
            raise ValueError(
                f"Invalid state for LLM operation {operation}: {finding.get('state')}"
            )
        evidence_id = str(finding.get("evidence_id", ""))
        if evidence_id and evidence_id not in allowed_evidence_ids:
            raise ValueError(
                f"LLM response refers to unsupported evidence ID: {evidence_id}"
            )
    return result