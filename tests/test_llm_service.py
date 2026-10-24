import json

import pytest

from src.llm_service import (
    LLMNotConfiguredError,
    request_structured_analysis,
)


def test_optional_llm_fails_explicitly_when_unconfigured():
    with pytest.raises(LLMNotConfiguredError):
        request_structured_analysis(None, "Analyze evidence", [])


def test_llm_suggestions_must_use_supported_operations_and_evidence():
    valid = [
        {
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "file-1",
        }
    ]
    result = request_structured_analysis(
        lambda prompt: json.dumps(valid),
        "Analyze evidence",
        ["file-1"],
    )
    assert result == valid

    unsupported = [
        {
            "operation": "REPORT_REMAINING_RECORD",
            "state": "PRESENT",
            "evidence_id": "invented",
        }
    ]
    with pytest.raises(ValueError, match="unsupported evidence ID"):
        request_structured_analysis(
            lambda prompt: json.dumps(unsupported),
            "Analyze evidence",
            ["file-1"],
        )


def test_llm_response_must_be_json_array():
    with pytest.raises(ValueError, match="valid JSON"):
        request_structured_analysis(lambda prompt: "not-json", "Analyze", [])
    with pytest.raises(ValueError, match="JSON array"):
        request_structured_analysis(lambda prompt: "{}", "Analyze", [])
