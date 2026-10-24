import csv

import pytest

from src import main


def test_supplied_requests_validate_and_are_unique():
    requests = main.load_requests()
    assert len(requests) == 518
    assert len({row["case_id"] for row in requests}) == 518
    assert [row["case_id"] for row in requests] == sorted(
        row["case_id"] for row in requests
    )


def test_load_requests_rejects_missing_columns(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    with (evidence_dir / "deletion_requests.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.writer(file)
        writer.writerow(["case_id", "email"])
        writer.writerow(["case_1", "one@example.test"])
    monkeypatch.setattr(main, "EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr(main, "ROOT", tmp_path)

    with pytest.raises(ValueError, match="Missing required columns"):
        main.load_requests()


def test_load_requests_rejects_duplicate_case_ids(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    columns = list(main.REQUIRED_COLUMNS)
    row = {
        "case_id": "case_1",
        "email": "one@example.test",
        "requested_at": "2026-01-01T00:00:00Z",
        "reported_status": "COMPLETE",
        "reported_at": "2026-01-02T00:00:00Z",
        "audit_at": "2026-01-03T00:00:00Z",
        "request_text": "Please delete my personal data.",
    }
    with (evidence_dir / "deletion_requests.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(file, fieldnames=columns)
        writer.writeheader()
        writer.writerow(row)
        writer.writerow(row)
    monkeypatch.setattr(main, "EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr(main, "ROOT", tmp_path)

    with pytest.raises(ValueError, match="Duplicate case_id"):
        main.load_requests()


def test_load_requests_rejects_invalid_timestamp(tmp_path, monkeypatch):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    row = {
        "case_id": "case_1",
        "email": "one@example.test",
        "requested_at": "not-a-date",
        "reported_status": "COMPLETE",
        "reported_at": "2026-01-02T00:00:00Z",
        "audit_at": "2026-01-03T00:00:00Z",
        "request_text": "Please delete my personal data.",
    }
    with (evidence_dir / "deletion_requests.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(file, fieldnames=row.keys())
        writer.writeheader()
        writer.writerow(row)
    monkeypatch.setattr(main, "EVIDENCE_DIR", evidence_dir)
    monkeypatch.setattr(main, "ROOT", tmp_path)

    with pytest.raises(ValueError, match="Invalid timestamp"):
        main.load_requests()