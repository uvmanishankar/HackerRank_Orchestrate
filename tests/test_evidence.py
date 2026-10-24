import csv
import sqlite3

from src.config import SUPPORTING_FILES
from src.evidence_loader import (
    EvidenceBundle,
    _read_lines,
    load_evidence,
    records_for_identity,
)


def test_empty_supporting_files_are_reported_as_gaps(tmp_path):
    for filename in SUPPORTING_FILES.values():
        (tmp_path / filename).write_text("", encoding="utf-8")

    bundle = load_evidence(tmp_path)

    empty_source_gaps = [
        gap for gap in bundle.gaps if "Evidence source is empty:" in gap
    ]
    assert len(empty_source_gaps) == len(SUPPORTING_FILES)


def test_evidence_after_audit_time_is_not_used():
    bundle = EvidenceBundle(
        tables={
            "system_activity": [
                {
                    "user_id": "u-1",
                    "activity_at": "2026-01-04T00:00:00Z",
                    "activity_id": "future",
                },
                {
                    "user_id": "u-1",
                    "activity_at": "2026-01-02T00:00:00Z",
                    "activity_id": "at-audit",
                },
            ]
        }
    )
    result = records_for_identity(
        bundle,
        {"user_ids": {"u-1"}, "emails": set(), "phones": set(), "email_hashes": set()},
        audit_at="2026-01-03T00:00:00Z",
    )

    assert [entry["record"]["activity_id"] for entry in result] == ["at-audit"]


def test_linked_activity_resource_expands_to_its_treatment_history():
    bundle = EvidenceBundle(
        tables={
            "system_activity": [
                {
                    "activity_id": "link-1",
                    "event_time": "2026-01-01T00:00:00Z",
                    "event_type": "LINK_RESOURCE_IDENTITY",
                    "target_system": "account_service",
                    "resource_id": "account_42",
                    "details": (
                        "Data catalog linked account_42 to "
                        "one@example.test and user_1."
                    ),
                },
                {
                    "activity_id": "delete-1",
                    "event_time": "2026-01-02T00:00:00Z",
                    "event_type": "DELETE_RECORD",
                    "target_system": "account_service",
                    "resource_id": "account_42",
                    "reported_result": "FAILED",
                    "details": "Deletion operation failed.",
                },
                {
                    "activity_id": "other",
                    "event_time": "2026-01-02T00:00:00Z",
                    "event_type": "DELETE_RECORD",
                    "target_system": "account_service",
                    "resource_id": "account_99",
                    "reported_result": "FAILED",
                    "details": "Unrelated record references account_42 in a note.",
                },
                {
                    "activity_id": "future-link",
                    "event_time": "2026-01-04T00:00:00Z",
                    "event_type": "DELETE_RECORD",
                    "target_system": "account_service",
                    "resource_id": "account_42",
                    "reported_result": "FAILED",
                    "details": "This event is after the audit time.",
                },
            ]
        }
    )

    matches = records_for_identity(
        bundle,
        {
            "user_ids": {"user_1"},
            "emails": {"one@example.test"},
            "phones": set(),
            "email_hashes": set(),
        },
        audit_at="2026-01-03T00:00:00Z",
    )

    assert {row["record"]["activity_id"] for row in matches} == {
        "link-1",
        "delete-1",
    }


def test_profile_snapshot_does_not_infer_absence_from_numeric_identifiers():
    bundle = EvidenceBundle(
        artifacts=[
            {
                "file_id": "snapshot-1",
                "path": "profile-snapshot.sql",
                "records": [
                    {
                        "__source_table": "customer_profiles",
                        "user_id": "user_05",
                        "resource_id": "account_005",
                        "captured_at": "2026-01-02T00:00:00Z",
                    },
                    {
                        "__source_table": "customer_profiles",
                        "user_id": "user_8741",
                        "resource_id": "account_8741",
                        "captured_at": "2026-01-02T00:00:00Z",
                    },
                ],
            }
        ]
    )

    matches = records_for_identity(
        bundle,
        {
            "user_ids": {"user_01"},
            "emails": set(),
            "phones": set(),
            "email_hashes": set(),
        },
        audit_at="2026-01-03T00:00:00Z",
    )

    assert matches == []


def test_text_reader_extracts_key_value_and_pipe_delimited_evidence(tmp_path):
    path = tmp_path / "events.log"
    path.write_text(
        "2026-01-02T00:00:00Z level=INFO service=account_service "
        "event=profile_lookup_completed resource_id=account_1 rows=0\n"
        "- 2026-01-02T00:00:00Z | search_service | search_2 | "
        "SEARCH_INDEX_ENTRY | FOUND | one@example.test\n",
        encoding="utf-8",
    )

    records = _read_lines(path)

    assert records[0]["service"] == "account_service"
    assert records[0]["event"] == "profile_lookup_completed"
    assert records[0]["resource_id"] == "account_1"
    assert records[1]["system_id"] == "search_service"
    assert records[1]["resource_id"] == "search_2"
    assert records[1]["category"] == "SEARCH_INDEX_ENTRY"
    assert records[1]["email"] == "one@example.test"


def test_manifest_artifact_is_read_and_scoped(tmp_path):
    for filename in SUPPORTING_FILES.values():
        (tmp_path / filename).write_text("", encoding="utf-8")
    with (tmp_path / "evidence_files.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["file_id", "file_path", "captured_at"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "e-1",
                "file_path": "records.csv",
                "captured_at": "2026-01-02T00:00:00Z",
            }
        )
    with (tmp_path / "records.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(file, fieldnames=["email", "record_id"])
        writer.writeheader()
        writer.writerow(
            {"email": "one@example.test", "record_id": "r-1"}
        )

    bundle = load_evidence(tmp_path)
    matches = records_for_identity(
        bundle,
        {
            "user_ids": set(),
            "emails": {"one@example.test"},
            "phones": set(),
            "email_hashes": set(),
        },
    )

    assert len(matches) == 1
    assert matches[0]["file_id"] == "e-1"


def test_record_timestamp_is_preserved_when_artifact_is_exported_later(tmp_path):
    for filename in SUPPORTING_FILES.values():
        (tmp_path / filename).write_text("", encoding="utf-8")
    with (tmp_path / "evidence_files.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["file_id", "file_path", "captured_at"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "e-late",
                "file_path": "records.json",
                "captured_at": "2026-01-04T00:00:00Z",
            }
        )
    (tmp_path / "records.json").write_text(
        '{"captured_at":"2026-01-02T00:00:00Z",'
        '"records":[{"email":"one@example.test","resource_id":"r-1"}]}',
        encoding="utf-8",
    )

    bundle = load_evidence(tmp_path)
    matches = records_for_identity(
        bundle,
        {
            "user_ids": set(),
            "emails": {"one@example.test"},
            "phones": set(),
            "email_hashes": set(),
        },
        audit_at="2026-01-03T00:00:00Z",
    )

    assert len(matches) == 1
    assert matches[0]["record"]["__manifest_captured_at"] == "2026-01-04T00:00:00Z"


def test_manifest_capture_time_is_used_when_record_has_no_timestamp(tmp_path):
    for filename in SUPPORTING_FILES.values():
        (tmp_path / filename).write_text("", encoding="utf-8")
    with (tmp_path / "evidence_files.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["file_id", "file_path", "captured_at"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "e-late",
                "file_path": "records.csv",
                "captured_at": "2026-01-04T00:00:00Z",
            }
        )
    with (tmp_path / "records.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(file, fieldnames=["email", "resource_id"])
        writer.writeheader()
        writer.writerow({"email": "one@example.test", "resource_id": "r-1"})

    bundle = load_evidence(tmp_path)
    matches = records_for_identity(
        bundle,
        {
            "user_ids": set(),
            "emails": {"one@example.test"},
            "phones": set(),
            "email_hashes": set(),
        },
        audit_at="2026-01-03T00:00:00Z",
    )

    assert matches == []


def test_manifest_resolves_artifact_nested_under_extra_directory(tmp_path):
    evidence_dir = tmp_path / "evidence"
    nested_log = evidence_dir / "databases" / "logs" / "events.log"
    nested_log.parent.mkdir(parents=True)
    nested_log.write_text(
        "2026-01-02T10:00:00Z user_id=u-1",
        encoding="utf-8",
    )
    for filename in SUPPORTING_FILES.values():
        (tmp_path / filename).write_text("", encoding="utf-8")
    with (tmp_path / "evidence_files.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["file_id", "file_path", "captured_at"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "e-2",
                "file_path": "evidence/logs/events.log",
                "captured_at": "2026-01-02T10:00:00Z",
            }
        )

    bundle = load_evidence(tmp_path)
    matches = records_for_identity(
        bundle,
        {
            "user_ids": {"u-1"},
            "emails": set(),
            "phones": set(),
            "email_hashes": set(),
        },
    )

    assert len(matches) == 1
    assert matches[0]["file_id"] == "e-2"
    assert not any("unavailable" in gap.lower() for gap in bundle.gaps)


def test_nested_json_records_keep_service_hierarchy(tmp_path):
    for filename in SUPPORTING_FILES.values():
        (tmp_path / filename).write_text("", encoding="utf-8")
    with (tmp_path / "evidence_files.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["file_id", "file_path", "captured_at"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "nested-json",
                "file_path": "snapshot.json",
                "captured_at": "2026-01-02T00:00:00Z",
            }
        )
    (tmp_path / "snapshot.json").write_text(
        '{"service_exports":{"account_service":{"profile_lookups":'
        '[{"resource_id":"account-1","status_code":404}]}}}',
        encoding="utf-8",
    )

    bundle = load_evidence(tmp_path)
    record = bundle.artifacts[0]["records"][0]

    assert (
        record["__source_path"]
        == "service_exports.account_service.profile_lookups"
    )


def test_unmanifested_local_log_is_ingested_and_identity_matched(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    for filename in SUPPORTING_FILES.values():
        (evidence_dir / filename).write_text("", encoding="utf-8")
    log_path = evidence_dir / "operations.log"
    log_path.write_text(
        "2026-01-02T10:00:00Z user_id=u-1 sync job active",
        encoding="utf-8",
    )

    bundle = load_evidence(tmp_path)
    matches = records_for_identity(
        bundle,
        {"user_ids": {"u-1"}, "emails": set(), "phones": set(), "email_hashes": set()},
    )

    assert len(matches) == 1
    assert matches[0]["source"] == "evidence_artifact"
    assert matches[0]["record"]["recorded_at"] == "2026-01-02T10:00:00Z"
    assert matches[0]["file_id"] == "evidence/operations.log"


def test_sqlite_snapshot_is_read_without_writing_to_it(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    for filename in SUPPORTING_FILES.values():
        (evidence_dir / filename).write_text("", encoding="utf-8")
    database = evidence_dir / "snapshot.sqlite"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE customer_records "
            "(user_id TEXT, category TEXT, system_id TEXT, state TEXT)"
        )
        connection.execute(
            "INSERT INTO customer_records VALUES (?, ?, ?, ?)",
            ("u-1", "profile", "crm", "present"),
        )
    with (evidence_dir / "evidence_files.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        writer = csv.DictWriter(
            file, fieldnames=["file_id", "file_path", "captured_at"]
        )
        writer.writeheader()
        writer.writerow(
            {
                "file_id": "snapshot-1",
                "file_path": "snapshot.sqlite",
                "captured_at": "2026-01-02T00:00:00Z",
            }
        )

    bundle = load_evidence(tmp_path)
    matches = records_for_identity(
        bundle,
        {"user_ids": {"u-1"}, "emails": set(), "phones": set(), "email_hashes": set()},
    )

    assert len(matches) == 1
    assert matches[0]["file_id"] == "snapshot-1"
    assert matches[0]["record"]["__source_table"] == "customer_records"


def test_sql_dump_is_loaded_in_memory_and_rejects_unsafe_statements(tmp_path):
    from src.evidence_loader import _read_sql_dump

    dump = tmp_path / "snapshot.sql"
    dump.write_text(
        "CREATE TABLE records (user_id TEXT, category TEXT);\n"
        "INSERT INTO records VALUES ('u-1', 'profile');\n",
        encoding="utf-8",
    )

    rows = _read_sql_dump(dump)
    assert rows[0]["user_id"] == "u-1"
    assert rows[0]["category"] == "profile"

    unsafe = tmp_path / "unsafe.sql"
    unsafe.write_text("ATTACH DATABASE 'external.db' AS external;", encoding="utf-8")
    try:
        _read_sql_dump(unsafe)
    except ValueError as error:
        assert "safe snapshot subset" in str(error)
    else:
        raise AssertionError("Unsafe SQL dump statement was accepted")


def test_sql_dump_allows_trailing_snapshot_comment(tmp_path):
    from src.evidence_loader import _read_sql_dump

    dump = tmp_path / "snapshot.sql"
    dump.write_text(
        "CREATE TABLE records (user_id TEXT);\n"
        "INSERT INTO records VALUES ('u-1');\n"
        "-- snapshot_completed_at=2026-01-02T00:00:00Z\n",
        encoding="utf-8",
    )

    assert _read_sql_dump(dump)[0]["user_id"] == "u-1"


def test_sql_dump_allows_foreign_key_pragma(tmp_path):
    from src.evidence_loader import _read_sql_dump

    dump = tmp_path / "snapshot.sql"
    dump.write_text(
        "PRAGMA foreign_keys=ON;\n"
        "CREATE TABLE records (user_id TEXT);\n"
        "INSERT INTO records VALUES ('u-1');\n",
        encoding="utf-8",
    )

    assert _read_sql_dump(dump)[0]["user_id"] == "u-1"


def test_media_extractor_reports_missing_optional_dependency(tmp_path, monkeypatch):
    import sys

    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    for filename in SUPPORTING_FILES.values():
        (evidence_dir / filename).write_text("", encoding="utf-8")
    (evidence_dir / "scan.pdf").write_bytes(b"not a real PDF")
    monkeypatch.setitem(sys.modules, "pypdf", None)

    bundle = load_evidence(tmp_path)

    assert any(
        "PDF support requires pypdf" in gap for gap in bundle.gaps
    )


def test_pdf_pages_are_extracted_when_manifested(tmp_path):
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    for filename in SUPPORTING_FILES.values():
        (evidence_dir / filename).write_text("", encoding="utf-8")
    content = b"BT /F1 12 Tf 10 100 Td (user_id=u-1 2026-01-02T00:00:00Z) Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>"
        ),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length "
        + str(len(content)).encode("ascii")
        + b" >>\nstream\n"
        + content
        + b"\nendstream",
    ]
    pdf = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, body in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{number} 0 obj\n".encode("ascii"))
        pdf.extend(body)
        pdf.extend(b"\nendobj\n")
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    (evidence_dir / "snapshot.pdf").write_bytes(pdf)
    with (evidence_dir / "evidence_files.csv").open(
        "w", encoding="utf-8", newline=""
    ) as file:
        manifest = csv.DictWriter(
            file,
            fieldnames=["file_id", "file_path", "captured_at"],
        )
        manifest.writeheader()
        manifest.writerow(
            {
                "file_id": "pdf-1",
                "file_path": "snapshot.pdf",
                "captured_at": "2026-01-02T00:00:00Z",
            }
        )

    bundle = load_evidence(tmp_path)

    assert len(bundle.artifacts) == 1
    assert bundle.artifacts[0]["file_id"] == "pdf-1"
    assert bundle.artifacts[0]["records"][0]["page_number"] == "1"
    assert "user_id=u-1" in bundle.artifacts[0]["records"][0]["text"]
    matches = records_for_identity(
        bundle,
        {"user_ids": {"u-1"}, "emails": set(), "phones": set(), "email_hashes": set()},
        audit_at="2026-01-03T00:00:00Z",
    )
    assert len(matches) == 1
