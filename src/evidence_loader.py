import csv
from io import BytesIO
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

if __package__:
    from .config import SUPPORTING_FILES
else:
    from config import SUPPORTING_FILES

IDENTIFIER_FIELDS = {
    "user_ids": {"user_id", "customer_id", "subject_id", "account_id"},
    "emails": {
        "email",
        "email_address",
        "old_email",
        "new_email",
        "customer_email",
        "requester_email",
        "owner_email",
    },
    "phones": {"phone", "phone_number", "mobile", "old_phone", "new_phone"},
    "email_hashes": {
        "email_hash",
        "hashed_email",
        "old_email_hash",
        "new_email_hash",
    },
}
TIMESTAMP_FIELDS = {
    "timestamp",
    "event_at",
    "event_time",
    "activity_at",
    "created_at",
    "updated_at",
    "occurred_at",
    "recorded_at",
    "captured_at",
    "deleted_at",
    "restored_at",
    "requested_at",
}
TABLE_FILES = set(SUPPORTING_FILES.values()) | {
    "deletion_requests.csv",
    "sample_deletion_requests.csv",
    "sample_output.csv",
    "output.csv",
}
ARTIFACT_EXTENSIONS = {
    ".csv",
    ".json",
    ".jsonl",
    ".txt",
    ".log",
    ".pdf",
    ".sqlite",
    ".sqlite3",
    ".db",
    ".sql",
    ".png",
    ".jpg",
    ".jpeg",
    ".tif",
    ".tiff",
    ".bmp",
    ".webp",
}
ISO_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
KEY_VALUE = re.compile(
    r"""(?P<key>[A-Za-z_][A-Za-z0-9_.-]*)=(?:"(?P<double>(?:\\.|[^"])*)"|'(?P<single>(?:\\.|[^'])*)'|(?P<bare>[^\s]+))"""
)
IDENTITY_CONTEXT_FIELDS = {
    "lookup_key",
    "correlation_key",
    "customer_reference",
    "subject_reference",
    "subject_ref",
    "customer_id",
    "matched_value",
}
@dataclass
class EvidenceBundle:
    tables: dict = field(default_factory=dict)
    gaps: list = field(default_factory=list)
    artifacts: list = field(default_factory=list)


def _read_csv(path):
    with path.open(encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            return []
        return [
            {key: (value or "").strip() for key, value in row.items()}
            for row in reader
        ]


def _parse_datetime(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(
            str(value).strip().replace("Z", "+00:00")
        )
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _row_timestamps(row):
    values = [
        _parse_datetime(value)
        for key, value in row.items()
        if str(key).strip().casefold() in TIMESTAMP_FIELDS and value
    ]
    invalid = any(
        str(key).strip().casefold() in TIMESTAMP_FIELDS
        and value
        and _parse_datetime(value) is None
        for key, value in row.items()
    )
    return [value for value in values if value is not None], invalid


def _safe_file_id(path, root):
    return path.relative_to(root).as_posix()


def _read_sqlite(path):
    uri = path.resolve().as_uri() + "?mode=ro"
    rows = []
    with sqlite3.connect(uri, uri=True) as connection:
        tables = connection.execute(
            "SELECT name FROM sqlite_master "
            "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        for (table_name,) in tables:
            quoted_table = '"' + table_name.replace('"', '""') + '"'
            cursor = connection.execute(f"SELECT * FROM {quoted_table}")
            columns = [column[0] for column in cursor.description or ()]
            for values in cursor.fetchall():
                record = dict(zip(columns, values))
                record["__source_table"] = table_name
                rows.append(record)
    return rows


def _read_sql_dump(path):
    statements = []
    current = []
    with path.open(encoding="utf-8-sig") as source:
        for line in source:
            current.append(line)
            candidate = "".join(current)
            if sqlite3.complete_statement(candidate):
                statement = candidate.strip()
                current = []
                if statement:
                    statements.append(statement)
    trailing_content = "".join(current).strip()
    trailing_content = re.sub(
        r"(?m)^\s*--[^\n]*$", "", trailing_content
    )
    trailing_content = re.sub(r"/\*.*?\*/", "", trailing_content, flags=re.DOTALL)
    if trailing_content.strip():
        raise ValueError("SQL dump ends with an incomplete statement")

    connection = sqlite3.connect(":memory:")
    try:
        for statement in statements:
            normalized = statement.lstrip()
            if normalized.startswith("--") or normalized.startswith("/*"):
                normalized = re.sub(
                    r"^(?:\s|--[^\n]*(?:\n|$)|/\*.*?\*/)*",
                    "",
                    normalized,
                    flags=re.DOTALL,
                )
            if not normalized.strip("; \r\n\t"):
                continue
            if not re.match(
                r"(?is)^(?:CREATE\s+(?:TABLE|(?:UNIQUE\s+)?INDEX)\b|"
                r"INSERT\s+INTO\b|BEGIN\b|COMMIT\b|END\b|"
                r"PRAGMA\s+foreign_keys\s*=\s*(?:ON|OFF)\b)",
                normalized,
            ):
                raise ValueError(
                    "SQL dump contains a statement outside the safe snapshot subset"
                )
            connection.execute(normalized)
        connection.commit()
        return _read_sqlite_connection(connection)
    finally:
        connection.close()


def _read_sqlite_connection(connection):
    rows = []
    tables = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    for (table_name,) in tables:
        quoted_table = '"' + table_name.replace('"', '""') + '"'
        cursor = connection.execute(f"SELECT * FROM {quoted_table}")
        columns = [column[0] for column in cursor.description or ()]
        for values in cursor.fetchall():
            record = dict(zip(columns, values))
            record["__source_table"] = table_name
            rows.append(record)
    return rows


def _read_lines(path):
    rows = []
    with path.open(encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            text = line.strip()
            if not text:
                continue
            row = {"text": text, "line_number": str(line_number)}
            timestamp_match = ISO_TIMESTAMP.search(text)
            if timestamp_match:
                row["recorded_at"] = timestamp_match.group(0)
            json_start = text.find("{")
            if json_start >= 0:
                try:
                    json_fields = json.loads(text[json_start:])
                except json.JSONDecodeError:
                    json_fields = None
                if isinstance(json_fields, dict):
                    row.update(json_fields)
            for match in KEY_VALUE.finditer(text):
                value = next(
                    (
                        match.group(group)
                        for group in ("double", "single", "bare")
                        if match.group(group) is not None
                    ),
                    "",
                )
                row[match.group("key")] = value.replace(r"\"", '"').replace(
                    r"\\", "\\"
                )
            pipe_fields = [part.strip() for part in text.strip(" -").split("|")]
            if (
                len(pipe_fields) == 6
                and _parse_datetime(pipe_fields[0]) is not None
                and re.fullmatch(r"[A-Z][A-Z0-9_]+", pipe_fields[3])
                and re.fullmatch(r"[A-Z][A-Z0-9_]+", pipe_fields[4])
            ):
                row.update(
                    {
                        "recorded_at": pipe_fields[0],
                        "system_id": pipe_fields[1],
                        "resource_id": pipe_fields[2],
                        "category": pipe_fields[3],
                        "record_state": pipe_fields[4],
                    }
                )
                subject = pipe_fields[5]
                if "@" in subject:
                    row["email"] = subject
                elif subject.casefold().startswith("user_"):
                    row["user_id"] = subject
            rows.append(row)
    return rows


def _read_jsonl(path):
    rows = []
    with path.open(encoding="utf-8-sig") as source:
        for line_number, line in enumerate(source, start=1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                value = {"text": str(value)}
            value.setdefault("line_number", str(line_number))
            rows.append(value)
    return rows


def _read_pdf(path):
    try:
        from pypdf import PdfReader
    except ImportError as error:
        raise RuntimeError(
            "PDF support requires pypdf; install requirements.txt"
        ) from error
    from pypdf.errors import FileNotDecryptedError, PdfReadError

    try:
        reader = PdfReader(str(path))
        records = []
        for index, page in enumerate(reader.pages):
            text = page.extract_text() or ""
            if not text.strip():
                text = _ocr_pdf_page(path, index)
            record = {"text": text, "page_number": str(index + 1)}
            timestamp_match = ISO_TIMESTAMP.search(text)
            if timestamp_match:
                record["recorded_at"] = timestamp_match.group(0)
            records.append(record)
    except (FileNotDecryptedError, PdfReadError) as error:
        raise RuntimeError(f"PDF cannot be extracted: {error}") from error
    return records


def _ocr_image(image):
    try:
        import pytesseract
    except ImportError as error:
        raise RuntimeError(
            "Image OCR requires pytesseract; install requirements.txt"
        ) from error
    try:
        tesseract_cmd = os.environ.get("TESSERACT_CMD")
        if tesseract_cmd:
            pytesseract.pytesseract.tesseract_cmd = tesseract_cmd
        return pytesseract.image_to_string(image)
    except pytesseract.pytesseract.TesseractNotFoundError as error:
        raise RuntimeError(
            "Image OCR requires the Tesseract executable to be installed"
        ) from error
    except pytesseract.TesseractError as error:
        raise RuntimeError(f"Image OCR failed: {error}") from error


def _ocr_pdf_page(path, page_index):
    try:
        import fitz
        from PIL import Image
    except ImportError as error:
        raise RuntimeError(
            "Scanned PDF OCR requires PyMuPDF and Pillow; install requirements.txt"
        ) from error
    try:
        with fitz.open(path) as document:
            pixmap = document[page_index].get_pixmap()
        image = Image.open(BytesIO(pixmap.tobytes("png")))
        return _ocr_image(image)
    except (OSError, ValueError, RuntimeError) as error:
        raise RuntimeError(
            f"Could not OCR scanned PDF page {page_index + 1}: {error}"
        ) from error


def _read_image(path):
    try:
        from PIL import Image
    except ImportError as error:
        raise RuntimeError(
            "Image OCR requires Pillow; install requirements.txt"
        ) from error
    try:
        text = _ocr_image(Image.open(path))
    except (OSError, ValueError) as error:
        raise RuntimeError(f"Could not read image: {error}") from error
    record = {"text": text, "page_number": "1"}
    timestamp_match = ISO_TIMESTAMP.search(text)
    if timestamp_match:
        record["recorded_at"] = timestamp_match.group(0)
    return [record]


def _extract_file(path):
    suffix = path.suffix.casefold()
    if suffix == ".csv":
        return _read_csv(path)
    if suffix == ".json":
        content = json.loads(path.read_text(encoding="utf-8-sig"))
        return _flatten_json_records(content)
    if suffix == ".jsonl":
        return _read_jsonl(path)
    if suffix in {".txt", ".log"}:
        return _read_lines(path)
    if suffix in {".sqlite", ".sqlite3", ".db"}:
        return _read_sqlite(path)
    if suffix == ".sql":
        return _read_sql_dump(path)
    if suffix == ".pdf":
        return _read_pdf(path)
    if suffix in {".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".webp"}:
        return _read_image(path)
    return []


def _flatten_json_records(value, inherited=None):
    inherited = dict(inherited or {})
    if isinstance(value, list):
        records = []
        for item in value:
            records.extend(_flatten_json_records(item, inherited))
        return records
    if not isinstance(value, dict):
        return [{"text": str(value), **inherited}]

    current = dict(inherited)
    nested = {}
    for key, item in value.items():
        if isinstance(item, (dict, list)):
            nested[key] = item
        else:
            current[key] = item
    if not nested:
        return [current]

    records = []
    for key, child in nested.items():
        child_inherited = dict(current)
        source_path = child_inherited.get("__source_path", "")
        child_inherited["__source_path"] = ".".join(
            part for part in (source_path, str(key)) if part
        )
        records.extend(_flatten_json_records(child, child_inherited))
    return records


def _resolve_manifest_path(raw_path, roots):
    path_value = Path(raw_path)
    resolved_roots = [root.resolve() for root in roots]
    for root in resolved_roots:
        candidate = (root / path_value).resolve()
        if candidate == root or root in candidate.parents:
            if candidate.is_file():
                return candidate

    suffix_parts = path_value.parts
    if suffix_parts and suffix_parts[0].casefold() == "evidence":
        suffix_parts = suffix_parts[1:]
    if not suffix_parts:
        return None

    suffix_matches = set()
    for root in resolved_roots:
        if not root.is_dir():
            continue
        for candidate in root.rglob(suffix_parts[-1]):
            resolved_candidate = candidate.resolve()
            if (
                candidate.is_file()
                and root in resolved_candidate.parents
                and tuple(candidate.relative_to(root).parts[-len(suffix_parts):])
                == suffix_parts
            ):
                suffix_matches.add(resolved_candidate)
    if len(suffix_matches) == 1:
        return suffix_matches.pop()
    return None


def load_evidence(data_dir):
    data_dir = Path(data_dir).resolve()
    evidence_dir = data_dir / "evidence"
    roots = [data_dir]
    if evidence_dir.is_dir():
        roots.insert(0, evidence_dir)

    bundle = EvidenceBundle(tables={key: [] for key in SUPPORTING_FILES})
    for table_name, filename in SUPPORTING_FILES.items():
        path = next(
            (root / filename for root in roots if (root / filename).is_file()),
            None,
        )
        if path is None:
            bundle.gaps.append(f"Missing evidence source: {filename}")
            continue
        rows = _read_csv(path)
        if not rows:
            bundle.gaps.append(f"Evidence source is empty: {filename}")
        bundle.tables[table_name] = rows

    manifest_roots = [root for root in roots if root.is_dir()]
    manifest_rows = bundle.tables["evidence_files"]
    manifest_ids = {}
    manifest_timestamps = {}
    for row in manifest_rows:
        raw_path = _first_value(
            row, ("file_path", "path", "filename", "relative_path")
        )
        if not raw_path:
            bundle.gaps.append(
                "Evidence manifest row has no file path: "
                + (_first_value(row, ("file_id", "id")) or "unknown")
            )
            continue
        path = _resolve_manifest_path(raw_path, manifest_roots)
        if path is None:
            bundle.gaps.append(f"Evidence artifact is unavailable: {raw_path}")
            continue
        file_id = _first_value(row, ("file_id", "id"))
        if not file_id:
            bundle.gaps.append(
                f"Evidence manifest entry has no file_id: {raw_path}"
            )
            file_id = _safe_file_id(path, data_dir)
        manifest_ids[path] = file_id
        manifest_timestamps[path] = _first_value(
            row,
            ("captured_at", "snapshot_at", "collected_at", "observed_at"),
        )

    candidates = set(manifest_ids)
    artifact_roots = [evidence_dir] if evidence_dir.is_dir() else [data_dir]
    for root in artifact_roots:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.casefold() not in ARTIFACT_EXTENSIONS:
                continue
            if path.name.casefold() in TABLE_FILES:
                continue
            candidates.add(path.resolve())

    if not candidates:
        bundle.gaps.append("No local evidence artifacts were found.")

    for path in sorted(candidates, key=lambda item: item.as_posix().casefold()):
        file_id = manifest_ids.get(path, _safe_file_id(path, data_dir))
        if path not in manifest_ids:
            bundle.gaps.append(
                f"Evidence artifact is not listed in evidence_files.csv: {file_id}"
            )
        try:
            records = _extract_file(path)
        except (
            OSError,
            UnicodeError,
            csv.Error,
            json.JSONDecodeError,
            sqlite3.Error,
            RuntimeError,
            ValueError,
        ) as error:
            bundle.gaps.append(f"Could not read evidence artifact {file_id}: {error}")
            continue
        if not records:
            bundle.gaps.append(f"Evidence artifact has no readable records: {file_id}")
        for index, record in enumerate(records, start=1):
            timestamps, _ = _row_timestamps(record)
            if manifest_timestamps.get(path):
                record["__manifest_captured_at"] = manifest_timestamps[path]
            if not timestamps and manifest_timestamps.get(path):
                record["recorded_at"] = manifest_timestamps[path]
            record.setdefault("source_page_or_record", str(index))
        bundle.artifacts.append(
            {
                "file_id": file_id,
                "path": _safe_file_id(path, data_dir),
                "records": records,
            }
        )
    return bundle


def _row_matches_identity(row, values, text_pattern=None):
    normalized = {str(key).strip().casefold(): value for key, value in row.items()}
    for identity_type, aliases in IDENTIFIER_FIELDS.items():
        candidates = values[identity_type]
        for alias in aliases:
            value = normalized.get(alias)
            if value is not None and str(value).strip().casefold() in candidates:
                return True
    all_candidates = {
        candidate
        for candidates in values.values()
        for candidate in candidates
    }
    if any(
        str(normalized[field]).strip().casefold() in all_candidates
        for field in IDENTITY_CONTEXT_FIELDS
        if normalized.get(field) is not None
    ):
        return True
    if text_pattern is None:
        return False
    text = " ".join(
        str(value)
        for key, value in row.items()
        if str(key).strip().casefold()
        in {"text", "content", "message", "line", "details", "description"}
    ).casefold()
    return bool(text) and bool(text_pattern.search(text))


def records_for_identity(bundle, identity, audit_at=None):
    values = {
        field_name: {
            str(value).strip().casefold()
            for value in identity.get(field_name, set())
            if value
        }
        for field_name in IDENTIFIER_FIELDS
    }
    candidates = sorted(
        {value for grouped in values.values() for value in grouped},
        key=len,
        reverse=True,
    )
    text_pattern = (
        re.compile(
            r"(?<![A-Za-z0-9])(?:"
            + "|".join(re.escape(value) for value in candidates)
            + r")(?![A-Za-z0-9])",
            re.IGNORECASE,
        )
        if candidates
        else None
    )
    cutoff = _parse_datetime(audit_at) if isinstance(audit_at, str) else audit_at
    matches = []
    activity_rows = bundle.tables.get("system_activity", [])
    direct_activity_matches = []
    for source_name, rows in bundle.tables.items():
        for row in rows:
            if not _row_matches_identity(row, values, text_pattern):
                continue
            timestamps, invalid_timestamp = _row_timestamps(row)
            if cutoff is not None and invalid_timestamp:
                gap = f"Unparseable event timestamp in {source_name} evidence."
                if gap not in bundle.gaps:
                    bundle.gaps.append(gap)
                continue
            if cutoff is not None and source_name == "system_activity" and not timestamps:
                gap = "Matched system activity has no timestamp and cannot be placed at audit time."
                if gap not in bundle.gaps:
                    bundle.gaps.append(gap)
                continue
            if cutoff is not None and timestamps and max(timestamps) > cutoff:
                continue
            match = {"source": source_name, "record": row}
            matches.append(match)
            if source_name == "system_activity":
                direct_activity_matches.append(row)

    linked_resources = set()
    for row in direct_activity_matches:
        event_type = str(row.get("event_type", "")).strip().upper()
        if event_type != "LINK_RESOURCE_IDENTITY":
            continue
        if row.get("resource_id"):
            linked_resources.add(str(row["resource_id"]).casefold())

    matched_activity_ids = {
        str(row.get("activity_id", ""))
        for row in direct_activity_matches
    }
    for row in activity_rows:
        activity_id = str(row.get("activity_id", ""))
        if activity_id in matched_activity_ids:
            continue
        resource_id = str(row.get("resource_id", "")).casefold()
        if not resource_id or resource_id not in linked_resources:
            continue
        timestamps, invalid_timestamp = _row_timestamps(row)
        if cutoff is not None and (invalid_timestamp or not timestamps):
            continue
        if cutoff is not None and timestamps and max(timestamps) > cutoff:
            continue
        matches.append({"source": "system_activity", "record": row})
        if activity_id:
            matched_activity_ids.add(activity_id)

    for artifact in bundle.artifacts:
        artifact_matches = []
        for row in artifact["records"]:
            if not _row_matches_identity(row, values, text_pattern):
                continue
            timestamps, invalid_timestamp = _row_timestamps(row)
            if cutoff is not None and invalid_timestamp:
                gap = f"Unparseable event timestamp in artifact {artifact['path']}."
                if gap not in bundle.gaps:
                    bundle.gaps.append(gap)
                continue
            if cutoff is not None and not timestamps:
                gap = (
                    f"Evidence artifact {artifact['path']} has no timestamp or manifest capture time."
                )
                if gap not in bundle.gaps:
                    bundle.gaps.append(gap)
                continue
            if cutoff is not None and timestamps and max(timestamps) > cutoff:
                continue
            artifact_matches.append(row)
        matched_traces = {
            str(row.get("trace_id", "")).strip()
            for row in artifact_matches
            if str(row.get("trace_id", "")).strip()
        }
        matched_row_ids = {id(row) for row in artifact_matches}
        for row in artifact["records"]:
            trace_id = str(row.get("trace_id", "")).strip()
            if not trace_id or trace_id not in matched_traces or id(row) in matched_row_ids:
                continue
            timestamps, invalid_timestamp = _row_timestamps(row)
            if cutoff is not None and (invalid_timestamp or not timestamps):
                continue
            if cutoff is not None and timestamps and max(timestamps) > cutoff:
                continue
            artifact_matches.append(row)
        matches.extend(
            {
                "source": "evidence_artifact",
                "file_id": artifact["file_id"],
                "record": row,
            }
            for row in artifact_matches
        )

    return matches


def _first_value(row, aliases):
    normalized = {str(key).strip().casefold(): value for key, value in row.items()}
    for alias in aliases:
        value = normalized.get(alias.casefold())
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""
