# Ghost Data Deletion Audit

A deterministic, offline-first audit pipeline for customer deletion requests. It resolves identity only from explicit identifiers, evaluates supplied deletion rules, considers linked activity/evidence at the request's audit time, and validates the final CSV before writing it.

## Current input coverage

The pipeline expects the request file at `dataset/deletion_requests.csv`, supporting CSVs in `dataset/`, and local evidence under `dataset/evidence/`. The data corpus and the entire `dataset/` folder are intentionally excluded from GitHub and `code.zip`; place your authorized local dataset in that location before running the audit. The project does not ship the supplied requests, canonical answers, or evidence artifacts.

The pipeline uses the supplied structured records and evidence that can be read locally. If a referenced artifact is missing, a full deletion audit for any dependent case cannot be established. The audit will not copy `reported_status`, invent identity links, or claim that records are absent. Its output is a conservative decision based on accessible evidence, not a replacement for missing evidence.

## Run

Python 3.10+ is recommended. The core audit uses the standard library; PDF/OCR support uses the packages listed in `requirements.txt`.

```powershell
python -m src.main
```

Or run the script directly from the project root:

```powershell
python src\main.py
```

The command writes:

- `output.csv` — exactly `case_id,deletion_status,steps_json`
- `evaluation\evaluation_report.md` — run counts and known evidence limitations
- `evaluation\usage_report.md` — full-dataset provider, model, call, token, and cost totals
- `code.zip` — source, tests, README, configuration template, and evaluation reports under the required `code\` directory, including `code\evaluation\evaluation_report.md` and `code\evaluation\usage_report.md`; corpus and generated output files are excluded

The source datasets are not included in `code.zip`.

## Test

```powershell
python -m pip install -r requirements.txt
python -m pytest -v
```

## Input layout

The audit loads the request file and supporting CSVs from `dataset\`. Evidence manifest paths are resolved relative to `dataset\` and `dataset\evidence\`, including a unique nested-path match when the on-disk evidence has an extra directory. Expected supporting files:

| File | Use |
| --- | --- |
| `user_identities.csv` | Current account identifiers |
| `user_audit_log.csv` | Historical identifier changes |
| `system_activity.csv` | Deletion, synchronization, import, and restore activity |
| `deletion_rules.csv` | Category/system-specific DELETE, REDACT, ANONYMIZE, or RETAIN policy |
| `evidence_files.csv` | Evidence artifact manifest (`file_id` and path fields) |

The identity resolver accepts explicit user IDs, emails, phones, and email hashes. It does not connect records by name and flags an email linked to multiple stable user IDs. The evidence reader supports CSV and JSON artifacts; missing, unsupported, unreadable, or empty evidence is recorded as a gap, never treated as evidence of absence. A retained audit record alone cannot establish that the primary account profile was deleted; an identity-linked profile lookup or profile record is required for a `COMPLETE` status. Rows with parseable event timestamps after `audit_at` are excluded from that case's findings.

## Output steps

Each `steps_json` value is a JSON array. Every step uses the required seven fields: `step_no`, `phase`, `system_id`, `resource_id`, `operation`, `state`, and `evidence_id`. The writer rejects extra or missing fields and invalid phase/operation/state combinations. The planner orders findings, remediation, and verification by the operation order in `src\remediation_planner.py`. `COMPLETE` rows contain evidence-linked verification steps only; proposed steps for `INCOMPLETE` rows have an empty `evidence_id`; `NOT_APPLICABLE` rows have no steps.

The audit decision is deterministic. LLM use is disabled by default and no credentials are required. `src\llm_service.py` exposes a validator for optional structured suggestions; model output cannot introduce an unknown evidence ID or unsupported operation/state.

## Local evidence and evaluation

`src\evidence_loader.py` reads the provided structured CSV tables and recursively discovers local evidence under `dataset\evidence\`. It supports CSV, JSON/JSONL, key-value and pipe-delimited text/log records, and read-only SQLite snapshots. Nested JSON service hierarchy is retained as context when interpreting otherwise sparse lookup records. Record-level event or observation timestamps control historical scoping; manifest capture time is used when the record has no timestamp, so a later export does not overwrite an explicit historical observation. It also supports PDF text extraction with `pypdf`, scanned PDF rendering with PyMuPDF, and image OCR with Pillow, `pytesseract`, and the separately installed Tesseract executable. An unreadable or unsupported artifact is reported as an evidence gap; it is not treated as proof that data is absent. Unmanifested artifacts can be inspected but are flagged because their provenance is not in `evidence_files.csv`.

For OCR, install the Tesseract executable locally. If it is not on `PATH`, set the `TESSERACT_CMD` environment variable to its executable path before running the audit. The updated dataset includes PDFs, images, logs, JSON, and SQL snapshots. Image evidence cannot be read if the Tesseract executable is unavailable; such failures are listed in the evaluation report and are never treated as proof that the underlying records are absent.

When `dataset\sample_deletion_requests.csv` and `dataset\sample_output.csv` are available, the run evaluates the sample cases and reports case-status, step, field, and sequence metrics. Those measured scores are not a guarantee of hidden-case accuracy. Six fictional scenarios are included under `dataset\synthetic\` as additional evaluation cases; they are never used as evidence for the supplied requests.

## Synthetic demonstration

An optional synthetic demonstration can be run when its fictional fixtures are present in `dataset\synthetic\`. These use reserved `.test` email addresses and demonstrate historical identity resolution, an already-deleted record, a record still present, a permitted retained record, an active sync job, an active restore job, and a non-request. They are not associated with the supplied request CSV or any real person. The fixtures are excluded from GitHub and `code.zip`.

Run only the synthetic scenarios with:

```powershell
python -m src.synthetic_demo
```

This writes `simulated_output.csv` and `evaluation\synthetic_evaluation_report.md`. Both are explicitly labeled as simulated and must not be presented as verified findings about the supplied requests.
