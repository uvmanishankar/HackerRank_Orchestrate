# Evaluation report

## Run summary

- Cases audited: 518
- Status counts: {"COMPLETE": 35, "INCOMPLETE": 482, "NOT_APPLICABLE": 1}
- Ground-truth sample output: available for comparison.
- Evaluation uses the supplied source data only; no status is inferred from `reported_status`.

## Evidence limitations

- None reported.

## Accuracy metrics

- Evaluation sample size: 32 cases.
- Case/status accuracy: 68.75% (correct deletion_status / sample cases).
- Exact output-row accuracy: 15.62% (status and complete steps_json array both match).
- Exact step accuracy: 24.87% (exact step objects / expected steps).
- Step-field accuracy: 46.63% (matching required step fields / expected step fields).
- Sequence accuracy: 15.62% (exact ordered steps_json arrays / sample cases).
- Expected reference steps: 193; positionally aligned actual steps: 149.

## Additional team evaluation cases

| Case | Expected behavior |
|---|---|
| Synthetic deleted record | COMPLETE with evidence-backed absence verification |
| Synthetic record still present | INCOMPLETE with ordered delete and verification plan |
| Synthetic retained record | COMPLETE only when permitted identifiers remain |
| Synthetic active sync | INCOMPLETE with disable-flow and verification steps |
| Synthetic active restore | INCOMPLETE with block-restore and verification steps |
| Synthetic non-request | NOT_APPLICABLE with an empty steps array |

These are fictional scenarios from `dataset/synthetic/`; they are not findings about supplied requests.

## Failures found

- The 32-case canonical sample scored 15.62% exact output-row accuracy; 15.62% of ordered step sequences matched.
- Exact step accuracy was 24.87% and required step-field accuracy was 46.63%; only 149 of 193 expected steps aligned by position.
- These sample mismatches show the current discovery and remediation planning do not yet reproduce the reference answers; passing unit tests is not evidence of hidden-set accuracy.
- No source-level evidence ingestion gaps were detected; per-case evidence sufficiency is still checked independently.

## Improvements made

- Added strict allowed phase/operation/state and exact output-step schema validation.
- Added manifest and recursive local evidence ingestion for structured files, logs, PDFs, SQLite snapshots, and OCR-capable images.
- Preserved nested JSON service context and interpreted structured lookup results and contact-lookup rows using their observed states.
- Used record-level observation timestamps ahead of manifest export time, with manifest capture time as a fallback for untimestamped records.
- Removed unsupported numeric user/resource-ID suffix inference so it cannot fabricate absence findings.
- Required identity-linked primary-profile evidence before declaring the deletion complete.
- Resolved uniquely matching evidence files nested below an additional directory when their manifest-relative path was not present directly.
- Accepted the supplied SQL snapshot foreign-key pragma and trailing metadata comments while continuing to reject unsupported SQL statements.
- Added optional canonical sample comparison for case status, step fields, and sequence.
- Evaluation reports case/status, exact output-row, exact-step, step-field, and ordered-sequence metrics separately; sample metrics do not represent hidden-set accuracy.

- Verified request timestamps and unique case identifiers.
- Tested missing identity, policy, and evidence sources as evidence gaps.
- Tested CSV/JSON/log/SQLite/PDF evidence ingestion and audit-time filtering.
- Tested output JSON, status, exact fields, operation/state, and step-order validation.
