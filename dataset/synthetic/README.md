# Synthetic-only audit fixture

Every person, email, user ID, record, activity, and policy rule in this folder is fictional and created solely to exercise the audit pipeline. Email addresses use the reserved `.test` domain.

Nothing in this folder is evidence about the supplied deletion requests, any real person, or any real platform. Do not merge these rows with `dataset/evidence/deletion_requests.csv` or present their results as actual findings.

Run with `python -m src.synthetic_demo`. Outputs are intentionally named `simulated_output.csv` and `evaluation/synthetic_evaluation_report.md`.

The six scenarios cover a deleted record, a record still present, a policy-retained record, an active sync process, an active restore path, and an explicit non-request.
