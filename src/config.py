from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATASET_DIR = ROOT / "dataset"
EVIDENCE_DIR = DATASET_DIR / "evidence"
OUTPUT_PATH = ROOT / "output.csv"
EVALUATION_DIR = ROOT / "evaluation"

REQUEST_FILE = "deletion_requests.csv"
SUPPORTING_FILES = {
    "user_identities": "user_identities.csv",
    "user_audit_log": "user_audit_log.csv",
    "system_activity": "system_activity.csv",
    "deletion_rules": "deletion_rules.csv",
    "evidence_files": "evidence_files.csv",
}