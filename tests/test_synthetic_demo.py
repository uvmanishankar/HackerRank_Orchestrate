import csv
import json

from src.synthetic_demo import run_synthetic_demo


def test_synthetic_demo_covers_required_scenarios(tmp_path):
    output = tmp_path / "simulated_output.csv"
    report = tmp_path / "synthetic_evaluation_report.md"
    results = run_synthetic_demo(output, report)

    with output.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    assert len(rows) == 6
    assert all(row["case_id"].startswith("SIM-") for row in rows)
    assert any(row["deletion_status"] == "COMPLETE" for row in rows)
    assert any(row["deletion_status"] == "INCOMPLETE" for row in rows)
    assert any(row["deletion_status"] == "NOT_APPLICABLE" for row in rows)
    assert all(
        isinstance(json.loads(row["steps_json"]), list) for row in rows
    )

    contents = report.read_text(encoding="utf-8")
    assert "SYNTHETIC SIMULATION" in contents
    assert "not derived from or evidence about the supplied 518 requests" in contents
    assert "Active synchronization process" in contents
    assert "Active restore process" in contents
