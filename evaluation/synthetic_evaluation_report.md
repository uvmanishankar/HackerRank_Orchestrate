# SYNTHETIC SIMULATION — NOT VERIFIED FINDINGS

> Every identity, record, activity, policy, and result in this report is fictional. These simulated cases are not derived from or evidence about the supplied 518 requests.

## Run summary

- Synthetic scenarios: 6
- Status counts: {'COMPLETE': 2, 'INCOMPLETE': 3, 'NOT_APPLICABLE': 1}
- Simulated output: `simulated_output.csv`
- This is a functional simulation, not an independent ground-truth accuracy measurement.

## Scenario results

| Synthetic case | Scenario | Result | Steps |
|---|---|---|---:|
| SIM-001 | Historical email; record deleted | COMPLETE | 1 |
| SIM-002 | Record remains present | INCOMPLETE | 3 |
| SIM-003 | Required retained record | COMPLETE | 1 |
| SIM-004 | Active synchronization process | INCOMPLETE | 4 |
| SIM-005 | Active restore process | INCOMPLETE | 4 |
| SIM-006 | Explicit non-request | NOT_APPLICABLE | 0 |

## Interpretation

These scenarios exercise identity history, record deletion, retention, active sync/restore risks, and a non-request. The case-to-scenario mapping comes from the fixture CSV, not from case-specific decision logic.

All steps and statuses in `simulated_output.csv` are demonstrations against fabricated test fixtures only. Do not represent them as findings about actual users or the supplied request CSV.

## Fixture evidence gaps

- None in this synthetic fixture.
