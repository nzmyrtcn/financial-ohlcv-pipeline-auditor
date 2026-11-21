# Financial OHLCV Pipeline Auditor

Contract-enforced schema and integrity gate for B2B financial OHLCV data feeds.

Silent feed corruption breaks downstream backtests and risk models long before an exception fires. A single `NaN` close price, a boolean sneaking into a numeric column, or an inverted high/low candle can skew aggregations for hours. This package stops bad batches at ingestion time.

## How the State Machine Works

Every batch enters `run_pipeline_audit` in `STATE_UNVERIFIED`. The engine checks structural rules before touching numeric invariants. If any check fails, the batch moves to `STATE_QUARANTINED` and returns `exit_code = 1`.

```text
STATE_UNVERIFIED
  |-- schema error ---------> STATE_QUARANTINED (exit_code = 1)
  v
STATE_SCHEMA_OK
  |-- integrity error ------> STATE_QUARANTINED (exit_code = 1)
  v
STATE_INTEGRITY_OK
  v
STATE_CERTIFIED (exit_code = 0)
```

Empty record lists and any `NaN` or `Inf` values trigger an immediate `ValueError` before state transitions start. Illegal transitions inside `AuditStateMachine` also raise `ValueError`.

## Enforced Contract Rules

The default contract in `schemas/financial_ohlcv_contract_v1.json` requires seven columns (`timestamp_utc`, `symbol`, `open`, `high`, `low`, `close`, `volume`) and enforces eight named rules defined in `src/schema_contract.py`:

| Rule ID | Phase | Check Enforced |
| --- | --- | --- |
| `RULE_SCHEMA_COLUMNS_AND_TYPES` | Schema | Non-null 7 columns, `int >= 1` timestamp (no bool), symbol regex `^[A-Z0-9._/-]+$` (1..32 chars), finite numeric OHLCV (no bool) |
| `RULE_POSITIVE_PRICES` | Integrity | `open`, `high`, `low`, `close` strictly `> 0.0` |
| `RULE_OHLC_HIGH_ENVELOPE` | Integrity | `high >= low` and `high >= max(open, close)` |
| `RULE_OHLC_LOW_ENVELOPE` | Integrity | `low <= min(open, close)` |
| `RULE_NON_NEGATIVE_VOLUME` | Integrity | `volume >= 0.0` |
| `RULE_UNIQUE_COMPOSITE_KEY` | Integrity | Unique `(symbol, timestamp_utc)` pairs within the batch |
| `RULE_MONOTONIC_TIMESTAMP` | Integrity | Non-decreasing `timestamp_utc` per symbol |
| `RULE_MAX_GAP_SECONDS` | Integrity | Per-symbol gap `<= max_gap_seconds` (contract range `1..3600`, default `3600`) |

## Canonical Hashing and Atomic Report Output

Audit reports are hashed over the core payload excluding `elapsed_ms`. `canonical_json_dumps` uses sorted keys and compact separators (`(",", ":")`) with `allow_nan=False`, so identical inputs yield the exact same `report_sha256` across runs.

`write_audit_report_atomic` writes the serialized JSON to a sibling `.tmp` file, flushes buffers with `os.fsync`, checks `timeout_sec`, and commits via `os.replace`. Failed writes clean up the temporary file in a `finally` block.

## Repository Layout

| Path | Role |
| --- | --- |
| `schemas/financial_ohlcv_contract_v1.json` | Canonical 7-column OHLCV schema and threshold config |
| `src/schema_contract.py` | State machine, contract loader (5 MB cap), JCS SHA-256 helpers, schema/integrity validators |
| `src/audit_engine.py` | `run_pipeline_audit`, secondary certification lock, `write_audit_report_atomic` |
| `tests/test_financial_pipeline_audit.py` | 15 pytest cases covering certification, quarantine, boundary locks, and atomic writes |
| `package_manifest.json` | Commercial package metadata (`FINANCIAL_PIPELINE_AUDIT`, USD 79.00) |
| `lemonsqueezy_listing.md` | Self-serve product specification for LemonSqueezy MoR |

## Usage

Zero paid or third-party runtime dependencies are required. The core modules run on the Python standard library alone (`pytest` is only needed to run the test suite).

```python
from pathlib import Path
import sys

sys.path.insert(0, str(Path("src").resolve()))

from audit_engine import run_pipeline_audit, write_audit_report_atomic

records = [
    {
        "timestamp_utc": 1700000000,
        "symbol": "EURUSD",
        "open": 1.08,
        "high": 1.085,
        "low": 1.079,
        "close": 1.082,
        "volume": 1200.0,
    }
]

report = run_pipeline_audit(records, "schemas/financial_ohlcv_contract_v1.json")
print(report["final_state"], report["report_sha256"])
write_audit_report_atomic(report, "out/audit_report.json", timeout_sec=5.0)
```

## Verification

Run the included test suite from the package root:

```bash
python -m pytest tests/test_financial_pipeline_audit.py -v
```

Observed run output: 15 passed in 0.27s (Python 3.14.10, pytest 9.1.1).

## Commercial Release

A packaged commercial release (v1.0, USD 79.00) with the full test suite and schema contract is available via LemonSqueezy:

- Checkout: https://nazim-data-ops.lemonsqueezy.com/checkout/buy/13f9594e-66cb-4b22-9b74-a3378bc2160d
