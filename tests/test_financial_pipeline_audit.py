from __future__ import annotations

import json
import math
from pathlib import Path
import sys

import pytest

SRC_DIR = str(Path(__file__).resolve().parent.parent / 'src')
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from audit_engine import run_pipeline_audit, write_audit_report_atomic
from schema_contract import (
    AuditState,
    AuditStateMachine,
    DETERMINISTIC_RULES,
    canonical_json_dumps,
)

CONTRACT_PATH = 'schemas/financial_ohlcv_contract_v1.json'


def _valid_bar(ts: int = 1700000000, symbol: str = 'EURUSD', o: float = 1.08, h: float = 1.085, l: float = 1.079, c: float = 1.082, v: float = 1200.0) -> dict[str, object]:
    return {
        'timestamp_utc': ts,
        'symbol': symbol,
        'open': o,
        'high': h,
        'low': l,
        'close': c,
        'volume': v,
    }


def test_valid_single_record_certified() -> None:
    report = run_pipeline_audit([_valid_bar()], CONTRACT_PATH)
    assert report['exit_code'] == 0
    assert report['final_state'] == AuditState.STATE_CERTIFIED.value
    assert report['total_records'] == 1
    assert report['valid_records'] == 1
    assert report['violation_count'] == 0
    assert report['violations'] == []
    assert report['state_history'] == ['STATE_UNVERIFIED', 'STATE_SCHEMA_OK', 'STATE_INTEGRITY_OK', 'STATE_CERTIFIED']
    assert float(report['elapsed_ms']) <= 500.0
    assert len(DETERMINISTIC_RULES) >= 5


def test_valid_multi_symbol_sequence_certified() -> None:
    records = [
        _valid_bar(1700000000, 'EURUSD'),
        _valid_bar(1700000000, 'GBPUSD', 1.25, 1.255, 1.248, 1.252, 850.0),
        _valid_bar(1700003600, 'EURUSD', 1.082, 1.086, 1.081, 1.084, 1500.0),
        _valid_bar(1700003600, 'GBPUSD', 1.252, 1.258, 1.25, 1.254, 920.0),
    ]
    report = run_pipeline_audit(records, CONTRACT_PATH)
    assert report['exit_code'] == 0
    assert report['final_state'] == 'STATE_CERTIFIED'
    assert report['total_records'] == 4
    assert report['violation_count'] == 0


def test_empty_records_fail_closed_value_error() -> None:
    with pytest.raises(ValueError):
        run_pipeline_audit([], CONTRACT_PATH)


@pytest.mark.parametrize('bad_val', [float('nan'), float('inf'), float('-inf')])
def test_nan_and_inf_fail_closed_value_error(bad_val: float) -> None:
    rec = _valid_bar()
    rec['close'] = bad_val
    with pytest.raises(ValueError):
        run_pipeline_audit([rec], CONTRACT_PATH)


def test_inverted_high_low_quarantined() -> None:
    rec = _valid_bar(h=1.075, l=1.081)
    report = run_pipeline_audit([rec], CONTRACT_PATH)
    assert report['final_state'] == 'STATE_QUARANTINED'
    assert report['exit_code'] == 1
    assert report['violation_count'] >= 1
    assert any(v['rule_id'] == 'RULE_OHLC_HIGH_ENVELOPE' for v in report['violations'])


def test_ohlc_envelope_violations_quarantined() -> None:
    rec_low_bad = _valid_bar(o=1.08, h=1.085, l=1.081, c=1.082)
    report = run_pipeline_audit([rec_low_bad], CONTRACT_PATH)
    assert report['final_state'] == 'STATE_QUARANTINED'
    assert any(v['rule_id'] == 'RULE_OHLC_LOW_ENVELOPE' for v in report['violations'])


def test_negative_volume_quarantined() -> None:
    rec = _valid_bar(v=-10.0)
    report = run_pipeline_audit([rec], CONTRACT_PATH)
    assert report['final_state'] == 'STATE_QUARANTINED'
    assert report['exit_code'] == 1
    assert any(v['rule_id'] == 'RULE_NON_NEGATIVE_VOLUME' for v in report['violations'])


def test_non_monotonic_timestamp_quarantined() -> None:
    records = [_valid_bar(1700000060, 'EURUSD'), _valid_bar(1700000000, 'EURUSD')]
    report = run_pipeline_audit(records, CONTRACT_PATH)
    assert report['final_state'] == 'STATE_QUARANTINED'
    assert any(v['rule_id'] == 'RULE_MONOTONIC_TIMESTAMP' for v in report['violations'])


def test_duplicate_composite_key_quarantined() -> None:
    records = [_valid_bar(1700000000, 'EURUSD'), _valid_bar(1700000000, 'EURUSD')]
    report = run_pipeline_audit(records, CONTRACT_PATH)
    assert report['final_state'] == 'STATE_QUARANTINED'
    assert any(v['rule_id'] == 'RULE_UNIQUE_COMPOSITE_KEY' for v in report['violations'])


def test_max_gap_exceeded_quarantined() -> None:
    records = [_valid_bar(1700000000, 'EURUSD'), _valid_bar(1700003601, 'EURUSD')]
    report = run_pipeline_audit(records, CONTRACT_PATH)
    assert report['final_state'] == 'STATE_QUARANTINED'
    assert any(v['rule_id'] == 'RULE_MAX_GAP_SECONDS' for v in report['violations'])


def test_missing_column_and_bool_rejected_in_schema_phase() -> None:
    rec = _valid_bar()
    del rec['volume']
    rec['open'] = True
    report = run_pipeline_audit([rec], CONTRACT_PATH)
    assert report['final_state'] == 'STATE_QUARANTINED'
    assert report['state_history'] == ['STATE_UNVERIFIED', 'STATE_QUARANTINED']
    assert report['violation_count'] >= 2


def test_missing_contract_raises_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        run_pipeline_audit([_valid_bar()], 'schemas/does_not_exist_v99.json')


def test_state_machine_illegal_transition_and_jcs_atomic_write(tmp_path: Path) -> None:
    sm = AuditStateMachine()
    with pytest.raises(ValueError):
        sm.transition(AuditState.STATE_CERTIFIED, 'ILLEGAL_JUMP')
    rec_a = {'volume': 1200.0, 'timestamp_utc': 1700000000, 'symbol': 'EURUSD', 'open': 1.08, 'low': 1.079, 'high': 1.085, 'close': 1.082}
    rec_b = _valid_bar()
    rep_a = run_pipeline_audit([rec_a], CONTRACT_PATH)
    rep_b = run_pipeline_audit([rec_b], CONTRACT_PATH)
    assert rep_a['report_sha256'] == rep_b['report_sha256']
    out_file = tmp_path / 'audit_report.json'
    written = write_audit_report_atomic(rep_a, str(out_file), timeout_sec=5.0)
    assert Path(written).is_file()
    loaded = json.loads(Path(written).read_text(encoding='utf-8'))
    assert loaded['report_sha256'] == rep_a['report_sha256']
    assert canonical_json_dumps({'b': 1, 'a': 2}) == '{"a":2,"b":1}'
