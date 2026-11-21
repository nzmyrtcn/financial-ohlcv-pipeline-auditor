from __future__ import annotations

import os
from pathlib import Path
import tempfile
import time

try:
    from .schema_contract import (
        AuditState,
        AuditStateMachine,
        canonical_json_dumps,
        compute_jcs_sha256,
        count_non_finite_values,
        load_contract,
        validate_integrity_phase,
        validate_schema_phase,
    )
except ImportError:
    from schema_contract import (
        AuditState,
        AuditStateMachine,
        canonical_json_dumps,
        compute_jcs_sha256,
        count_non_finite_values,
        load_contract,
        validate_integrity_phase,
        validate_schema_phase,
    )


def _enforce_certification_lock(records: list[dict[str, object]], nan_inf_count: int, violations: list[dict[str, object]], final_state: AuditState) -> None:
    if final_state != AuditState.STATE_CERTIFIED:
        return
    if len(records) == 0 or nan_inf_count >= 1 or len(violations) > 0:
        raise ValueError('Contract boundary lock triggered')
    prev_ts_by_symbol: dict[str, int] = {}
    for rec in records:
        h = float(rec['high'])
        l = float(rec['low'])
        v = float(rec['volume'])
        sym = str(rec['symbol'])
        ts = int(rec['timestamp_utc'])
        if h < l or v < 0.0 or (sym in prev_ts_by_symbol and ts < prev_ts_by_symbol[sym]):
            raise ValueError('Contract boundary lock triggered')
        prev_ts_by_symbol[sym] = ts


def run_pipeline_audit(records: list[dict[str, object]], contract_path: str) -> dict[str, object]:
    started = time.perf_counter()
    if not isinstance(records, list) or len(records) == 0:
        raise ValueError('Contract boundary lock triggered: records must be a non-empty list')
    nan_inf_count = count_non_finite_values(records)
    if nan_inf_count > 0:
        raise ValueError(f'Contract boundary lock triggered: detected {nan_inf_count} NaN/Inf values')

    contract = load_contract(contract_path, timeout_sec=5.0)
    machine = AuditStateMachine()

    schema_violations = validate_schema_phase(records, contract)
    if schema_violations:
        machine.transition(AuditState.STATE_QUARANTINED, 'RULE_SCHEMA_COLUMNS_AND_TYPES')
        violations = schema_violations
    else:
        machine.transition(AuditState.STATE_SCHEMA_OK, 'RULE_SCHEMA_COLUMNS_AND_TYPES')
        integrity_violations = validate_integrity_phase(records, contract)
        if integrity_violations:
            machine.transition(AuditState.STATE_QUARANTINED, 'RULE_INTEGRITY_VIOLATION')
            violations = integrity_violations
        else:
            machine.transition(AuditState.STATE_INTEGRITY_OK, 'RULE_INTEGRITY_VERIFIED')
            machine.transition(AuditState.STATE_CERTIFIED, 'RULE_CERTIFICATION_FINALIZED')
            violations = []

    _enforce_certification_lock(records, nan_inf_count, violations, machine.current_state)

    bad_indices = {int(v['record_index']) for v in violations if isinstance(v.get('record_index'), int)}
    valid_records = len(records) - len(bad_indices)
    exit_code = 0 if machine.current_state == AuditState.STATE_CERTIFIED else 1

    core_payload: dict[str, object] = {
        'contract_id': str(contract.get('contract_id', 'financial_ohlcv_contract_v1')),
        'schema_version': str(contract.get('schema_version', '1.0.0')),
        'final_state': machine.current_state.value,
        'exit_code': exit_code,
        'total_records': len(records),
        'valid_records': valid_records,
        'nan_inf_count': nan_inf_count,
        'violation_count': len(violations),
        'violations': violations,
        'state_history': list(machine.history),
    }
    report_sha256 = compute_jcs_sha256(core_payload)
    elapsed_ms = round((time.perf_counter() - started) * 1000.0, 3)
    report = dict(core_payload)
    report['report_sha256'] = report_sha256
    report['elapsed_ms'] = elapsed_ms
    return report


def write_audit_report_atomic(report: dict[str, object], output_path: str, timeout_sec: float = 5.0) -> str:
    if not isinstance(timeout_sec, (int, float)) or isinstance(timeout_sec, bool) or float(timeout_sec) <= 0.0:
        raise ValueError('timeout_sec must be a positive number')
    started = time.monotonic()
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    serialized = canonical_json_dumps(report) + chr(10)
    tmp_path: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=str(out.parent), prefix=out.stem + '.', suffix='.tmp', delete=False) as tf:
            tmp_path = tf.name
            tf.write(serialized)
            tf.flush()
            os.fsync(tf.fileno())
        if (time.monotonic() - started) > float(timeout_sec):
            raise TimeoutError(f'Atomic report write exceeded timeout_sec={timeout_sec}')
        os.replace(tmp_path, out)
        tmp_path = None
    finally:
        if tmp_path is not None and os.path.exists(tmp_path):
            os.unlink(tmp_path)
    return str(out)
