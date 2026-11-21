from __future__ import annotations

from enum import Enum
import hashlib
import json
import math
from pathlib import Path
import re
import time

REQUIRED_COLUMNS: tuple[str, ...] = ('timestamp_utc', 'symbol', 'open', 'high', 'low', 'close', 'volume')
NUMERIC_COLUMNS: tuple[str, ...] = ('open', 'high', 'low', 'close', 'volume')
MAX_CONTRACT_BYTES: int = 5 * 1024 * 1024
DEFAULT_SYMBOL_PATTERN: str = r'^[A-Z0-9._/-]+$'

DETERMINISTIC_RULES: tuple[str, ...] = ('RULE_SCHEMA_COLUMNS_AND_TYPES', 'RULE_OHLC_HIGH_ENVELOPE', 'RULE_OHLC_LOW_ENVELOPE', 'RULE_POSITIVE_PRICES', 'RULE_NON_NEGATIVE_VOLUME', 'RULE_MONOTONIC_TIMESTAMP', 'RULE_UNIQUE_COMPOSITE_KEY', 'RULE_MAX_GAP_SECONDS')


class AuditState(str, Enum):
    STATE_UNVERIFIED = 'STATE_UNVERIFIED'
    STATE_SCHEMA_OK = 'STATE_SCHEMA_OK'
    STATE_INTEGRITY_OK = 'STATE_INTEGRITY_OK'
    STATE_QUARANTINED = 'STATE_QUARANTINED'
    STATE_CERTIFIED = 'STATE_CERTIFIED'


ALLOWED_TRANSITIONS: dict[AuditState, frozenset[AuditState]] = {
    AuditState.STATE_UNVERIFIED: frozenset({AuditState.STATE_SCHEMA_OK, AuditState.STATE_QUARANTINED}),
    AuditState.STATE_SCHEMA_OK: frozenset({AuditState.STATE_INTEGRITY_OK, AuditState.STATE_QUARANTINED}),
    AuditState.STATE_INTEGRITY_OK: frozenset({AuditState.STATE_CERTIFIED, AuditState.STATE_QUARANTINED}),
    AuditState.STATE_QUARANTINED: frozenset(),
    AuditState.STATE_CERTIFIED: frozenset(),
}


class AuditStateMachine:
    def __init__(self) -> None:
        self.current_state: AuditState = AuditState.STATE_UNVERIFIED
        self.history: list[str] = [self.current_state.value]
        self.transition_rules: list[str] = []

    def transition(self, next_state: AuditState, rule_id: str) -> AuditState:
        allowed = ALLOWED_TRANSITIONS.get(self.current_state, frozenset())
        if next_state not in allowed:
            raise ValueError(f'Illegal state transition: {self.current_state.value} -> {next_state.value}')
        self.current_state = next_state
        self.history.append(next_state.value)
        self.transition_rules.append(rule_id)
        return self.current_state


def canonical_json_dumps(payload: object) -> str:
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


def compute_jcs_sha256(payload: object) -> str:
    return hashlib.sha256(canonical_json_dumps(payload).encode('utf-8')).hexdigest()


def _is_int_non_bool(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number_non_bool(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def resolve_contract_path(contract_path: str) -> Path:
    if not isinstance(contract_path, str) or not contract_path.strip():
        raise ValueError('contract_path must be a non-empty string')
    candidate = Path(contract_path)
    if candidate.is_file():
        return candidate
    if not candidate.is_absolute():
        showcase_candidate = Path(__file__).resolve().parent.parent / candidate
        if showcase_candidate.is_file():
            return showcase_candidate
    raise FileNotFoundError(f'Contract file not found: {contract_path}')


def load_contract(contract_path: str, timeout_sec: float = 5.0) -> dict[str, object]:
    if not _is_number_non_bool(timeout_sec) or float(timeout_sec) <= 0.0:
        raise ValueError('timeout_sec must be a positive number')
    started = time.monotonic()
    resolved = resolve_contract_path(contract_path)
    size_bytes = resolved.stat().st_size
    if size_bytes > MAX_CONTRACT_BYTES:
        raise ValueError(f'Contract file exceeds max allowed bytes: {size_bytes}')
    raw_text = resolved.read_text(encoding='utf-8')
    if (time.monotonic() - started) > float(timeout_sec):
        raise TimeoutError(f'Contract load exceeded timeout_sec={timeout_sec}')
    contract = json.loads(raw_text)
    if not isinstance(contract, dict):
        raise ValueError('Contract JSON root must be an object')
    req_cols = contract.get('required_columns')
    if req_cols != list(REQUIRED_COLUMNS):
        raise ValueError('Contract required_columns must match canonical 7 OHLCV columns')
    constraints = contract.get('constraints')
    if not isinstance(constraints, dict):
        raise ValueError('Contract constraints section is required')
    max_gap = constraints.get('max_gap_seconds')
    if not _is_int_non_bool(max_gap) or max_gap <= 0 or max_gap > 3600:
        raise ValueError('Contract max_gap_seconds must be an integer in range [1, 3600]')
    return contract


def count_non_finite_values(records: list[dict[str, object]]) -> int:
    bad_count = 0
    for rec in records:
        if not isinstance(rec, dict):
            continue
        for val in rec.values():
            if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                bad_count += 1
    return bad_count


def validate_schema_phase(records: list[dict[str, object]], contract: dict[str, object]) -> list[dict[str, object]]:
    violations: list[dict[str, object]] = []
    col_types = contract.get('column_types', {})
    symbol_spec = col_types.get('symbol', {}) if isinstance(col_types, dict) else {}
    pattern_str = str(symbol_spec.get('pattern', DEFAULT_SYMBOL_PATTERN))
    symbol_re = re.compile(pattern_str)
    min_len = int(symbol_spec.get('min_length', 1))
    max_len = int(symbol_spec.get('max_length', 32))
    ts_spec = col_types.get('timestamp_utc', {}) if isinstance(col_types, dict) else {}
    min_ts = int(ts_spec.get('min', 1))
    for idx, rec in enumerate(records):
        if not isinstance(rec, dict):
            violations.append({'record_index': idx, 'rule_id': 'RULE_SCHEMA_COLUMNS_AND_TYPES', 'field': '__record__', 'detail': 'Record must be a dictionary'})
            continue
        for col in REQUIRED_COLUMNS:
            if col not in rec or rec[col] is None:
                violations.append({'record_index': idx, 'rule_id': 'RULE_SCHEMA_COLUMNS_AND_TYPES', 'field': col, 'detail': f'Missing required column: {col}'})
        if 'timestamp_utc' in rec and rec['timestamp_utc'] is not None:
            ts_val = rec['timestamp_utc']
            if not _is_int_non_bool(ts_val) or int(ts_val) < min_ts:
                violations.append({'record_index': idx, 'rule_id': 'RULE_SCHEMA_COLUMNS_AND_TYPES', 'field': 'timestamp_utc', 'detail': f'timestamp_utc must be int >= {min_ts}'})
        if 'symbol' in rec and rec['symbol'] is not None:
            sym = rec['symbol']
            if not isinstance(sym, str) or len(sym) < min_len or len(sym) > max_len or not symbol_re.match(sym):
                violations.append({'record_index': idx, 'rule_id': 'RULE_SCHEMA_COLUMNS_AND_TYPES', 'field': 'symbol', 'detail': 'Invalid symbol string format or length'})
        for num_col in NUMERIC_COLUMNS:
            if num_col in rec and rec[num_col] is not None:
                if not _is_number_non_bool(rec[num_col]):
                    violations.append({'record_index': idx, 'rule_id': 'RULE_SCHEMA_COLUMNS_AND_TYPES', 'field': num_col, 'detail': f'{num_col} must be a finite int or float'})
    return violations


def check_ohlc_high_envelope(rec: dict[str, object], idx: int) -> list[dict[str, object]]:
    violations: list[dict[str, object]] = []
    o = float(rec['open'])
    h = float(rec['high'])
    l = float(rec['low'])
    c = float(rec['close'])
    if h < l:
        violations.append({'record_index': idx, 'rule_id': 'RULE_OHLC_HIGH_ENVELOPE', 'field': 'high', 'detail': f'high ({h}) < low ({l})'})
    if h < max(o, c):
        violations.append({'record_index': idx, 'rule_id': 'RULE_OHLC_HIGH_ENVELOPE', 'field': 'high', 'detail': f'high ({h}) < max(open={o}, close={c})'})
    return violations


def check_ohlc_low_envelope(rec: dict[str, object], idx: int) -> list[dict[str, object]]:
    o = float(rec['open'])
    l = float(rec['low'])
    c = float(rec['close'])
    if l > min(o, c):
        return [{'record_index': idx, 'rule_id': 'RULE_OHLC_LOW_ENVELOPE', 'field': 'low', 'detail': f'low ({l}) > min(open={o}, close={c})'}]
    return []


def check_positive_prices(rec: dict[str, object], idx: int) -> list[dict[str, object]]:
    violations: list[dict[str, object]] = []
    for field in ('open', 'high', 'low', 'close'):
        val = float(rec[field])
        if val <= 0.0:
            violations.append({'record_index': idx, 'rule_id': 'RULE_POSITIVE_PRICES', 'field': field, 'detail': f'{field} ({val}) must be > 0.0'})
    return violations


def check_non_negative_volume(rec: dict[str, object], idx: int) -> list[dict[str, object]]:
    vol = float(rec['volume'])
    if vol < 0.0:
        return [{'record_index': idx, 'rule_id': 'RULE_NON_NEGATIVE_VOLUME', 'field': 'volume', 'detail': f'volume ({vol}) < 0.0'}]
    return []


def validate_integrity_phase(records: list[dict[str, object]], contract: dict[str, object]) -> list[dict[str, object]]:
    violations: list[dict[str, object]] = []
    constraints = contract['constraints']
    max_gap_seconds = int(constraints['max_gap_seconds'])
    seen_keys: set[tuple[str, int]] = set()
    last_ts_by_symbol: dict[str, int] = {}
    for idx, rec in enumerate(records):
        violations.extend(check_positive_prices(rec, idx))
        violations.extend(check_ohlc_high_envelope(rec, idx))
        violations.extend(check_ohlc_low_envelope(rec, idx))
        violations.extend(check_non_negative_volume(rec, idx))
        sym = str(rec['symbol'])
        ts = int(rec['timestamp_utc'])
        key = (sym, ts)
        if key in seen_keys:
            violations.append({'record_index': idx, 'rule_id': 'RULE_UNIQUE_COMPOSITE_KEY', 'field': 'timestamp_utc', 'detail': f'Duplicate composite key ({sym}, {ts})'})
        else:
            seen_keys.add(key)
        if sym in last_ts_by_symbol:
            prev_ts = last_ts_by_symbol[sym]
            if ts < prev_ts:
                violations.append({'record_index': idx, 'rule_id': 'RULE_MONOTONIC_TIMESTAMP', 'field': 'timestamp_utc', 'detail': f'Non-monotonic timestamp for {sym}: {ts} < {prev_ts}'})
            elif (ts - prev_ts) > max_gap_seconds:
                violations.append({'record_index': idx, 'rule_id': 'RULE_MAX_GAP_SECONDS', 'field': 'timestamp_utc', 'detail': f'Gap {ts - prev_ts}s exceeds max_gap_seconds={max_gap_seconds} for {sym}'})
        last_ts_by_symbol[sym] = ts if sym not in last_ts_by_symbol else max(last_ts_by_symbol[sym], ts)
    return violations
