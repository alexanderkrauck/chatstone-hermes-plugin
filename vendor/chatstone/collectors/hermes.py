"""Explicit Hermes SQLite input; no discovery or connection at import time.

The SQLite path is checked through no-follow directory descriptors and all
sidecars are checked before connecting. Stdlib SQLite still opens by pathname:
this is not a VFS-level guarantee against a concurrent malicious rename. Run
against a trusted local store directory, not an attacker-controlled upload.
"""
from __future__ import annotations

import json
import os
import sqlite3
import stat
import time
from collections import defaultdict
from itertools import islice
from pathlib import Path

from .binary import text_digest
from .contracts import Part
from .normalization import record
from .policy import SourceDenied, checked_path, directory_anchor

_FIELDS = (
    "id", "session_id", "role", "content", "tool_call_id", "tool_calls", "tool_name",
    "timestamp", "reasoning", "reasoning_content", "reasoning_details",
    "codex_reasoning_items", "message_uid", "active", "compacted", "api_content",
)


# Keep the legacy scalar projection frozen; capture facts are strictly optional.
_INPUT_FIELDS = ('_compressed_summary', 'display_kind', 'platform_message_id')
_DISPLAY_KINDS = frozenset({'hidden', 'steer', 'internal_notification', 'process_complete',
    'async_delegation_complete', 'model_switch', 'personality_switch', 'failed_turn'})
_INPUT_PLATFORMS = frozenset({'local', 'telegram', 'discord', 'whatsapp', 'whatsapp_cloud',
    'slack', 'signal', 'mattermost', 'matrix', 'email', 'sms', 'dingtalk', 'api_server',
    'webhook', 'msgraph_webhook', 'feishu', 'wecom', 'wecom_callback', 'weixin',
    'bluebubbles', 'qqbot', 'relay', 'irc', 'teams'})
_ADMISSION_BYTES = 256 * 1024


def _locator(value):
    # Never coerce, truncate or normalize an identifier used in an exact join.
    try:
        return (isinstance(value, str) and 0 < len(value) <= 1024
                and all(c.isprintable() for c in value) and len(value.encode('utf-8')) <= 4096)
    except UnicodeEncodeError:
        return False


def _valid_native_input(value):
    """Closed transport shape; arbitrary source JSON dictionaries remain invalid."""
    required = {'basis', 'join', 'request_id', 'message_uid', 'intent', 'platform',
                'internal', 'automation'}
    return (isinstance(value, dict) and required <= value.keys()
            and value.keys() <= required | {'sender_id', 'source_is_bot'}
            and value['basis'] == 'hermes.native_text_v1'
            and value['join'] == 'same_session_request_id_message_uid'
            and all(_locator(value[k]) for k in ('request_id', 'message_uid'))
            and value['intent'] in ('queue', 'steer', 'redirect')
            and isinstance(value['platform'], str) and value['platform'] in _INPUT_PLATFORMS
            and type(value['internal']) is bool and type(value['automation']) is bool
            and value['internal'] == value['automation']
            and ('sender_id' not in value or _locator(value['sender_id']))
            and ('source_is_bot' not in value or type(value['source_is_bot']) is bool))


def _input_selection(columns):
    # No display_metadata, admission text or arbitrary metadata is selected into raw.
    def select(name):
        if name not in columns:
            return f'NULL AS "{name}"'
        if name in ('display_kind', 'platform_message_id'):
            return (f"CASE WHEN typeof(m.\"{name}\")='text' THEN CAST(m.\"{name}\" AS BLOB) "
                    f'END AS "{name}"')
        return f'm."{name}"'
    return ', '.join(select(name) for name in (*_FIELDS, *_INPUT_FIELDS))


def _admissions_supported(connection):
    columns = {r[1] for r in connection.execute('PRAGMA table_info(session_admissions)')}
    return {'target_session_id', 'request_id', 'payload_json', 'intent'} <= columns


def _optional_text(value):
    if isinstance(value, bytes):
        try:
            return value.decode('utf-8')
        except UnicodeDecodeError:
            return None
    return value


def _capture_joins(connection, locators, columns):
    """Bounded locator-only joins; at most one ledger-session scan per256 rows.

    Native messages have (session_id,platform_message_id), but the admission
    index leads with (target_session_id,status,seq), not request_id. Batch the
    latter instead of walking one concentrated session for every user input.
    Retain at most two candidates per requested pair, never a full-ledger cache.
    Payloads are fetched only by unique physical rowid, one at a time.
    """
    if not {'message_uid', 'platform_message_id'} <= columns:
        return {}
    wanted = set()
    for locator in locators:
        metadata = connection.execute(
            "SELECT session_id,role,message_uid,CASE WHEN typeof(platform_message_id)='text' "
            "THEN CAST(platform_message_id AS BLOB) END "
            'FROM messages WHERE rowid=?', (locator,)).fetchone()
        if metadata is None:
            raise SourceDenied('ACQUISITION_LOCATOR_MISSING')
        session, role, uid, request = metadata
        request = _optional_text(request)
        if role == 'user' and _locator(uid) and _locator(request):
            wanted.add((session, request))
    if not wanted:
        return {}
    sessions = tuple({s for s, r in wanted})
    requests = tuple({r for s, r in wanted})
    def marks(values):
        return ','.join('?' for _ in values)
    params = (*sessions, *requests)
    targets = {key: set() for key in wanted}
    for session, request, uid, role in connection.execute(
            "SELECT session_id,CAST(platform_message_id AS BLOB),CASE WHEN typeof(message_uid)='text' "
            "THEN CAST(message_uid AS BLOB) END,role "
            f'FROM messages WHERE session_id IN ({marks(sessions)}) '
            f'AND platform_message_id IN ({marks(requests)})', params):
        key = session, _optional_text(request)
        if key in targets and len(targets[key]) < 2:
            targets[key].add((_optional_text(uid), role))
    admissions = {key: [] for key in wanted}
    for rowid, session, request in connection.execute(
            'SELECT rowid,target_session_id,CAST(request_id AS BLOB) '
            f'FROM session_admissions WHERE target_session_id IN ({marks(sessions)}) '
            f'AND request_id IN ({marks(requests)})', params):
        key = session, _optional_text(request)
        if key in admissions and len(admissions[key]) < 2:
            admissions[key].append(rowid)
    return {key: (next(iter(targets[key]))[0], rows[0]) for key, rows in admissions.items()
            if len(rows) == 1 and len(targets[key]) == 1
            and next(iter(targets[key]))[1] == 'user'}


def _capture_input(connection, raw, joins):
    """Source facts only; neither a human-input classifier nor an owner binding.

    Qualified against Hermes 3b421578's native_text_v1 codec: ordinary snapshots
    reject internal events; automation snapshots restore internal=True. The actual
    event sender is separate from source.user_id and the dispatch principal.
    Every lookup shares the message reader's existing read-only BEGIN snapshot.
    """
    summary = raw.pop('_compressed_summary')
    if type(summary) is int and summary in (0, 1):
        raw['_compressed_summary'] = bool(summary)
    kind = _optional_text(raw.pop('display_kind'))
    if isinstance(kind, str) and kind in _DISPLAY_KINDS:
        raw['display_kind'] = kind
    request = _optional_text(raw.pop('platform_message_id'))
    if _locator(request):
        raw['platform_message_id'] = request
    uid = raw.get('message_uid')
    match = joins.get((raw['session_id'], request))
    if not (raw['role'] == 'user' and _locator(uid) and match and match[0] == uid):
        return raw
    encoded, intent = connection.execute(
        "SELECT CASE WHEN typeof(payload_json)='text' AND length(CAST(payload_json AS BLOB))<=? "
        'THEN CAST(payload_json AS BLOB) END,intent FROM session_admissions WHERE rowid=?',
        (_ADMISSION_BYTES, match[1])).fetchone()
    if not isinstance(encoded, bytes) or intent not in ('queue', 'steer', 'redirect'):
        return raw
    try:
        payload = json.loads(encoded)
    except (ValueError, RecursionError):
        return raw
    if (not isinstance(payload, dict) or set(payload) != {'text', 'native_text_v1'}
            or not isinstance(payload['text'], str)):
        return raw
    envelope = payload['native_text_v1']
    if not isinstance(envelope, dict):
        return raw
    source, event = envelope.get('source'), envelope.get('event')
    if (not isinstance(source, dict) or not isinstance(event, dict)
            or 'internal' in event):  # not an event field of the qualified native codec
        return raw
    platform = source.get('platform')
    if (not isinstance(platform, str) or platform not in _INPUT_PLATFORMS
            or event.get('message_id') != request):
        return raw
    automation = 'automation' in envelope
    if automation and not isinstance(envelope['automation'], dict):
        return raw
    facts = {'basis': 'hermes.native_text_v1', 'join': 'same_session_request_id_message_uid',
             'request_id': request, 'message_uid': uid, 'intent': intent, 'platform': platform,
             'internal': automation, 'automation': automation}
    if _locator(event.get('user_id')):
        facts['sender_id'] = event['user_id']
    if type(source.get('is_bot')) is bool:
        facts['source_is_bot'] = source['is_bot']
    raw['native_input'] = facts
    return raw


def legacy_capture_raw(data):
    """Comparison only; remove supplemental capture fields, never other raw data.

    Never send this projection or replace a retained original with it. An exact
    legacy *wire* fingerprint match permits prospective-only capture upgrades.
    """
    from .hermes_reader import _decode
    from .normalization import canonical

    try:
        raw = _decode(data)
    except (ValueError, TypeError, RecursionError):
        return None
    legacy = {k: v for k, v in raw.items() if k not in {*_INPUT_FIELDS, 'native_input'}}
    return canonical(legacy) if legacy != raw else None


def _parts(raw, limits):
    parts, warnings = [], []
    if raw["tool_calls"] not in (None, ""):
        try:
            calls = json.loads(raw["tool_calls"])
            if not isinstance(calls, list):
                raise TypeError
            for call in calls:
                if not isinstance(call, dict) or not isinstance(call.get("function"), dict):
                    warnings.append("TOOL_CALLS_INVALID")
                    continue
                function = call["function"]
                if not all(isinstance(value, (str, type(None))) for value in (
                    call.get("id"), function.get("name"), function.get("arguments")
                )):
                    warnings.append("TOOL_CALLS_INVALID")
                    continue
                parts.append(Part(kind="tool_call", call_id=call.get("id"),
                                  name=function.get("name"), arguments_json=function.get("arguments")))
        except (ValueError, TypeError, RecursionError):
            warnings.append("TOOL_CALLS_INVALID")
    aliases = [raw[name] for name in ("reasoning", "reasoning_content") if raw[name] is not None]
    for text in dict.fromkeys(aliases):
        parts.append(Part(kind="reasoning", text=text))
    if len(set(aliases)) > 1:
        warnings.append("REASONING_ALIASES_DIFFER")
    for name in ("reasoning_details", "codex_reasoning_items"):
        text = raw[name]
        if text not in (None, "", "[]", "{}", "null"):
            parts.append(Part(kind="reasoning", name=name, text=text))
    bounded = []
    for part in parts:
        if part.kind == "reasoning" and isinstance(part.text, str):
            size, digest = text_digest(part.text)
            if size > limits.max_text_bytes:
                bounded.append(Part(kind="oversize", name=part.name, size=size, sha256=digest,
                                    content_type="text/plain"))
                warnings.append("REASONING_OVERSIZE")
                continue
        bounded.append(part)
    return bounded, warnings


def _native_rows(db_path: Path):
    db_path = checked_path(db_path)
    with directory_anchor(db_path.parent) as parent:
        for suffix in ("", "-wal", "-shm", "-journal"):
            try:
                metadata = os.stat(db_path.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if suffix:
                    continue
                raise
            if not stat.S_ISREG(metadata.st_mode):
                raise SourceDenied("SOURCE_NOT_REGULAR")
        connection = sqlite3.connect(db_path.as_uri() + "?mode=ro&vfs=unix&readonly_shm=1",
                                     uri=True, timeout=1.0)
        deadline = time.monotonic() + 30.0
        try:
            connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
            connection.execute("PRAGMA query_only=ON")
            if connection.execute("PRAGMA query_only").fetchone() != (1,):
                raise SourceDenied("SOURCE_NOT_READONLY")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute("PRAGMA temp_store=MEMORY")
            connection.execute("PRAGMA cache_size=-2048")
            connection.execute("BEGIN")
            columns = {row[1] for row in connection.execute('PRAGMA table_info("messages")')}
            sessions = {row[1] for row in connection.execute('PRAGMA table_info("sessions")')}
            if (not {"id", "session_id", "role", "content"} <= columns
                    or not {'id', 'source'} <= sessions):
                raise SourceDenied("HERMES_SCHEMA_UNSUPPORTED")
            # Sort only native row locators/order keys, not every raw payload.
            # rowid is indexed (the id alias in the native schema); each lookup
            # stays in this same BEGIN snapshot, including the sessions join.
            cursor = connection.execute(
                "SELECT m.rowid FROM messages AS m "
                "ORDER BY MIN(m.id) OVER (PARTITION BY m.session_id), m.id"
            )
            for locator, raw in _frozen_rows(connection, (r[0] for r in cursor), deadline):
                yield raw
        finally:
            connection.rollback()
            connection.close()


def maximum_id(db_path: Path):
    """Read the indexed enrollment boundary without reading message contents."""
    db_path = checked_path(db_path)
    connection = sqlite3.connect(db_path.as_uri() + '?mode=ro', uri=True, timeout=1.0)
    try:
        connection.execute('PRAGMA query_only=ON')
        return connection.execute('SELECT coalesce(max(id),0) FROM messages').fetchone()[0]
    finally:
        connection.close()


def incremental_rows(db_path: Path, *, after, through=None, limit=1000):
    """Indexed ID range from one short WAL read snapshot; never copy/checkpoint.

    Session-relative sequence uses the existing (session_id,id) index. Deleted
    predecessors may shift sequence on reconciliation, but identity stays native ID.
    """
    db_path = checked_path(db_path)
    with directory_anchor(db_path.parent) as parent:
        for suffix in ('', '-wal', '-shm', '-journal'):
            try:
                info = os.stat(db_path.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if suffix:
                    continue
                raise
            if not stat.S_ISREG(info.st_mode):
                raise SourceDenied('SOURCE_NOT_REGULAR')
        connection = sqlite3.connect(db_path.as_uri() + '?mode=ro&vfs=unix&readonly_shm=1',
                                     uri=True, timeout=1.0)
    deadline = time.monotonic() + 20
    try:
        connection.set_progress_handler(lambda: int(time.monotonic() >= deadline), 1000)
        connection.execute('PRAGMA query_only=ON')
        connection.execute('PRAGMA trusted_schema=OFF')
        connection.execute('PRAGMA temp_store=MEMORY')
        connection.execute('PRAGMA cache_size=-2048')
        connection.execute('BEGIN')
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 250_000_000)
        columns = {r[1] for r in connection.execute('PRAGMA table_info(messages)')}
        sessions = {r[1] for r in connection.execute('PRAGMA table_info(sessions)')}
        if (not {'id', 'session_id', 'role', 'content', 'timestamp'} <= columns
                or not {'id', 'source'} <= sessions):
            raise SourceDenied('HERMES_SCHEMA_UNSUPPORTED')
        query = ('SELECT m.rowid, '
                 '(SELECT count(*) FROM messages p WHERE p.session_id=m.session_id AND p.id<m.id) '
                 'FROM messages m WHERE m.id>? AND m.id<=? ORDER BY m.id LIMIT ?')
        maximum = through if through is not None else 2**63 - 1
        cursor = connection.execute(query, (after, maximum, limit))
        while positions := cursor.fetchmany(256):
            selected = _frozen_rows(connection, (r[0] for r in positions), deadline)
            try:
                for (locator, raw), (_, seq) in zip(selected, positions, strict=True):
                    yield raw, seq
            finally:
                selected.close()
    except sqlite3.DataError:
        raise SourceDenied('SOURCE_ROW_SIZE_LIMIT') from None
    finally:
        connection.rollback()
        connection.close()


def parse_hermes(db_path: Path, *, identity, limits, sample=None):
    from .hermes_reader import rows

    db_path = checked_path(db_path)
    # Preserve caller-side missing/nonregular refusal before launching a reader.
    # Directory descriptors cannot release another SQLite connection's DB locks.
    with directory_anchor(db_path.parent) as parent:
        for suffix in ('', '-wal', '-shm', '-journal'):
            try:
                metadata = os.stat(db_path.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                if suffix:
                    continue
                raise
            if not stat.S_ISREG(metadata.st_mode):
                raise SourceDenied('SOURCE_NOT_REGULAR')
    sequences = defaultdict(int)
    selected = rows(db_path) if sample is None else rows(db_path, sample=sample)
    try:
        for raw in selected:
            session = raw['session_id']
            seq = sequences[session]
            sequences[session] += 1
            parts, warnings = _parts(raw, limits)
            tool_result = (raw['tool_call_id'], raw['tool_name']) if raw['role'] == 'tool' else None
            yield record(raw=raw, identity=identity, session=session,
                         native_id=str(raw['id']), seq=seq, ts=raw['timestamp'],
                         native_role=raw['role'], text=raw['content'] or '', limits=limits,
                         native_source=raw['native_source'], parts=parts, warnings=warnings,
                         tool_result=tool_result)
    finally:
        selected.close()


# Explicit frozen-input seams. The legacy _native_rows/parse_hermes contract
# above retains its single invocation and complete-history ordering/deadline.
def _ordered_locators(connection):
    return connection.execute('SELECT m.rowid FROM messages AS m '
                              'ORDER BY MIN(m.id) OVER (PARTITION BY m.session_id), m.id')


def _frozen_rows(connection, locators, deadline):
    """Exactly one first-match payload per physical locator, never native ID."""
    columns = {row[1] for row in connection.execute('PRAGMA table_info("messages")')}
    if not {'id', 'session_id', 'role', 'content'} <= columns:
        raise SourceDenied('HERMES_SCHEMA_UNSUPPORTED')
    selected = _input_selection(columns)
    admissions = _admissions_supported(connection)
    query = (f'SELECT {selected}, s.source FROM messages AS m '
             'LEFT JOIN sessions AS s ON s.id=m.session_id WHERE m.rowid=?')
    locators = iter(locators)
    while page := list(islice(locators, 256)):
        for locator in page:
            if type(locator) is not int:
                raise SourceDenied('ACQUISITION_LOCATOR_INVALID')
        joins = _capture_joins(connection, page, columns) if admissions else {}
        for locator in page:
            row = connection.execute(query, (locator,)).fetchone()
            if row is None:
                raise SourceDenied('ACQUISITION_LOCATOR_MISSING')
            if time.monotonic() >= deadline:
                raise SourceDenied('SOURCE_READ_TIMEOUT')
            raw = dict(zip((*_FIELDS, *_INPUT_FIELDS, 'native_source'), row, strict=True))
            yield locator, _capture_input(connection, raw, joins)


# Explicit human surfaces (gateway.session_policy.SURFACES and Platform values).
# A parent also denotes compression continuation: it never implies subagent.
_HUMAN_SOURCES = frozenset({'cli', 'tui', 'gui', 'desktop', 'acp', 'telegram', 'discord',
    'slack', 'whatsapp', 'signal', 'matrix', 'sms', 'email', 'teams', 'msteams',
    'mattermost', 'feishu', 'dingtalk', 'wecom', 'qq', 'wechat', 'line', 'imessage',
    'irc', 'web', 'dashboard'})
_SESSION_FIELDS = ('id', 'source', 'created_source', 'chat_type', 'origin_json', 'title',
    'model', 'cwd', 'git_repo_root', 'parent_session_id', 'started_at', 'ended_at',
    'end_reason', 'title_source')


def session_kind(source, created_source, platform=None):
    labels = {source, created_source, platform}
    if 'subagent' in labels:
        return 'subagent'
    if 'cron' in labels:
        return 'scheduled'
    # Internal labels must not be laundered by a later surface/accounting label.
    if labels & {'tool', 'api_server', 'oneshot', 'bot_room', 'a2a'}:
        return 'other'
    return 'interactive' if labels & _HUMAN_SOURCES else 'other'


def _session_text(value):
    if not isinstance(value, str):
        return None
    return value.replace('\x00', '').encode('utf-8')[:4096].decode('utf-8', errors='ignore')


def _session_time(value):
    from datetime import UTC, datetime
    try:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, UTC).isoformat()
        stamp = datetime.fromisoformat(value)
        return stamp.isoformat() if stamp.utcoffset() is not None else None
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def session_metadata(db_path: Path, *, after=0, limit=64):
    """Bounded rowid-ordered metadata read; no message bodies or private origin IDs.

    Older Hermes schemas omit new columns. The source is never written/checkpointed.
    Returns (rowid, payload) for durable reconciliation without changing message hashes.
    """
    db_path = checked_path(db_path)
    with sqlite3.connect(db_path.as_uri()+'?mode=ro', uri=True, timeout=1) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('PRAGMA trusted_schema=OFF')
        columns = {r[1] for r in db.execute('PRAGMA table_info(sessions)')}
        if not {'id', 'source'} <= columns:
            raise SourceDenied('HERMES_SCHEMA_UNSUPPORTED')
        selected = ','.join(f'substr("{name}",1,4096)' if name in columns
            and name not in ('started_at','ended_at') else f'"{name}"' if name in columns
            else 'NULL' for name in _SESSION_FIELDS)
        deadline = time.monotonic()+2
        db.set_progress_handler(lambda: int(time.monotonic()>=deadline), 1000)
        rows = db.execute(f'SELECT rowid,{selected} FROM sessions WHERE rowid>? ORDER BY rowid LIMIT ?',
                          (after, min(64, limit))).fetchall()
    result = []
    for rowid, *values in rows:
        raw = dict(zip(_SESSION_FIELDS, values, strict=True))
        try:
            origin = json.loads(raw['origin_json'] or '{}')
        except (ValueError, RecursionError):
            origin = {}
        platform = origin.get('platform') if isinstance(origin, dict) else None
        meta = {k: _session_text(raw[k]) for k in
                ('source', 'created_source', 'chat_type', 'end_reason', 'title_source')}
        meta['platform'] = _session_text(platform)
        result.append((rowid, {'native_session_id': _session_text(raw['id']),
            'kind': session_kind(raw['source'], raw['created_source'], _session_text(platform)),
            'title': _session_text(raw['title']), 'model': _session_text(raw['model']),
            'cwd': _session_text(raw['cwd']), 'project': _session_text(raw['git_repo_root']),
            'started_at': _session_time(raw['started_at']), 'ended_at': _session_time(raw['ended_at']),
            'parent_native_id': _session_text(raw['parent_session_id']), 'meta': meta}))
    return result
