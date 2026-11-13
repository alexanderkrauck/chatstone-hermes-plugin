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
            selected = ", ".join(f'm."{name}"' if name in columns else f'NULL AS "{name}"'
                                 for name in _FIELDS)
            # Sort only native row locators/order keys, not every raw payload.
            # rowid is indexed (the id alias in the native schema); each lookup
            # stays in this same BEGIN snapshot, including the sessions join.
            cursor = connection.execute(
                "SELECT m.rowid FROM messages AS m "
                "ORDER BY MIN(m.id) OVER (PARTITION BY m.session_id), m.id"
            )
            lookup = (f"SELECT {selected}, s.source FROM messages AS m "
                      "LEFT JOIN sessions AS s ON s.id=m.session_id WHERE m.rowid=?")
            for (rowid,) in cursor:
                row = connection.execute(lookup, (rowid,)).fetchone()
                if time.monotonic() >= deadline:
                    raise TimeoutError("SOURCE_READ_TIMEOUT")
                yield dict(zip((*_FIELDS, "native_source"), row, strict=True))
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
        selected = ', '.join(f'm."{name}"' if name in columns else f'NULL AS "{name}"'
                             for name in _FIELDS)
        query = (f'SELECT {selected}, s.source, '
                 '(SELECT count(*) FROM messages p WHERE p.session_id=m.session_id AND p.id<m.id) '
                 'FROM messages m LEFT JOIN sessions s ON s.id=m.session_id '
                 'WHERE m.id>? AND m.id<=? ORDER BY m.id LIMIT ?')
        maximum = through if through is not None else 2**63 - 1
        for row in connection.execute(query, (after, maximum, limit)):
            if time.monotonic() >= deadline:
                raise SourceDenied('SOURCE_READ_TIMEOUT')
            yield dict(zip((*_FIELDS, 'native_source'), row[:-1], strict=True)), row[-1]
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
    selected = ', '.join(f'm."{name}"' if name in columns else f'NULL AS "{name}"'
                         for name in _FIELDS)
    query = (f'SELECT {selected}, s.source FROM messages AS m '
             'LEFT JOIN sessions AS s ON s.id=m.session_id WHERE m.rowid=?')
    for locator in locators:
        if type(locator) is not int:
            raise SourceDenied('ACQUISITION_LOCATOR_INVALID')
        row = connection.execute(query, (locator,)).fetchone()
        if row is None:
            raise SourceDenied('ACQUISITION_LOCATOR_MISSING')
        if time.monotonic() >= deadline:
            raise SourceDenied('SOURCE_READ_TIMEOUT')
        yield locator, dict(zip((*_FIELDS, 'native_source'), row, strict=True))


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
