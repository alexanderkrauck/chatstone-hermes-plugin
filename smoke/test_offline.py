"""Deliberately public, synthetic, offline release checks; no server or owner data."""
import contextlib
import importlib
import importlib.util
import io
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
# Source-tree execution is useful on the dedicated host; releases use vendor only.
sys.path.insert(0, str(ROOT/'vendor' if (ROOT/'vendor').is_dir() else ROOT.parent/'src'))
spec = importlib.util.spec_from_file_location('chatstone_public_smoke', ROOT/'__init__.py',
                                            submodule_search_locations=[str(ROOT)])
assert spec is not None and spec.loader is not None
plugin = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = plugin
spec.loader.exec_module(plugin)


class PublicSmoke(unittest.TestCase):
    def test_compile_and_import_every_runtime_module(self):
        files = list(ROOT.glob('*.py')) + list((ROOT/'vendor').rglob('*.py'))
        for path in files:
            with self.subTest(module=str(path.relative_to(ROOT))):
                compile(path.read_bytes(), str(path), 'exec')
                if path.parent == ROOT:
                    name = 'chatstone_public_smoke' + ('.'+path.stem if path.stem != '__init__' else '')
                else:
                    parts = list(path.relative_to(ROOT/'vendor').with_suffix('').parts)
                    if parts[-1] == '__init__':
                        parts.pop()
                    name = '.'.join(parts)
                importlib.import_module(name)

    def test_reader_admission_skip_retry_and_restart(self):
        from chatstone_public_smoke import runtime

        from chatstone.client.spool import Spool
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/'state.db'
            with sqlite3.connect(source) as db:
                db.executescript('CREATE TABLE sessions(id TEXT PRIMARY KEY,source TEXT);'
                    'CREATE TABLE messages(id INTEGER PRIMARY KEY,session_id TEXT,role TEXT,content TEXT,timestamp REAL);'
                    "INSERT INTO sessions VALUES('public-smoke','cli');")
                db.executemany('INSERT INTO messages VALUES(?,?,?,?,?)', [
                    (n, 'public-smoke', 'user', 'synthetic public smoke row', 1794400000+n)
                    for n in range(1, 4)])
            before = source.read_bytes()
            prepare = runtime.prepare_row

            def one_bad_row(spool, source, raw, seq):
                if raw['id'] == 2:
                    raise UnicodeError('synthetic content that must never be logged')
                return prepare(spool, source, raw, seq)

            options = {'source': 'hermes', 'host': 'public-smoke', 'destination': 'https://example.com'}
            with Spool(root/'spool', **options) as spool:
                runtime.initialize(spool, source)
                with patch.object(runtime, 'prepare_row', one_bad_row):
                    runtime.capture_history(spool, source)
                self.assertEqual(spool.status()['pending'], 2)
                self.assertEqual(runtime.snapshot(spool)['skipped'], 1)
                ledger = spool._db.execute('SELECT cause FROM plugin_skipped').fetchone()[0]
                self.assertNotIn('synthetic content', ledger)
                self.assertEqual(spool._db.execute('SELECT remaining FROM plugin_backfill').fetchone()[0], 0)
                runtime.retry_skipped(spool, source)
                self.assertEqual(runtime.snapshot(spool)['skipped'], 0)
                self.assertEqual(spool.status()['pending'], 3)
                identity = spool.install_id
            with Spool(root/'spool', **options) as spool:
                self.assertEqual(spool.install_id, identity)
                runtime.capture_history(spool, source)
                self.assertEqual(spool.status()['pending'], 3)
            self.assertEqual(source.read_bytes(), before)

    def test_content_free_errors_and_diagnose_without_credentials(self):
        from chatstone_public_smoke import cli, errors
        value = errors.cause(ValueError('synthetic secret /private/path'))
        self.assertNotIn('synthetic secret', json.dumps(value))
        self.assertNotIn('/private/path', json.dumps(value))
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stdout(io.StringIO()) as output:
            with patch.object(cli, 'sync', side_effect=AssertionError('network must not run')):
                result = cli.handle(SimpleNamespace(action='diagnose'), Path(temporary))
            text = output.getvalue()
            self.assertEqual(result, 1)
            self.assertIn('Version:', text)
            self.assertIn('Chatstone: FileNotFoundError', text)
            self.assertNotIn(temporary, text)


if __name__ == '__main__':
    unittest.main()
