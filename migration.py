"""One-time adoption: retain daemon identity, queue and source position in place.

macOS Keychain access executes once in the daemon's own interpreter, not Hermes.
Scheduler/MCP removal uses supported platform CLIs and verifies their effects.
"""
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from pathlib import Path

from chatstone.client.transport import TOKEN, Client

from .config import read_private


def run(args, *, input=None):
    result = subprocess.run([str(x) for x in args], input=input, text=True, check=False,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90)
    if result.returncode:
        raise RuntimeError('DAEMON_MIGRATION_FAILED')
    return result.stdout


def discover():
    base = Path.home()/'.local/share/chatstone'
    candidates = [p for p in (base/'hermes-client', base/'automatic') if (p/'tick.json').is_file()]
    if len(candidates) > 1:
        raise RuntimeError('DAEMON_LAYOUT_AMBIGUOUS_USE_EXPLICIT_ROOT')
    return candidates[0] if candidates else None


def adopt_files(root):
    root = Path(root)
    old = read_private(root/'tick.json')
    Client(old['destination'])
    credentials = {}
    if old.get('credential_backend') == 'macos-keychain':
        script = ('import json,sys; from chatstone.client.automatic import _config,_credential; '
                  'print(json.dumps({"ingest_token":_credential(_config(sys.argv[1]))}))')
        token = json.loads(run([root/'venv/bin/python', '-c', script, root/'tick.json']))['ingest_token']
    else:
        credentials = read_private(Path(old['credential_file']))
        token = credentials['ingest_token']
    search = root/'search.json'
    if search.exists():
        read = read_private(search)['read_key']
    elif old.get('credential_backend') != 'macos-keychain':
        # Hand-built VPS layout keeps BOTH keys in its private credential file.
        read = credentials['read_token']
        if (credentials.get('host') != old['host'] or credentials.get('base_url') != old['destination']
                or credentials.get('source') != 'hermes'):
            raise RuntimeError('DAEMON_IDENTITY_MISMATCH')
        # The daemon uploads under tick/spool identity; enrollment metadata can be stale.
        database = Path(old['spool_path'])/'spool.sqlite3'
        if database.exists():
            with closing(sqlite3.connect(database.resolve().as_uri()+'?mode=ro', uri=True)) as db:
                identity = db.execute('SELECT install FROM identity').fetchone()
            if identity != (old['expected_install'],):
                raise RuntimeError('DAEMON_IDENTITY_MISMATCH')
    else:
        raise RuntimeError('DAEMON_READ_KEY_MISSING')
    if not all(isinstance(x, str) and TOKEN.fullmatch(x) for x in (token, read)):
        raise RuntimeError('CREDENTIAL_INVALID')
    return {'device': old['host'], 'origin': old['destination'], 'ingest_key': token,
        'read_key': read, 'source_path': old['source_path'], 'spool_path': old['spool_path'],
        'install_id': old['expected_install'], 'adopted_from': str(root)}


def stop_scheduler(root):
    root = Path(root)
    if sys.platform == 'darwin':
        # launchd.remove validates its own plist binding and post-removal job absence.
        run([root/'venv/bin/python', '-m', 'chatstone.client.launchd', 'remove',
            '--config', root/'tick.json', '--python', root/'venv/bin/python'])
        return
    units = Path.home()/'.config/systemd/user'
    legacy = root.name == 'automatic'
    prefix = 'chatstone-collector-vps' if legacy else 'chatstone-hermes'
    paths = [units/f'{prefix}.{suffix}' for suffix in ('service', 'timer')]
    # Validate all destinations BEFORE stopping or deleting anything. Legacy
    # clients/<sha> interpreters are allowed; the exact tick config must be bound.
    for path in paths:
        if path.is_symlink():
            raise RuntimeError('SCHEDULER_CHANGED')
        if path.exists():
            text = path.read_text()
            expected = str(root/'tick.json') if legacy else str(root)
            if (path.suffix == '.service' and expected not in text) or (
                    path.suffix == '.timer' and f'Unit={prefix}.service' not in text):
                raise RuntimeError('SCHEDULER_CHANGED')
    if paths[1].exists():
        run(['systemctl', '--user', 'disable', '--now', f'{prefix}.timer'])
    if paths[0].exists():
        run(['systemctl', '--user', 'disable', '--now', f'{prefix}.service'])
    for path in paths:
        path.unlink(missing_ok=True)
    run(['systemctl', '--user', 'daemon-reload'])
    for name in (f'{prefix}.service', f'{prefix}.timer'):
        check = subprocess.run(['systemctl', '--user', 'is-active', '--quiet', name], check=False,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
        if check.returncode not in (3, 4):
            raise RuntimeError('DAEMON_STOP_UNVERIFIED')


def disconnect_mcp(home):
    import hermes_yaml as yaml
    path = Path(home)/'config.yaml'
    config = yaml.safe_load(path.read_text()) if path.exists() else {}
    if 'chatstone' in (config or {}).get('mcp_servers', {}):
        result = subprocess.run(['hermes', 'mcp', 'remove', 'chatstone'],
            env={**os.environ, 'HERMES_HOME': str(home)}, input='y\n', text=True, check=False,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=90)
        if result.returncode:
            raise RuntimeError('MCP_REMOVAL_FAILED')
        saved = yaml.safe_load(path.read_text()) or {}
        if 'chatstone' in saved.get('mcp_servers', {}):
            raise RuntimeError('MCP_REMOVAL_FAILED')
