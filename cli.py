"""Native `hermes chatstone` commands; keys and codes never enter argv/logs."""
import fcntl
import getpass
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path

import httpx

from chatstone.client.spool import Spool
from chatstone.client.transport import TOKEN, Client, ClientError

from .config import load, read_private, root, write_private
from .runtime import initialize, open_spool, sync


@contextmanager
def lease(home, *, wait=False):
    path = root(home)/'.lock'
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        end = time.monotonic() + (40 if wait else 0)
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= end:
                    raise ClientError('PLUGIN_BUSY') from None
                time.sleep(.1)
        yield
    finally:
        os.close(fd)


def setup(parser):
    parser.add_argument('action', choices=['login','backfill','status','adopt-daemon','logout'])
    parser.add_argument('--daemon-root', type=Path,
        help='Explicit older/custom daemon layout (never inferred from another Hermes profile)')


def login(home):
    folder = root(home)
    if (folder/'credentials.json').exists() or (folder/'enrollment-started.json').exists():
        raise RuntimeError('ALREADY_CONFIGURED_OR_EXCHANGE_UNCERTAIN')
    from .migration import discover
    old = discover()
    if old is not None:
        adopt(home, old)
        return
    origin = os.environ.get('CHATSTONE_SERVER_URL', 'https://api.chatstone.goedly.com').rstrip('/')
    Client(origin)
    source = Path(home)/'state.db'
    if source.is_symlink():
        raise RuntimeError('RUN_HERMES_FIRST')
    if not source.exists():
        from hermes_state import SessionDB
        SessionDB(source).close()  # Native empty schema; no fabricated session/message.
    if not source.is_file():
        raise RuntimeError('RUN_HERMES_FIRST')
    # Hidden TTY only: getpass must never fall back to piped stdin.
    code = os.environ.pop('CHATSTONE_ENROLLMENT_CODE', None)
    if not code:
        with open('/dev/tty', 'w') as terminal:
            code = getpass.getpass('One-time enrollment code: ', stream=terminal)
    write_private(folder/'enrollment-started.json', {'started':True})
    with httpx.Client(timeout=15, trust_env=False, follow_redirects=False) as client:
        response = client.post(origin+'/api/v1/enroll', json={'code':code})
    del code
    if response.status_code != 200:
        raise RuntimeError('ENROLLMENT_UNAVAILABLE_ASK_FOR_FRESH_CODE')
    value = response.json()
    if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,62}',value.get('device',''))
            or value.get('sources') != ['hermes'] or not all(
                TOKEN.fullmatch(value.get(k,'')) for k in ('ingest_key','read_key'))):
        raise RuntimeError('ENROLLMENT_RESPONSE_INVALID')
    # Persist returned credentials BEFORE source preparation (a consumed code cannot be replayed).
    config = {'device': value['device'], 'origin': origin, 'ingest_key': value['ingest_key'],
        'read_key': value['read_key'], 'source_path': str(source), 'spool_path': str(folder/'spool')}
    with Spool(config['spool_path'], source='hermes', host=config['device'], destination=origin,
               max_bytes=1073741824, max_pending=10000) as spool:
        config['install_id'] = spool.install_id
        write_private(folder/'credentials.json', config)
        initialize(spool, source)
    (folder/'enrollment-started.json').unlink()
    print('Chatstone device: '+config['device']+'. Live sync enabled; run hermes chatstone backfill for history.')


def status(home):
    config = load(home)
    try:
        saved = read_private(root(home)/'status.json')
    except FileNotFoundError:
        saved = {}
    with open_spool(config) as spool:
        pending = spool.status()['pending']
        row = spool._db.execute('SELECT remaining,admitted,enabled FROM plugin_backfill').fetchone()
    print('Device: '+config['device'])
    print('Last sync: '+str(saved.get('last_sync','not yet'))+'; pending: '+str(pending))
    print('Backfill: '+str(row[1])+' admitted; remaining through native ID '+str(row[0])+
          (' (enabled)' if row[2] else ' (not started)'))
    print('Last error: '+str(saved.get('last_error') or 'none'))


def adopt(home, old):
    from .migration import adopt_files, disconnect_mcp, stop_scheduler
    if (root(home)/'credentials.json').exists():
        config = load(home)
        if config.get('adopted_from') != str(old):
            raise RuntimeError('ALREADY_CONFIGURED')
        stop_scheduler(old)
        disconnect_mcp(home)
        print('Adoption complete for device: '+config['device'])
        return
    # Read credentials first; no scheduler is touched on a bad binding/profile.
    config = adopt_files(old)
    if Path(config['source_path']).resolve() != (Path(home)/'state.db').resolve():
        raise RuntimeError('DAEMON_BELONGS_TO_DIFFERENT_HERMES_PROFILE')
    stop_scheduler(old)
    with open_spool(config) as spool:
        initialize(spool, config['source_path'])
        # Existing daemon histories continue automatically, newest undelivered first.
        with spool._transaction():
            spool._db.execute('UPDATE plugin_backfill SET enabled=1')
        write_private(root(home)/'credentials.json', config)
    # Keep retained spool and old config for rollback; never invoke daemon uninstall.
    disconnect_mcp(home)
    print('Adopted device: '+config['device']+'; original identity/queue retained. Start a new Hermes session.')


def handle(args, home):
    try:
        with lease(home, wait=True):
            if args.action == 'login':
                login(home)
            elif args.action == 'adopt-daemon':
                from .migration import discover
                old = args.daemon_root or discover()
                if old is None:
                    raise RuntimeError('DAEMON_NOT_FOUND')
                adopt(home, old)
            elif args.action == 'logout':
                (root(home)/'credentials.json').unlink(missing_ok=True)
                (root(home)/'enrollment-started.json').unlink(missing_ok=True)
                print('Logged out. Local queue/history and hosted archive retained; revoke keys with operator if needed.')
            elif args.action == 'status':
                status(home)
            else:
                config = load(home)
                with open_spool(config) as spool:
                    initialize(spool, config['source_path'])
                    with spool._transaction():
                        spool._db.execute('UPDATE plugin_backfill SET enabled=1')
                while True:
                    result = sync(config)
                    result['last_error'] = None
                    write_private(root(home)/'status.json', result)
                    progress = result['backfill']
                    print('Backfill: '+str(progress['admitted'])+' admitted; remaining through ID '+
                        str(progress['remaining_through_id'])+'; pending '+str(result['pending']), flush=True)
                    if (not progress['remaining_through_id'] and not result['pending']
                            and progress.get('legacy_phase') in (None, 'RETIRED')):
                        break
    except KeyboardInterrupt:
        print('Paused; durable queue/position retained. Rerun backfill to resume.')
        return 130
    except Exception as error:  # noqa: BLE001 -- no secret exception text
        allowed = {'ALREADY_CONFIGURED','ALREADY_CONFIGURED_OR_EXCHANGE_UNCERTAIN',
            'DAEMON_FOUND_USE_ADOPT_DAEMON','RUN_HERMES_FIRST','ENROLLMENT_UNAVAILABLE_ASK_FOR_FRESH_CODE',
            'ENROLLMENT_RESPONSE_INVALID','DAEMON_BELONGS_TO_DIFFERENT_HERMES_PROFILE','PLUGIN_BUSY'}
        from .errors import guidance
        code = getattr(error, 'code', '')
        if args.action == 'backfill' and code != 'PLUGIN_BUSY':
            write_private(root(home)/'status.json', {'last_error': guidance(code)})
        message = str(error) if str(error) in allowed else guidance(code)
        print('Chatstone: '+message)
        return 1
    return 0
