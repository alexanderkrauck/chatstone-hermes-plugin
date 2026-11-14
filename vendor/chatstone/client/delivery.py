"""Shared durable per-envelope delivery; harnesses retain their own capture order."""
import json
import time
from concurrent.futures import ThreadPoolExecutor

from .ingest import encode_ingest_json
from .spool import Spool
from .transport import ClientError


def metadata_only(value):
    if isinstance(value, dict):
        return {k: None if k == 'data_base64' else metadata_only(v) for k, v in value.items()}
    if isinstance(value, list):
        return [metadata_only(v) for v in value]
    return value


class RetryingSpool(Spool):
    """Only scheduling differs; persistence, retries and upload are shared."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.live = False
        with self._transaction():
            self._db.execute('CREATE TABLE IF NOT EXISTS native_priority(batch TEXT PRIMARY KEY, priority INTEGER)')
            self._db.execute('DELETE FROM native_priority WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_identity(batch TEXT PRIMARY KEY,native TEXT)')
            self._db.execute('CREATE INDEX IF NOT EXISTS native_identity_key ON native_identity(native)')
            self._db.execute('DELETE FROM native_identity WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_retry('
                'batch TEXT PRIMARY KEY,attempts INTEGER,code TEXT,bytes INTEGER,next_at REAL)')
            self._db.execute('DELETE FROM native_retry WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_blobs('
                'batch TEXT,digest TEXT,PRIMARY KEY(batch,digest))')
            self._db.execute('DELETE FROM native_blobs WHERE batch NOT IN (SELECT batch FROM pending)')
            self._db.execute('CREATE TABLE IF NOT EXISTS native_health('
                'kind TEXT PRIMARY KEY,at REAL,code TEXT)')
            for batch, payload in self._db.execute('SELECT batch,payload FROM pending WHERE batch NOT IN (SELECT batch FROM native_identity)'):
                message = json.loads(payload)['records'][0]['message']
                self._db.execute('INSERT INTO native_identity VALUES(?,?)', (batch, json.dumps([message['native_session_id'], message['native_id']])))

    def _add_prepared(self, prepared):
        batch = super()._add_prepared(prepared)
        if batch:
            self._db.execute('INSERT INTO native_priority VALUES(?,?)', (batch, 0 if self.live else 1))
            self._db.execute('INSERT INTO native_identity VALUES(?,?)', (batch, json.dumps(json.loads(prepared[0]))))
        return batch

    def promote(self, session, native):
        if self.live:
            self._db.execute('UPDATE native_priority SET priority=0 WHERE batch IN '
                '(SELECT batch FROM native_identity WHERE native=?)', (json.dumps([session, native]),))

    def delivery_window(self):
        """Close the SQLite read cursor BEFORE any socket or lease handoff.

        A failed registration otherwise retains it in an exception traceback;
        sqlite3_close_v2 then leaves a read lock alive in another process's way.
        """
        rows, size = [], 0
        cursor = self._delivery_rows(8)
        try:
            for row in cursor:
                if rows and size+len(row[1]) > 32*1024*1024:
                    break
                rows.append(row)
                size += len(row[1])
        finally:
            cursor.close()
        return rows

    def status(self):
        value = super().status()
        if not self._db.execute("SELECT 1 FROM sqlite_master WHERE name='native_retry'").fetchone():
            return {**value, 'set_aside': {'count': 0, 'largest_bytes': 0, 'max_attempts': 0, 'reasons': {}},
                    'last_success': {}, 'last_failure': {}, 'active_pending': value['pending'], 'next_retry': None}
        count, largest, attempts = self._db.execute(
            "SELECT count(*),coalesce(max(bytes),0),coalesce(max(attempts),0) FROM native_retry "
            "WHERE (attempts>=3 OR code='UPLOAD_BODY_TIMEOUT') AND code!='AWAITING_RECEIPT'").fetchone()
        value['set_aside'] = {'count': count, 'largest_bytes': largest, 'max_attempts': attempts,
            'reasons': dict(self._db.execute("SELECT code,count(*) FROM native_retry "
                "WHERE (attempts>=3 OR code='UPLOAD_BODY_TIMEOUT') AND code!='AWAITING_RECEIPT' GROUP BY code"))}
        for kind in ('success', 'failure'):
            row = self._db.execute('SELECT at,code FROM native_health WHERE kind=?', (kind,)).fetchone()
            value['last_'+kind] = {'at': row[0], 'cause': row[1]} if row else {}
        value['active_pending'] = value['pending']-self._db.execute(
            'SELECT count(*) FROM native_retry WHERE next_at>?', (time.time(),)).fetchone()[0]
        row = self._db.execute('SELECT min(next_at) FROM native_retry').fetchone()
        value['next_retry'] = row[0]
        return value

    def defer(self, batch, error, size):
        # Keep original envelope, batch ID, seen state and every attachment byte.
        # Only conclusive operator-wide refusals stop the worker. An uncertain
        # ACK always replays its original ID, never a new logical upload.
        if error.code in {'INVALID_KEY', 'UNAUTHORIZED', 'FORBIDDEN', 'INGEST_DISABLED',
                          'INGEST_CAPACITY_EXCEEDED', 'QUOTA_EXCEEDED', 'SPOOL_IO', 'SPOOL_BUSY', 'SYNC_BUSY',
                          'SPOOL_FULL', 'SPOOL_CORRUPT', 'SPOOL_IDENTITY_MISMATCH'} or error.status in (401, 403, 507):
            raise error
        with self._transaction():
            row = self._db.execute('SELECT attempts FROM native_retry WHERE batch=?', (batch,)).fetchone()
            attempts = (row[0] if row else 0)+1
            pause = (30, 60)[attempts-1] if attempts < 3 else min(3600, 300*2**min(attempts-3, 4))
            if error.code == 'UPLOAD_BODY_TIMEOUT':
                pause = min(3600, 300*2**min(attempts-1, 4))
            if error.code == 'AWAITING_RECEIPT':
                pause = min(60, .25*2**min(attempts-1, 8))
            self._db.execute('INSERT OR REPLACE INTO native_retry VALUES(?,?,?,?,?)',
                (batch, attempts, error.code, getattr(error, 'upload_bytes', size), time.time()+pause))
            if error.code != 'AWAITING_RECEIPT':
                self._db.execute("INSERT OR REPLACE INTO native_health VALUES('failure',?,?)",
                                 (time.time(), error.code))

    def flush(self, client):
        """One ordered request; independent staging failures do not block its peers.

        A retained message never loses its original or passes an older revision
        of itself. Unrelated messages keep the existing live/history order.
        """
        if getattr(client, 'native_registered', None) != self.install_id:
            client.register_source(install_id=self.install_id, source=self.source, host=self.host)
            client.native_registered = self.install_id
        batches = []
        for batch, payload, receipt in self.delivery_window():
            if receipt in ('rejected', 'denied'):
                raise ClientError('QUOTA_EXCEEDED' if self.status()['errors'].get('QUOTA_EXCEEDED') else 'INVALID_RECORD')
            body = json.loads(payload)
            try:
                encode_ingest_json({'batches': metadata_only(batches+[body])})
            except ClientError as error:
                if error.code != 'REQUEST_TOO_LARGE':
                    raise
                if not batches:
                    batches.append(body)
                break
            batches.append(body)
        if not batches:
            return 0

        accepted = {batch['batch_id']: {row[0] for row in self._db.execute(
            'SELECT digest FROM native_blobs WHERE batch=?', (batch['batch_id'],))} for batch in batches}

        def stage(batch):
            known = accepted[batch['batch_id']]
            try:
                records = client._stage_attachments(self.install_id, batch['records'], None, staged=known)
                return {**batch, 'records': records}, None
            except ClientError as error:
                return batch, error

        # Never write SQLite from staging threads. A failed original holds back
        # its entire message, not the other messages in this window.
        with ThreadPoolExecutor(max_workers=4) as executor:
            outcomes = list(executor.map(stage, batches))
        # Persist positive blob acknowledgments before enqueue. Originals remain
        # unchanged until a final message receipt. One write group, not per part.
        new_blobs = [(batch, digest) for batch, digests in accepted.items() for digest in digests
            if not self._db.execute('SELECT 1 FROM native_blobs WHERE batch=? AND digest=?',
                                    (batch, digest)).fetchone()]
        if new_blobs:
            with self._transaction():
                self._db.executemany('INSERT OR IGNORE INTO native_blobs VALUES(?,?)', new_blobs)
        staged = []
        for batch, error in outcomes:
            if error is not None:
                self.defer(batch['batch_id'], error, len(encode_ingest_json(metadata_only(batch))))
            else:
                staged.append(batch)
        if not staged:
            return 0
        try:
            if len(staged) == 1:
                results = [client.enqueue(**staged[0])]
            else:
                result = client.enqueue_ordered(batches=staged)
                results = result.get('receipts')
            if not isinstance(results, list) or not 1 <= len(results) <= len(staged):
                raise ClientError('INVALID_ACK')
            checked = []
            for index, result in enumerate(results):
                receipt, code = self._receipt(result, staged[index]['batch_id'])
                if receipt != 'applied' and index != len(results)-1:
                    raise ClientError('INVALID_ACK')
                checked.append((staged[index]['batch_id'], receipt, code))
        except ClientError as error:
            for batch in staged:
                self.defer(batch['batch_id'], error, len(encode_ingest_json(batch)))
            return 0
        delivered, failure = 0, None
        with self._transaction():
            for batch, receipt, code in checked:
                if receipt == 'applied':
                    self._db.execute('DELETE FROM pending WHERE batch=?', (batch,))
                    self._db.execute('DELETE FROM native_retry WHERE batch=?', (batch,))
                    self._db.execute('DELETE FROM native_blobs WHERE batch=?', (batch,))
                    self._db.execute("INSERT OR REPLACE INTO native_health VALUES('success',?,NULL)", (time.time(),))
                    delivered += 1
                else:
                    self._db.execute('UPDATE pending SET receipt=?,code=? WHERE batch=?', (receipt, code, batch))
                    if code:
                        failure = ClientError(code)
        # Final-receipt polling also grows a pause; it must not busy-loop.
        for batch, receipt, code in checked:
            if receipt == 'queued':
                self.defer(batch, ClientError('AWAITING_RECEIPT'), 0)
        if failure:
            raise failure
        return delivered

    def retry_after_update(self, release):
        """One immediate retry of retained items per installed plugin release."""
        row = self._db.execute("SELECT code FROM native_health WHERE kind='release'").fetchone()
        if row != (release,):
            with self._transaction():
                self._db.execute('UPDATE native_retry SET next_at=0')
                self._db.execute("INSERT OR REPLACE INTO native_health VALUES('release',?,?)",
                                 (time.time(), release))

    def _delivery_rows(self, limit):
        fresh = self._db.execute("SELECT 1 FROM sqlite_master WHERE name='hermes_fresh'").fetchone()
        # Hermes' existing fresh,seq ordering is deliberately unchanged.
        order = ('p.fresh,p.seq' if fresh else
                 'coalesce(n.priority,1),CASE WHEN n.priority=0 THEN -p.seq ELSE p.seq END')
        return self._db.execute('SELECT p.batch,p.payload,p.receipt FROM pending p '
            'LEFT JOIN native_priority n ON p.batch=n.batch '
            'JOIN native_identity i ON p.batch=i.batch '
            'LEFT JOIN native_retry r ON p.batch=r.batch '
            'WHERE (r.next_at IS NULL OR r.next_at<=?) AND NOT EXISTS '
            '(SELECT 1 FROM pending older JOIN native_identity oi ON older.batch=oi.batch '
            'WHERE oi.native=i.native AND older.seq<p.seq) '
            f'ORDER BY {order} LIMIT ?',
            (time.time(), limit,))
