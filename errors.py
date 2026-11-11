"""Fixed, content-free guidance: never display a server's exception text."""


def guidance(code):
    if code in ('INGEST_CAPACITY_EXCEEDED', 'QUOTA_EXCEEDED'):
        return ('Server capacity refused this upload. Queued data is kept. Ask the operator '
                'to raise the device/tenant allowance or free server capacity; sync retries automatically.')
    if code in ('UNAUTHORIZED', 'FORBIDDEN', 'INVALID_KEY', 'KEY_REVOKED', 'INGEST_DISABLED'):
        return ('Server refused device access. Queued data is kept. Ask the operator to restore '
                'this device\'s ingest access; do not re-enroll or delete its queue.')
    if code in ('RATE_LIMITED', 'SERVICE_UNAVAILABLE', 'DEADLINE_EXCEEDED', 'REQUEST_TIMEOUT'):
        return 'Server temporarily unavailable or busy. Queued data is kept; sync retries automatically.'
    if code in ('DELIVERY_REFUSED', 'SPOOL_REJECTED', 'INVALID_RECORD', 'INVALID_ACK'):
        return ('Server refused or could not confirm an upload. Queued data is kept. '
                'Ask support to inspect the refusal; do not delete the queue.')
    return ('Sync unavailable. Queued data is kept. Check connectivity and device access; '
            'if this persists, ask support. Run hermes chatstone status.')
