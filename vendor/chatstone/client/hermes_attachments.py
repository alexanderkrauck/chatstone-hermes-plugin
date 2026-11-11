"""Capture explicit Hermes originals, never discover arbitrary nearby files.

``uploader.upload_blob(kind='attachments', data=bytes)`` is optional and bound
by the caller to its authenticated installation. Returned paths/bytes are private;
log only counts/status, types, sizes and hash-equality, not Capture reprs.
"""
import hashlib
import json
import mimetypes
import os
import re
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from urllib.parse import unquote, urlsplit

from chatstone.collectors.contracts import Attachment, Part
from chatstone.collectors.normalization import canonical
from chatstone.collectors.policy import SourceDenied, checked_path, open_explicit

CAP = 25_000_000
_MEDIA = re.compile(r'(?m)^\s*MEDIA:\s*(?:"([^"\n]+)"|([^\s`<>]+))')
_SAVED = re.compile(r'(?:also saved at:|[Ii]t is saved at:)\s*(.+?)(?:\]|\. (?:Its |Read |If |To ))')
_INBOUND = re.compile(r'\[User sent (?:an image|audio|a video|a file):\s*([^\]\n]+)\]')


@dataclass(frozen=True, repr=False)
class Capture:
    reference: str
    status: str
    size: int | None = None
    sha256: str | None = None
    content_type: str | None = None
    data: bytes | None = None


def _references(message):
    if message.get('role') not in ('user', 'assistant'):
        return ()
    content = message.get('content') or ''
    refs = []
    def visit(value):
        if isinstance(value, str):
            if value.startswith('\x00json:'):
                try:
                    visit(json.loads(value[6:]))
                except (ValueError, RecursionError):
                    pass
                return
            refs.extend(a or b for a, b in _MEDIA.findall(value))
            refs.extend(_SAVED.findall(value))
            refs.extend(_INBOUND.findall(value))
            if value.startswith(('[', '{')):
                try:
                    visit(json.loads(value))
                except (ValueError, RecursionError):
                    pass
        elif isinstance(value, list):
            for item in value[:100]:
                visit(item)
        elif isinstance(value, dict):
            if value.get('type') == 'image_url':
                image = value.get('image_url', {})
                if (isinstance(image, dict) and isinstance(image.get('url'), str)
                        and not image['url'].startswith('data:')):
                    refs.append(image['url'])
            if isinstance(value.get('text'), str):
                visit(value['text'])
    visit(content)
    visit(message.get('api_content'))
    return tuple(dict.fromkeys(refs))[:100]


def _capture(home, reference):
    if reference.startswith('file://'):
        url = urlsplit(reference)
        if url.netloc not in ('', 'localhost'):
            return Capture(reference, 'unsupported')
        reference = unquote(url.path)
    elif '://' in reference or reference.startswith('data:'):
        # Inline binary is extracted by collectors.binary, never fetched here.
        return Capture(reference, 'unsupported')
    if reference.startswith('~/'):
        reference = str(home.parent / reference[2:])
    path = Path(reference)
    if not path.is_absolute():
        path = home / path
    try:
        checked_path(path)
        path.relative_to(home.parent)
        if any(p in {'.ssh', '.aws', '.gnupg', 'Keychains'} for p in path.parts):
            raise SourceDenied('SOURCE_CREDENTIAL_NAME')
        if path.is_relative_to(home) and not any(path.is_relative_to(home / d) for d in (
                'cache', 'image_cache', 'audio_cache', 'document_cache', 'video_cache', 'screenshots')):
            raise SourceDenied('SOURCE_NOT_ALLOWLISTED')
        with open_explicit(path) as stream:
            before = os.fstat(stream.fileno())
            size = before.st_size
            mime = mimetypes.guess_type(path.name)[0] or 'application/octet-stream'
            if size > CAP:
                return Capture(reference, 'oversize', size, content_type=mime)
            data = stream.read(CAP + 1)
            after = os.fstat(stream.fileno())
            if (len(data) != size or (before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    != (after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
                return Capture(reference, 'unsupported', size, content_type=mime)
        return Capture(reference, 'ready', size, hashlib.sha256(data).hexdigest(), mime, data)
    except FileNotFoundError:
        return Capture(reference, 'missing')
    except (SourceDenied, PermissionError, ValueError, OSError):
        return Capture(reference, 'denied')


def capture_attachments(hermes_home, message, uploader=None):
    home = checked_path(Path(hermes_home))
    captures = [_capture(home, ref) for ref in _references(message)]
    if message.get('role') in ('user', 'assistant'):
        from chatstone.collectors.binary import extract_content
        from chatstone.collectors.contracts import ParseLimits
        seen_inline = set()
        for field in ('content', 'api_content'):
            text = message.get(field)
            if isinstance(text, (list, dict)):
                text = json.dumps(text)
            if not isinstance(text, str):
                continue
            for item in extract_content(text, limits=ParseLimits()).attachments:
                if item.sha256 not in seen_inline:
                    captures.append(Capture('inline:' + item.sha256,
                        'oversize' if item.oversize else 'ready', item.size,
                        item.sha256, item.content_type, item.data))
                    seen_inline.add(item.sha256)
    captures = tuple(captures)
    if uploader is not None:
        uploaded = set()
        for item in captures:
            if item.status == 'ready' and item.sha256 not in uploaded:
                uploader.upload_blob(kind='attachments', data=item.data)
                uploaded.add(item.sha256)
    return captures


def enrich_record(hermes_home, parsed_record):
    message = parsed_record.message
    try:
        native = json.loads(parsed_record.raw_record)
    except (ValueError, TypeError):
        native = {}
    if not isinstance(native, dict):
        native = {}
    captures = capture_attachments(hermes_home, {**native, 'role': message.role,
        'content': native.get('content', message.content)})
    if not captures:
        return parsed_record
    parts, attachments = list(message.parts), {a.sha256: a for a in parsed_record.attachments}
    warnings = list(message.warnings)
    for item in captures:
        if item.sha256 is not None and item.sha256 in attachments:
            continue
        if item.status == 'ready':
            parts.append(Part(kind='attachment', name=Path(item.reference).name,
                              sha256=item.sha256, size=item.size, content_type=item.content_type))
            attachments[item.sha256] = Attachment(item.sha256, item.size, item.content_type,
                                                   item.data, False)
        else:
            parts.append(Part(kind='oversize' if item.status == 'oversize' else 'invalid',
                              name='attachment_' + item.status, size=item.size,
                              content_type=item.content_type))
            warnings.append('ATTACHMENT_' + item.status.upper())
    semantic = canonical({'native_role': message.native_role, 'content': message.content,
                          'parts': [asdict(p) for p in parts]})
    return replace(parsed_record, attachments=tuple(attachments.values()), message=replace(
        message, parts=tuple(parts), warnings=tuple(dict.fromkeys(warnings)),
        content_hash=hashlib.sha256(semantic).hexdigest()))
