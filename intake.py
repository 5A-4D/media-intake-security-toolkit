#!/usr/bin/env python3
"""Read-only media checks. Reports contain fixed findings and numeric IDs only."""
import argparse
from contextlib import ExitStack
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import stat
import subprocess


class ReviewRequired(Exception):
    pass


def parts_for(name):
    if not isinstance(name, str) or not name or '\\' in name or '\x00' in name:
        raise ReviewRequired('invalid_relative_path')
    parts = name.split('/')
    if any(p in ('', '.', '..') for p in parts):
        raise ReviewRequired('invalid_relative_path')
    return parts


def open_regular(root, name):
    """Linux: anchor each component with openat and refuse symlinks/special files."""
    parts = parts_for(name)
    parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ReviewRequired('not_a_regular_file')
    return os.fdopen(fd, 'rb')


def stamp(handle):
    s = os.fstat(handle.fileno())
    return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns


MIME = {
    '.mkv': ('video', {'video/x-matroska', 'video/matroska'}),
    '.mp4': ('video', {'video/mp4', 'application/mp4'}),
    '.wav': ('audio', {'audio/x-wav', 'audio/wav', 'audio/vnd.wave'}),
    '.mp3': ('audio', {'audio/mpeg'}),
    '.flac': ('audio', {'audio/flac', 'audio/x-flac'}),
    '.srt': ('sidecar', {'text/plain', 'application/x-subrip'}),
    '.nfo': ('sidecar', {'text/plain'}),
}


def classify(suffix, mime):
    kind, allowed = MIME.get(suffix.lower(), ('unexpected', set()))
    return kind if mime in allowed else 'unexpected'


def probe(handle, kind, allowed_mime):
    fd = handle.fileno()
    path = f'/proc/self/fd/{fd}'
    magic = subprocess.run(['file', '--dereference', '--brief', '--mime-type', '--', path],
                           capture_output=True, text=True, pass_fds=(fd,), timeout=15)
    if magic.returncode:
        raise ReviewRequired('magic_unavailable')
    mime = magic.stdout.strip()
    if mime not in allowed_mime:
        return mime, 'not_checked'
    if kind == 'sidecar':
        return mime, 'not_applicable'
    if not shutil.which('ffprobe'):
        return mime, 'not_checked'
    p = subprocess.run(['ffprobe', '-v', 'error', '-protocol_whitelist', 'file',
                        '-show_entries', 'format=duration:stream=codec_type', '-of', 'json', path],
                       capture_output=True, text=True, pass_fds=(fd,), timeout=45)
    if p.returncode:
        return mime, 'review'
    data = json.loads(p.stdout)
    duration = float(data.get('format', {}).get('duration', 0))
    streams = {s.get('codec_type') for s in data.get('streams', [])}
    plausible = math.isfinite(duration) and duration > 0 and kind in streams
    # Embedded data/attachments need separate inspection, not an automatic pass.
    return mime, 'plausible' if plausible and not streams.intersection({'data', 'attachment'}) else 'review'


def inspect(root):
    root = Path(root).resolve(strict=True)
    if not root.is_dir():
        raise ReviewRequired('root_not_a_directory')
    results = []
    def walk_error(_):
        raise ReviewRequired('directory_unreadable')
    for folder, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        links = [d for d in dirs if (Path(folder) / d).is_symlink()]
        dirs[:] = sorted(d for d in dirs if d not in links)
        for name in sorted(files + links):
            if len(results) >= 10000:
                raise ReviewRequired('inventory_limit')
            path = Path(folder) / name
            row = {'item': len(results) + 1, 'kind': 'unexpected', 'status': 'review'}
            try:
                with open_regular(root, path.relative_to(root).as_posix()) as handle:
                    before = stamp(handle)
                    requested_kind = MIME.get(path.suffix.lower(), ('unexpected', set()))[0]
                    if requested_kind == 'unexpected':
                        raise ReviewRequired('unexpected_file_type')
                    mime, media = probe(handle, requested_kind, MIME[path.suffix.lower()][1])
                    row['kind'] = classify(path.suffix, mime)
                    row['media_probe'] = media
                    if stamp(handle) != before:
                        raise ReviewRequired('source_changed')
                    if row['kind'] == 'unexpected':
                        raise ReviewRequired('extension_type_mismatch')
                    row['status'] = 'inspection_only' if media in ('plausible', 'not_applicable') else 'review'
            except (OSError, ValueError, subprocess.SubprocessError, ReviewRequired) as error:
                row['finding'] = str(error) if isinstance(error, ReviewRequired) else 'inspection_unavailable'
            results.append(row)
    return {'mode': 'read_only_inspection', 'items': results,
            'release_authorized': False, 'antivirus': 'not_run',
            'scope': 'Completion must be independently confirmed. Inspection is not malware clearance.'}


def verify(root, manifest):
    """Stream v1 SHA-1 pieces across exact files; no fetching or size-based matching."""
    length = manifest['piece_length']
    files, expected = manifest['files'], manifest['pieces_sha1']
    if type(length) is not int or not 1 <= length <= 64 * 1024 * 1024:
        raise ReviewRequired('invalid_piece_length')
    if not isinstance(files, list) or not 1 <= len(files) <= 10000 or not isinstance(expected, list):
        raise ReviewRequired('invalid_manifest')
    total, names = 0, set()
    for item in files:
        parts_for(item['path'])
        if item['path'] in names or type(item['length']) is not int or item['length'] < 0:
            raise ReviewRequired('invalid_manifest')
        names.add(item['path'])
        total += item['length']
    if total == 0 or len(expected) != (total + length - 1) // length:
        raise ReviewRequired('invalid_piece_table')
    try:
        hashes = [bytes.fromhex(value) for value in expected]
    except (TypeError, ValueError):
        raise ReviewRequired('invalid_piece_table') from None
    if any(len(h) != 20 for h in hashes):
        raise ReviewRequired('invalid_piece_table')
    with ExitStack() as stack:
        handles = [stack.enter_context(open_regular(root, f['path'])) for f in files]
        before = [stamp(h) for h in handles]
        if any(s[2] != f['length'] for s, f in zip(before, files)):
            raise ReviewRequired('payload_size_mismatch')
        piece, used, checked, mismatches = hashlib.sha1(), 0, 0, 0
        for handle in handles:
            while block := handle.read(min(1024 * 1024, length - used)):
                piece.update(block)
                used += len(block)
                if used == length:
                    mismatches += piece.digest() != hashes[checked]
                    checked += 1
                    piece, used = hashlib.sha1(), 0
        if used:
            mismatches += piece.digest() != hashes[checked]
            checked += 1
        stable = before == [stamp(h) for h in handles]
    return {'mode': 'v1_piece_integrity', 'status': 'match' if stable and not mismatches else 'review',
            'pieces_checked': checked, 'piece_mismatches': mismatches, 'source_stable': stable,
            'scope': 'Matches supplied metadata only; does not prove source trust, completion or malware safety.'}


def coverage(record):
    """Evaluate claimed byte intervals; never equate chunk coverage with a clean scan."""
    size, windows = record['total_bytes'], record['windows']
    if type(size) is not int or size <= 0 or not isinstance(windows, list):
        raise ReviewRequired('invalid_coverage_record')
    intervals, failed = [], 0
    for window in windows:
        start, count = window['offset'], window['length']
        if type(start) is not int or type(count) is not int or start < 0 or count <= 0 or start + count > size:
            raise ReviewRequired('invalid_scan_window')
        if type(window.get('exit_code')) is not int or window['exit_code'] != 0:
            failed += 1
        else:
            intervals.append((start, start + count))
    end, covered = 0, 0
    for start, stop in sorted(intervals):
        covered += max(0, stop - max(start, end))
        end = max(end, stop)
    return {'mode': 'reported_scan_coverage', 'byte_coverage': 'full' if covered == size else 'partial',
            'reported_bytes_covered': covered, 'failed_or_unknown_windows': failed,
            'analysis_method': 'raw_windows' if record.get('method') == 'raw_windows' else 'unspecified',
            'whole_file_analysis_verified': False, 'release_authorized': False,
            'scope': 'Evaluates supplied records; does not run antivirus or prove the engine inspected every byte.'}


def read_json(path):
    with Path(path).open('rb') as stream:
        data = stream.read(2 * 1024 * 1024 + 1)
    if len(data) > 2 * 1024 * 1024:
        raise ReviewRequired('manifest_size_limit')
    return json.loads(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    for name in ['inspect', 'verify']:
        p = sub.add_parser(name)
        p.add_argument('--completed-root', required=True, type=Path)
        p.add_argument('--completion-confirmed', required=True, action='store_true')
        if name == 'verify':
            p.add_argument('--manifest', required=True, type=Path)
    sub.add_parser('coverage').add_argument('record', type=Path)
    args = parser.parse_args()
    try:
        if args.command == 'inspect':
            result = inspect(args.completed_root)
        elif args.command == 'verify':
            result = verify(args.completed_root, read_json(args.manifest))
        else:
            result = coverage(read_json(args.record))
    except (OSError, ValueError, TypeError, KeyError, IndexError, AttributeError, ReviewRequired):
        parser.exit(2, 'Check incomplete. Review inputs, dependencies and permissions privately; no raw details emitted.\n')
    print(json.dumps(result, indent=2))
    if args.command == 'inspect':
        return 0 if result['items'] and all(r['status'] == 'inspection_only' for r in result['items']) else 1
    if args.command == 'verify':
        return 0 if result['status'] == 'match' else 1
    return 0 if result['byte_coverage'] == 'full' and result['failed_or_unknown_windows'] == 0 else 1


if __name__ == '__main__':
    raise SystemExit(main())
