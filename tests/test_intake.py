import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import intake


class IntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'a.txt').write_bytes(b'abcdefg')
        (self.root / 'b.txt').write_bytes(b'hijklm')
        payload = b'abcdefghijklm'
        self.manifest = {'piece_length': 5, 'files': [{'path': 'a.txt', 'length': 7}, {'path': 'b.txt', 'length': 6}],
                         'pieces_sha1': [hashlib.sha1(payload[i:i+5]).hexdigest() for i in range(0, len(payload), 5)]}

    def test_cross_file_piece_and_short_final_piece(self):
        result = intake.verify(self.root, self.manifest)
        self.assertEqual(result['status'], 'match')
        self.assertEqual(result['pieces_checked'], 3)

    def test_tampering_is_detected(self):
        (self.root / 'b.txt').write_bytes(b'Xijklm')
        self.assertEqual(intake.verify(self.root, self.manifest)['piece_mismatches'], 1)

    def test_missing_file_never_becomes_partial_success(self):
        (self.root / 'b.txt').unlink()
        with self.assertRaises(OSError):
            intake.verify(self.root, self.manifest)

    def test_wrong_length_is_rejected(self):
        (self.root / 'b.txt').write_bytes(b'x')
        with self.assertRaises(intake.ReviewRequired):
            intake.verify(self.root, self.manifest)

    def test_malformed_piece_table_is_rejected(self):
        self.manifest['pieces_sha1'].pop()
        with self.assertRaises(intake.ReviewRequired):
            intake.verify(self.root, self.manifest)

    def test_traversal_absolute_and_ambiguous_paths_are_rejected(self):
        for path in ['../a.txt', '/a.txt', 'dir//a.txt', 'dir/./a.txt', 'dir\\a.txt']:
            with self.subTest(path=path), self.assertRaises(intake.ReviewRequired):
                intake.open_regular(self.root, path)

    def test_symlink_file_and_parent_are_rejected(self):
        (self.root / 'link.txt').symlink_to(self.root / 'a.txt')
        (self.root / 'linkdir').symlink_to(self.root, target_is_directory=True)
        for path in ['link.txt', 'linkdir/a.txt']:
            with self.assertRaises(OSError):
                intake.open_regular(self.root, path)

    def test_fifo_is_rejected_without_reading_or_blocking(self):
        os.mkfifo(self.root / 'pipe')
        with self.assertRaises(intake.ReviewRequired):
            intake.open_regular(self.root, 'pipe')


class InspectionTests(unittest.TestCase):
    def test_extension_type_mismatch(self):
        self.assertEqual(intake.classify('.mkv', 'application/x-executable'), 'unexpected')
        self.assertEqual(intake.classify('.zip', 'application/zip'), 'unexpected')
        self.assertEqual(intake.classify('.mkv', 'video/x-matroska'), 'video')

    def test_report_excludes_real_names_and_never_authorizes_release(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'SYNTHETIC_PRIVATE_NAME.srt').write_text('1\n00:00:01,000 --> 00:00:02,000\nExample\n')
            with patch.object(intake, 'probe', return_value=('text/plain', 'not_applicable')):
                result = intake.inspect(root)
            self.assertEqual(result['items'][0]['status'], 'inspection_only')
            self.assertFalse(result['release_authorized'])
            self.assertNotIn('SYNTHETIC_PRIVATE_NAME', json.dumps(result))
            self.assertNotIn(root, json.dumps(result))

    def test_unavailable_media_probe_requires_review(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'example.mkv').write_bytes(b'synthetic fixture')
            with patch.object(intake, 'probe', return_value=('video/x-matroska', 'not_checked')):
                self.assertEqual(intake.inspect(root)['items'][0]['status'], 'review')

    def test_mismatch_does_not_reach_ffprobe(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'example.mkv').write_bytes(b'synthetic fixture')
            with intake.open_regular(root, 'example.mkv') as handle, patch.object(intake.subprocess, 'run') as run:
                run.return_value.returncode = 0
                run.return_value.stdout = 'application/x-executable\n'
                mime, media = intake.probe(handle, 'video', {'video/x-matroska'})
                self.assertEqual(media, 'not_checked')
                self.assertEqual(run.call_count, 1)


class CoverageTests(unittest.TestCase):
    def test_overlapping_windows_do_not_double_count_or_prove_whole_analysis(self):
        record = {'total_bytes': 10, 'method': 'raw_windows', 'windows': [
            {'offset': 0, 'length': 6, 'exit_code': 0}, {'offset': 4, 'length': 6, 'exit_code': 0}]}
        result = intake.coverage(record)
        self.assertEqual(result['reported_bytes_covered'], 10)
        self.assertEqual(result['byte_coverage'], 'full')
        self.assertFalse(result['whole_file_analysis_verified'])
        self.assertFalse(result['release_authorized'])

    def test_gap_failed_and_unknown_windows_are_not_coverage(self):
        record = {'total_bytes': 10, 'windows': [{'offset': 0, 'length': 4, 'exit_code': 0},
                  {'offset': 4, 'length': 4, 'exit_code': 1}, {'offset': 8, 'length': 2}]}
        result = intake.coverage(record)
        self.assertEqual(result['reported_bytes_covered'], 4)
        self.assertEqual(result['failed_or_unknown_windows'], 2)
        self.assertEqual(result['byte_coverage'], 'partial')

    def test_out_of_bounds_and_negative_windows_are_rejected(self):
        for offset, length in [(-1, 5), (8, 5), (0, 0)]:
            with self.assertRaises(intake.ReviewRequired):
                intake.coverage({'total_bytes': 10, 'windows': [{'offset': offset, 'length': length, 'exit_code': 0}]})


class PrivacyTests(unittest.TestCase):
    def test_cli_errors_do_not_echo_private_paths(self):
        name = '/SYNTHETIC_PRIVATE_LOCATION/missing.json'
        run = subprocess.run([sys.executable, 'intake.py', 'coverage', name], capture_output=True, text=True)
        self.assertEqual(run.returncode, 2)
        self.assertNotIn(name, run.stderr)


if __name__ == '__main__':
    unittest.main()
