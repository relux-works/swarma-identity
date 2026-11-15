"""Native path-record/argv regression fixtures; no macOS API is executed."""
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import release_keychains as keychains


ORIGINALS = ['/keys/normal.keychain-db', '/keys/with spaces.keychain-db',
             '/keys/one"quote.keychain-db', r'/keys/literal\backslash.keychain-db',
             '/keys/one" "/extra.keychain-db', '/keys/end\\']


def native(records):
    # Apple display_name wraps paths in quotes without shell/JSON escaping.
    return ''.join('    "' + path + '"\n' for path in records)


class NativeKeychainPathsTests(unittest.TestCase):
    # Claim: one native line yields one unchanged path, including literal quote,
    # backslash and quote/space path-splitting witnesses beside ordinary paths.
    def test_native_records_preserve_literal_paths(self):
        self.assertEqual(keychains.paths(native(ORIGINALS)), ORIGINALS)
        for path in ORIGINALS:
            with self.subTest(path=path):
                self.assertEqual(keychains.paths(native([path])), [path])
        self.assertEqual(keychains.paths('  "/keys/normal"'), ['/keys/normal'])

    # Claim: filesystem-byte decoding round-trips non-UTF8 bytes, literal quote
    # and backslash exactly; no shell or Unicode-normalization step is applied.
    def test_native_record_filesystem_bytes_roundtrip(self):
        value = b'/keys/opaque-\xff"literal\\name'
        self.assertEqual([os.fsencode(path) for path in keychains.paths(b'    "' + value + b'"\n')], [value])

    # Claim: only complete nonempty outer-quoted absolute-path records pass;
    # malformed multi-line/extra-token input must fail rather than yield a prefix.
    def test_native_records_reject_malformed_input(self):
        for raw in ('', '/keys/plain\n', "'/keys/plain'\n", '"/keys/plain\n',
                    '"/keys/plain" extra\n', '"/keys/plain" /other\n',
                    '"/keys/a\nb"\n', '""\n', '"relative"\n', '"/keys/a\x00b"\n',
                    '"/keys/a\rb"\n', '"/keys/a"\n\n', '"/keys/valid"\nbad\n'):
            with self.subTest(raw=raw), self.assertRaises(keychains.StateError):
                keychains.paths(raw)

    # Claim: saved JSON and native setter argv preserve every original exactly
    # once, with each default variant; restore uses the same unchanged paths.
    def test_native_configure_restore_exact_state_and_arguments(self):
        for default in ORIGINALS:
            with self.subTest(default=default), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                temp_keychain = work / 'release.keychain-db'
                calls = []
                def security(*args):
                    calls.append(args)
                    if args == ('list-keychains', '-d', 'user'):
                        return native(ORIGINALS)
                    if args == ('default-keychain', '-d', 'user'):
                        return native([default])
                    return ''
                with patch.object(keychains, 'security', side_effect=security):
                    keychains.configure(work, temp_keychain)
                    self.assertEqual(json.loads((work / 'keychain-state.json').read_text()),
                                     {'search_list': ORIGINALS, 'default_keychain': default})
                    self.assertEqual(calls[-1], ('list-keychains', '-d', 'user', '-s', str(temp_keychain), *ORIGINALS))
                    keychains.restore(work)
                    self.assertEqual(calls[-2:], [('list-keychains', '-d', 'user', '-s', *ORIGINALS),
                                                  ('default-keychain', '-d', 'user', '-s', default)])

    # Claim: malformed original list/default is rejected before any native setter
    # or committed snapshot; the valid positive controls are immediately above.
    def test_bad_native_records_do_not_mutate_state(self):
        for output in ('list', 'default'):
            with self.subTest(output=output), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                calls = []
                def security(*args):
                    calls.append(args)
                    if args[0] == 'list-keychains':
                        return '"/keys/valid" extra\n' if output == 'list' else native(ORIGINALS)
                    return '"/keys/a\nb"\n'
                with patch.object(keychains, 'security', side_effect=security), self.assertRaises(keychains.StateError):
                    keychains.configure(work, work / 'release.keychain-db')
                self.assertFalse(any('-s' in args for args in calls))
                self.assertEqual(list(work.iterdir()), [])

    # Claim: controlled job paths with either quote, backslash or whitespace
    # refuse before querying native state, writing a snapshot or changing a list.
    def test_controlled_temp_path_refuses_unsafe_characters(self):
        for suffix in ('has space', 'has"quote', "has'quote", 'has\\slash', 'has\nnewline', 'has\rreturn', 'has\ttab'):
            with self.subTest(suffix=suffix), tempfile.TemporaryDirectory() as tmp:
                work = Path(tmp)
                with patch.object(keychains, 'security') as security, self.assertRaises(keychains.StateError):
                    keychains.configure(work, work / suffix)
                security.assert_not_called()
                self.assertEqual(list(work.iterdir()), [])

    # Claim: subprocess output decoding preserves literal bytes/CR before record
    # validation; universal-newline translation must not hide a malformed record.
    def test_security_output_is_not_shell_or_newline_decoded(self):
        raw = b'    "/keys/literal\\name\rpart"\n'
        with patch.object(keychains.subprocess, 'run', return_value=SimpleNamespace(stdout=raw)) as run:
            result = keychains.security('list-keychains', '-d', 'user')
        self.assertEqual(os.fsencode(result), raw)
        self.assertNotIn('text', run.call_args.kwargs)


if __name__ == '__main__':
    unittest.main()
