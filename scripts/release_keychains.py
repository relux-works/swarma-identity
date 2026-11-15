#!/usr/bin/env python3
"""Save/restore non-secret user keychain paths; no signing material is stored."""
import argparse
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys


class StateError(ValueError):
    pass


def security(*args):
    return subprocess.run(['security', *args], check=True, capture_output=True, text=True).stdout


def paths(raw):
    values = shlex.split(raw)
    if any(not value.startswith('/') or '\x00' in value for value in values):
        raise StateError('expected absolute keychain paths')
    return values


def configure(work, keychain):
    state = work / 'keychain-state.json'
    if state.exists() or state.is_symlink():
        raise StateError('original keychain state already recorded')
    search = paths(security('list-keychains', '-d', 'user'))
    default = paths(security('default-keychain', '-d', 'user'))
    if len(default) != 1 or default[0] == str(keychain):
        raise StateError('expected one original default keychain')
    # Some macOS versions may already list a newly created keychain. It was
    # created by this job, so never restore a reference to it after deletion.
    search = [path for path in search if path != str(keychain)]
    pending = work / 'keychain-state.pending'
    with pending.open('x') as stream:
        os.chmod(pending, 0o600)
        json.dump({'search_list': search, 'default_keychain': default[0]}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    # Commit complete recovery data before the first native list mutation.
    pending.replace(state)
    security('list-keychains', '-d', 'user', '-s', str(keychain), *search)
    # No default-keychain mutation is needed for signing. Cleanup nevertheless
    # restores the saved default explicitly before deleting the job keychain.


def restore(work):
    state = work / 'keychain-state.json'
    if state.is_symlink():
        raise StateError('keychain recovery state must not be a symlink')
    if not state.exists():
        return  # killed before configuration, or already fully cleaned
    saved = json.loads(state.read_text())
    if (not isinstance(saved, dict) or set(saved) != {'search_list', 'default_keychain'}
            or not isinstance(saved['search_list'], list)
            or not all(isinstance(path, str) and path.startswith('/') and '\x00' not in path for path in saved['search_list'])
            or not isinstance(saved['default_keychain'], str)
            or not saved['default_keychain'].startswith('/') or '\x00' in saved['default_keychain']):
        raise StateError('invalid keychain recovery paths')
    failed = False
    # Attempt both restores even if one fails. Leave the state for the next
    # independent cleanup; it is idempotent and must precede native deletion.
    for args in (('list-keychains', '-d', 'user', '-s', *saved['search_list']),
                 ('default-keychain', '-d', 'user', '-s', saved['default_keychain'])):
        try:
            security(*args)
        except subprocess.CalledProcessError:
            failed = True
    if failed:
        raise StateError('could not restore original keychain search list/default')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('configure', 'restore'))
    parser.add_argument('work', type=Path)
    parser.add_argument('keychain', type=Path, nargs='?')
    args = parser.parse_args()
    try:
        if args.command == 'configure':
            if args.keychain is None:
                raise StateError('configure requires the temporary keychain path')
            configure(args.work, args.keychain)
        else:
            restore(args.work)
    except (OSError, ValueError, subprocess.CalledProcessError):
        # Native commands receive only paths, but keep errors bounded and never
        # render file contents, environment values or secret-bearing tool argv.
        print('release keychains: could not ' + args.command + ' user keychain state', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
