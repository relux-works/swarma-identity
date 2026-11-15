"""Real Bash/file cleanup regressions with inert Apple boundaries, not hosted CI."""
import ast
import base64
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = Path(os.environ.get('RELEASE_WORKFLOW_UNDER_TEST', ROOT / '.github/workflows/release.yml'))

# Only native/platform boundaries are fixtures. The signing/cleanup shell and
# GITHUB_ENV file handling run unchanged; no real credentials or native keys.
STUB = r'''#!/usr/bin/env python3
import json, os, pathlib, shutil, signal, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ['FIXTURE_ROOT'])
def trace(event):
    with (root / 'keychain.trace').open('a') as stream:
        stream.write(json.dumps(event) + '\n')
if name == 'uname':
    print('Darwin')
elif name == 'git':
    print(os.environ['GITHUB_SHA'])
elif name == 'xcrun':
    assert args[0] == '--find'
    print('/inert/' + args[1])
elif name == 'security':
    if args[0] == 'create-keychain':
        pathlib.Path(args[-1]).write_text('INERT-KEYCHAIN')
        if os.environ.get('AUTO_LIST_NEW_KEYCHAIN') == '1':
            state = root / 'search-list.json'
            state.write_text(json.dumps([*json.loads(state.read_text()), args[-1]]))
    elif args[0] == 'unlock-keychain':
        if os.environ['FIXTURE_CASE'] == 'sigkill':
            recorded = int((root / 'signing.pid').read_text())
            assert recorded == os.getppid(), 'refuse to signal an unowned process'
            os.kill(recorded, signal.SIGKILL)
        elif not os.environ['FIXTURE_CASE'].startswith('search'):
            sys.exit(42)  # a real failed gate before the trap's first cleanup
    elif args[0] == 'list-keychains':
        state = root / 'search-list.json'
        if '-s' not in args:
            trace('query-list')
            for path in json.loads(state.read_text()): print('    "' + path + '"')
        else:
            values = args[args.index('-s') + 1:]
            restoring = not values or '/swarma-release.' not in values[0]
            trace('restore-list' if restoring else 'prepend-list')
            if not restoring:
                snapshot = pathlib.Path(values[0]).parent / 'keychain-state.json'
                assert set(json.loads(snapshot.read_text())) == {'search_list', 'default_keychain'}
                assert snapshot.stat().st_mode & 0o777 == 0o600
            marker = root / 'list-restore-failed'
            if restoring and os.environ.get('FAIL_RESTORE') == 'list' and not marker.exists():
                marker.touch(); sys.exit(42)
            state.write_text(json.dumps(values))
    elif args[0] == 'default-keychain':
        state = root / 'default-keychain.json'
        if '-s' not in args:
            trace('query-default'); print('    "' + json.loads(state.read_text()) + '"')
        else:
            trace('restore-default')
            marker = root / 'default-restore-failed'
            if os.environ.get('FAIL_RESTORE') == 'default' and not marker.exists():
                marker.touch(); sys.exit(42)
            state.write_text(json.dumps(args[-1]))
    elif args[0] == 'find-identity':
        print('  1) ' + 'A' * 40 + ' "Developer ID Application: Relux Works, LLC (262RZ595FP)"')
    elif args[0] == 'delete-keychain':
        trace('delete-keychain')
        if os.environ.get('FAIL_SECURITY') == '1':
            sys.exit(42)
        pathlib.Path(args[-1]).unlink()
    else:
        assert args[0] in ('set-keychain-settings', 'import', 'set-key-partition-list')
elif name == 'go':
    assert args[0] == 'run'
    app = pathlib.Path(args[-1])
    (app / 'Contents/MacOS').mkdir(parents=True)
    (app / 'Contents/MacOS/swarma-keychain').write_text('INERT-BINARY')
    shutil.copyfile(args[-2], app / 'Contents/embedded.provisionprofile')
    shutil.copyfile(root / 'release/macos/swarma-keychain.entitlements.plist', app.with_suffix('.entitlements.plist'))
elif name == 'codesign':
    trace('codesign')
    assert '--sign' in args and '--deep' not in args
    keychain = args[args.index('--keychain') + 1]
    assert json.loads((root / 'search-list.json').read_text())[0] == keychain
    if os.environ['FIXTURE_CASE'] == 'search-sigkill':
        recorded = int((root / 'signing.pid').read_text())
        assert recorded == os.getppid()
        os.kill(recorded, signal.SIGKILL)
    else:
        sys.exit(42)  # boundary stop: only ordering/restoration is exercised
elif name == 'rm':
    marker = root / 'rm-first-failure'
    if os.environ.get('FAIL_FIRST_RM') == '1' and not marker.exists():
        marker.touch()
        sys.exit(42)
    os.execv('/bin/rm', ['/bin/rm', *args])
else:
    sys.exit(99)  # no fixture may silently implement an unexercised native tool
'''


def workflow_steps():
    text = WORKFLOW.read_text()
    blocks = re.findall(r'^      - name: ([^\n]+)\n(.*?)(?=^      - |\Z)', text, re.M | re.S)
    result = {}
    for name, body in blocks:
        condition = re.search(r'^        if: (.*)$', body, re.M)
        run = re.search(r'^        run: \|\n((?:          .*\n|\n)+)', body, re.M)
        result[name] = (condition.group(1) if condition else 'success()',
                        ''.join(line[10:] if line.strip() else '\n' for line in run.group(1).splitlines(True)) if run else '')
    return result


def condition_value(expression, prior_success, cleanup_outcome):
    # Bounded interpreter for this workflow's literal boolean conditions, not a
    # GitHub runner replacement. Unsupported syntax fails the test, not open.
    expression = expression.removeprefix('${{').removesuffix('}}').strip()
    expression = expression.replace('always()', 'True').replace('success()', str(prior_success))
    expression = expression.replace('steps.cleanup.outcome', repr(cleanup_outcome))
    expression = expression.replace('&&', ' and ').replace('||', ' or ')
    expression = re.sub(r'\bfalse\b', 'False', expression)
    expression = re.sub(r'\btrue\b', 'True', expression)
    tree = ast.parse(expression, mode='eval')
    allowed = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Constant, ast.Compare, ast.Eq)
    if any(not isinstance(node, allowed) for node in ast.walk(tree)):
        raise AssertionError('unsupported workflow condition')
    return eval(compile(tree, '<bounded workflow condition>', 'eval'), {'__builtins__': {}}, {})


class CleanupWorkflowTests(unittest.TestCase):
    def setUp(self):
        (ROOT / '.temp').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix='cleanup-regression-', dir=ROOT / '.temp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'scripts').mkdir()
        for name in ('release-macos.sh', 'release-cleanup.sh', 'release_checks.py', 'release_keychains.py'):
            source = ROOT / 'scripts' / name
            if source.exists():
                shutil.copyfile(source, self.root / 'scripts' / name)
        shutil.copytree(ROOT / 'release', self.root / 'release')
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for name in ('uname', 'git', 'xcrun', 'security', 'codesign', 'spctl', 'ditto', 'rm', 'go'):
            path = self.bin / name
            path.write_text(STUB.replace('#!/usr/bin/env python3', '#!' + sys.executable, 1))
            path.chmod(0o700)
        self.runner = self.root / 'runner'
        self.runner.mkdir()
        self.original_search = [str(self.root / name) for name in ('Login "Team".keychain-db', 'Other Keychain.keychain-db', 'Normal.keychain-db', r'literal\backslash.keychain-db', 'one" "/two.keychain-db')]
        self.original_default = self.original_search[0]
        (self.root / 'search-list.json').write_text(json.dumps(self.original_search))
        (self.root / 'default-keychain.json').write_text(json.dumps(self.original_default))
        self.env_file = self.root / 'github-env'
        self.env_file.touch()
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ['PATH'],
                        FIXTURE_ROOT=str(self.root), FIXTURE_CASE='sigkill',
                        RUNNER_TEMP=str(self.runner), GITHUB_ENV=str(self.env_file),
                        GITHUB_ACTIONS='true', GITHUB_REF_TYPE='tag',
                        GITHUB_REF='refs/tags/v0.1.0-rc.1', GITHUB_REF_NAME='v0.1.0-rc.1',
                        GITHUB_SHA='A' * 40, MACOS_SIGN_P12=base64.b64encode(b'INERT-P12').decode(),
                        MACOS_SIGN_P12_PASSWORD='INERT-PASSWORD', ASC_ISSUER_ID='INERT-ISSUER',
                        ASC_KEY_ID='INERT-ID', ASC_KEY_P8='-----BEGIN PRIVATE KEY-----\nINERT-P8\n-----END PRIVATE KEY-----\n')

    def signing(self, case, fail_rm=False):
        self.env.update(FIXTURE_CASE=case, FAIL_FIRST_RM='1' if fail_rm else '0')
        with (self.root / 'signing.log').open('w') as log:
            process = subprocess.Popen(['bash', 'scripts/release-macos.sh'], cwd=self.root,
                                       env=self.env, stdout=log, stderr=subprocess.STDOUT)
            (self.root / 'signing.pid').write_text(str(process.pid))
            try:
                status = process.wait(timeout=15)
            finally:
                if process.poll() is None:
                    process.kill()  # only this recorded fixture PID
                    process.wait()
        lines = self.env_file.read_text().splitlines()
        self.assertEqual(len(lines), 2, 'recovery metadata must contain only two path records')
        values = dict(line.split('=', 1) for line in lines)
        self.assertEqual(set(values), {'SWARMA_RELEASE_WORK', 'SWARMA_RELEASE_KEYCHAIN'},
                         'only non-secret recovery paths must be exported before credentials')
        self.env.update(values)
        work = Path(values['SWARMA_RELEASE_WORK'])
        self.assertEqual(values['SWARMA_RELEASE_KEYCHAIN'], str(work / 'release.keychain-db'))
        self.assertEqual(work.parent, self.runner)
        return status, work

    def workflow_cleanup(self, prior_success):
        steps = workflow_steps()
        self.assertIn('Clean signing material', steps, 'workflow cleanup step missing')
        self.assertLess(list(steps).index('Clean signing material'), list(steps).index('Publish verified assets through a draft release'))
        expression, command = steps['Clean signing material']
        outcome = 'skipped'
        status = None
        if condition_value(expression, prior_success, outcome):
            result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', command], cwd=self.root,
                                    env=self.env, capture_output=True, text=True, timeout=15)
            status = result.returncode
            outcome = 'success' if status == 0 else 'failure'
        publish_if, _ = steps['Publish verified assets through a draft release']
        admitted = condition_value(publish_if, prior_success and status == 0, outcome)
        return status, admitted

    # Claim: configuration follows unlock and precedes the first codesign;
    # both trap and workflow cleanup use the restore-before-delete helper.
    # This static ordering check supplements real shell fixture runs below.
    def test_search_list_set_and_restore_order(self):
        signing = (ROOT / 'scripts/release-macos.sh').read_text()
        cleanup = (ROOT / 'scripts/release-cleanup.sh').read_text()
        configure = 'python3 "$ROOT/scripts/release_keychains.py" configure "$work" "$keychain"'
        restore = 'python3 "$(dirname "$0")/release_keychains.py" restore "$work"'
        self.assertIn(configure, signing, 'missing search-list configuration')
        self.assertIn(restore, cleanup, 'missing search-list restoration')
        self.assertLess(signing.index('security unlock-keychain'), signing.index(configure))
        self.assertLess(signing.index(configure), signing.index('  codesign --force'))
        self.assertLess(cleanup.index(restore), cleanup.index('security delete-keychain'))

    def assert_restored_before_delete(self):
        self.assertEqual(json.loads((self.root / 'search-list.json').read_text()), self.original_search)
        self.assertEqual(json.loads((self.root / 'default-keychain.json').read_text()), self.original_default)
        events = [json.loads(line) for line in (self.root / 'keychain.trace').read_text().splitlines()]
        self.assertLess(events.index('prepend-list'), events.index('codesign'))
        delete = events.index('delete-keychain')
        self.assertEqual(events[delete - 2:delete], ['restore-list', 'restore-default'])

    # Claim: real candidate Bash prepends the temp keychain with exact quoted
    # path preservation before its first codesign. The trap restores list and
    # default before deletion, retaining the injected codesign failure (42).
    def test_search_list_precedes_codesign_and_trap_restores(self):
        status, work = self.signing('search')
        self.assertEqual(status, 42)
        self.assertFalse(work.exists())
        self.assert_restored_before_delete()
        self.assertEqual(self.workflow_cleanup(False), (0, False))

    # Claim: a newly created keychain already listed by the platform is not
    # duplicated or retained in restored state; all original paths remain.
    def test_search_list_handles_already_listed_temporary_keychain(self):
        self.env['AUTO_LIST_NEW_KEYCHAIN'] = '1'
        status, work = self.signing('search')
        self.assertEqual(status, 42)
        self.assertFalse(work.exists())
        self.assert_restored_before_delete()

    # Claim: a SIGKILL after search-list mutation bypasses the trap; the actual
    # independent cleanup step restores both states before deletion and is
    # idempotent. Native security/codesign are inert boundaries on Linux.
    def test_search_list_restored_after_signing_sigkill(self):
        status, work = self.signing('search-sigkill')
        self.assertEqual(status, -signal.SIGKILL)
        self.assertEqual(json.loads((self.root / 'search-list.json').read_text())[0], str(work / 'release.keychain-db'))
        self.assertEqual(self.workflow_cleanup(False), (0, False))
        self.assert_restored_before_delete()
        self.assertFalse(work.exists())
        self.assertEqual(self.workflow_cleanup(False), (0, False))

    def check_restore_retry(self, failure):
        self.env['FAIL_RESTORE'] = failure
        status, work = self.signing('search')
        self.assertEqual(status, 42)
        self.assertTrue((work / 'keychain-state.json').exists())
        self.assertTrue((work / 'release.keychain-db').exists())
        self.assertFalse((work / 'AuthKey.p8').exists(), 'loose ASC key must be removed even if restore fails')
        events = [json.loads(line) for line in (self.root / 'keychain.trace').read_text().splitlines()]
        self.assertNotIn('delete-keychain', events, 'must restore before deleting')
        self.assertEqual(self.workflow_cleanup(False), (0, False))
        self.assertFalse(work.exists())
        self.assert_restored_before_delete()

    # Claim: a failed list restore blocks deletion, retains non-secret retry
    # state, scrubs loose credentials, and independent cleanup retries safely.
    def test_search_list_restore_failure_retries(self):
        self.check_restore_retry('list')

    # Claim: default-keychain restore failure has the same retry guarantee;
    # successful list restoration alone must not permit keychain deletion.
    def test_default_keychain_restore_failure_retries(self):
        self.check_restore_retry('default')

    # Claim: restoration failure in the independent workflow step blocks
    # publication even with successful prior gates; retry preserves that failure.
    def test_workflow_restore_failure_blocks_publication(self):
        work = Path(tempfile.mkdtemp(prefix='swarma-release.', dir=self.runner))
        keychain = work / 'release.keychain-db'
        keychain.write_text('INERT-KEYCHAIN')
        (work / 'AuthKey.p8').write_text('INERT-P8')
        result = subprocess.run([sys.executable, 'scripts/release_keychains.py', 'configure', str(work), str(keychain)],
                                cwd=self.root, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.env.update(SWARMA_RELEASE_WORK=str(work), SWARMA_RELEASE_KEYCHAIN=str(keychain), FAIL_RESTORE='list')
        self.assertEqual(self.workflow_cleanup(True), (1, False))
        self.assertTrue(keychain.exists())
        self.assertTrue((work / 'keychain-state.json').exists())
        self.assertFalse((work / 'AuthKey.p8').exists())
        self.assertEqual(self.workflow_cleanup(False), (0, False))
        self.assertFalse(work.exists())

    # Claim: real SIGKILL cannot run the signing trap; a new process executing
    # the actual always-step removes retained inert P8/P12/password/keychain,
    # and a successful cleanup cannot clear the earlier failed signing outcome.
    def test_workflow_cleanup_after_signing_sigkill(self):
        status, work = self.signing('sigkill')
        self.assertEqual(status, -signal.SIGKILL)
        self.assertTrue(all((work / name).exists() for name in ('AuthKey.p8', 'certificate.p12', 'keychain-password', 'release.keychain-db')))
        cleanup_status, publish = self.workflow_cleanup(False)
        self.assertFalse(work.exists(), 'workflow cleanup left credential files after SIGKILL')
        self.assertEqual(cleanup_status, 0)
        self.assertFalse(publish, 'cleanup must not clear an earlier failed gate')
        self.assertEqual(self.workflow_cleanup(False), (0, False), 'cleanup must be idempotent')

    # Claim: an actual first trap removal failure leaves inert credentials; the
    # independent always-step retries it and removes them, preserving exit 42.
    def test_workflow_cleanup_retries_first_trap_failure(self):
        status, work = self.signing('gate-failure', fail_rm=True)
        self.assertEqual(status, 42)
        self.assertTrue((work / 'AuthKey.p8').exists())
        self.assertTrue((self.root / 'rm-first-failure').exists())
        cleanup_status, publish = self.workflow_cleanup(False)
        self.assertFalse(work.exists(), 'workflow cleanup did not retry the first removal failure')
        self.assertEqual(cleanup_status, 0)
        self.assertFalse(publish)

    # Claim: with successful prior gates, independent cleanup failure blocks
    # publication; a successful retry cannot erase that failure. The adjacent
    # clean control admits publication. This models outcomes, not GitHub itself.
    def test_cleanup_failure_blocks_publication_and_positive_control(self):
        for fault in ('none', 'rm', 'security'):
            with self.subTest(fault=fault):
                work = Path(tempfile.mkdtemp(prefix='swarma-release.', dir=self.runner))
                (work / 'AuthKey.p8').write_text('INERT-P8')
                (work / 'release.keychain-db').write_text('INERT-KEYCHAIN')
                self.env.update(SWARMA_RELEASE_WORK=str(work), SWARMA_RELEASE_KEYCHAIN=str(work / 'release.keychain-db'),
                                FAIL_FIRST_RM='1' if fault == 'rm' else '0', FAIL_SECURITY='1' if fault == 'security' else '0')
                status, publish = self.workflow_cleanup(True)
                self.assertEqual(status, 0 if fault == 'none' else 1)
                self.assertEqual(publish, fault == 'none')
                self.env['FAIL_SECURITY'] = '0'
                self.assertEqual(self.workflow_cleanup(False), (0, False))
                self.assertFalse(work.exists())

    # Claim: cleanup cannot delete an unrelated path, a symlink target, or act
    # on incomplete metadata. Empty metadata is a valid pre-signing no-op.
    def test_cleanup_path_boundary_and_noop(self):
        self.assertEqual(self.workflow_cleanup(True), (0, True))
        sentinel = self.root / 'preserve'
        sentinel.mkdir()
        (sentinel / 'keep').write_text('keep')
        link = self.runner / 'swarma-release.link'
        link.symlink_to(sentinel, target_is_directory=True)
        for work, keychain in ((sentinel, sentinel / 'release.keychain-db'), (link, link / 'release.keychain-db'), (sentinel, '')):
            self.env.update(SWARMA_RELEASE_WORK=str(work), SWARMA_RELEASE_KEYCHAIN=str(keychain))
            self.assertEqual(self.workflow_cleanup(True), (1, False))
            self.assertEqual((sentinel / 'keep').read_text(), 'keep')

    # Claim: preserving the literal always() token while making its expression
    # false must kill the functional SIGKILL recovery regression, not merely a
    # YAML token scan. Native/hosted scheduling remains outside this harness.
    def test_cleanup_control_disables_execution_with_always_token_intact(self):
        original = WORKFLOW.read_text()
        mutant = original.replace('if: ${{ always() }}', 'if: ${{ always() && false }}', 1)
        self.assertNotEqual(mutant, original, 'control plant was not applied')
        self.assertIn('always()', mutant)
        path = self.root / 'cleanup-disabled.yml'
        path.write_text(mutant)
        result = subprocess.run([sys.executable, '-m', 'unittest', '-v',
                                 'test_release_cleanup.CleanupWorkflowTests.test_workflow_cleanup_after_signing_sigkill'],
                                cwd=ROOT / 'scripts', env=dict(os.environ, RELEASE_WORKFLOW_UNDER_TEST=str(path)),
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('workflow cleanup left credential files after SIGKILL', result.stderr)


if __name__ == '__main__':
    unittest.main()
