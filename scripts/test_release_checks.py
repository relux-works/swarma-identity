"""Release contract tests; portable checks and fixture controls, not macOS evidence."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_checks as gate


class ReleaseChecks(unittest.TestCase):
    def setUp(self):
        self.expected_req = (gate.MACOS / "DESIGNATED-REQUIREMENT.txt").read_text()
        self.expected_ent = (gate.MACOS / "swarma-keychain.entitlements.plist").read_bytes()

    # Claim: exactly one pinned DR is accepted; extra conditions, identity/team
    # drift, missing/multiple DRs and unexpected diagnostics cannot pass.
    def test_requirement_equality_and_refusals(self):
        gate.compare_requirement(self.expected_req, self.expected_req)
        gate.compare_requirement(self.expected_req, "Executable=/tmp/App\n" + self.expected_req)
        for name, raw in {
            "team": self.expected_req.replace("262RZ595FP", "WRONGTEAM1"),
            "identifier": self.expected_req.replace("works.relux.swarma-keychain", "works.relux.wrong"),
            "weaker-anchor": self.expected_req.replace("anchor apple generic", "anchor trusted"),
            "extra-condition": self.expected_req.strip() + " or true\n",
            "empty": "", "missing": "Executable=/tmp/App\n",
            "duplicate": self.expected_req * 2,
            "extra-output": self.expected_req + "unexpected output\n",
            "implicit": "# " + self.expected_req,
        }.items():
            with self.subTest(name=name), self.assertRaises(gate.GateError):
                gate.compare_requirement(self.expected_req, raw)

    # Claim: plist formatting/key order and XML/binary encoding do not alter
    # entitlements; any missing/extra key, value, type or duplicate key refuses.
    def test_entitlements_equality_and_refusals(self):
        gate.compare_entitlements(self.expected_ent, self.expected_ent)
        gate.compare_entitlements(self.expected_ent, plistlib.dumps(gate.ENTITLEMENTS, fmt=plistlib.FMT_BINARY))
        gate.compare_entitlements(self.expected_ent, plistlib.dumps(dict(reversed(list(gate.ENTITLEMENTS.items())))))
        for key in gate.ENTITLEMENTS:
            wrong = dict(gate.ENTITLEMENTS)
            wrong[key] = "wrong"
            missing = dict(gate.ENTITLEMENTS)
            del missing[key]
            for value in (wrong, missing):
                with self.subTest(key=key, value=value), self.assertRaisesRegex(gate.GateError, "entitlements mismatch"):
                    gate.compare_entitlements(self.expected_ent, plistlib.dumps(value))
        extra = dict(gate.ENTITLEMENTS, **{"com.apple.security.get-task-allow": True})
        duplicate = self.expected_ent.replace(b"</dict>", b"<key>com.apple.developer.team-identifier</key><string>262RZ595FP</string></dict>")
        for raw in (plistlib.dumps(extra), duplicate, b"not a plist", plistlib.dumps(["wrong-root"])):
            with self.subTest(raw=raw[:20]), self.assertRaises(gate.GateError):
                gate.compare_entitlements(self.expected_ent, raw)
        with self.assertRaisesRegex(gate.GateError, "entitlements mismatch"):
            gate.compare_entitlements(plistlib.dumps({"k": True}), plistlib.dumps({"k": 1}))

    # Claim: owner pins validate the supplied bytes and manifest independently;
    # corruption, missing files and a self-consistent rewritten pin all refuse.
    def test_input_pins_and_tampering(self):
        gate.check_pins(gate.MACOS)
        for name in gate.PINS:
            for variant in ("changed", "missing", "repinned", "symlink"):
                with self.subTest(name=name, variant=variant), tempfile.TemporaryDirectory() as tmp:
                    directory = Path(tmp) / "inputs"
                    shutil.copytree(gate.MACOS, directory)
                    file = directory / name
                    if variant in ("missing", "symlink"):
                        file.unlink()
                        if variant == "symlink":
                            file.symlink_to(gate.MACOS / name)
                    else:
                        file.write_bytes(file.read_bytes() + b"corruption")
                        if variant == "repinned":
                            import hashlib
                            manifest = directory / "SHA256SUMS"
                            manifest.write_text(manifest.read_text().replace(gate.PINS[name], hashlib.sha256(file.read_bytes()).hexdigest()))
                    with self.assertRaises((gate.GateError, OSError)):
                        gate.check_pins(directory)

    # Claim: every absent or whitespace-only organization secret refuses with
    # only its name; valid synthetic siblings distinguish this from reject-all.
    def test_missing_secrets_do_not_disclose_values(self):
        valid = {name: "synthetic-secret-" + name for name in gate.SECRET_NAMES}
        gate.check_secrets(valid)
        for absent in gate.SECRET_NAMES:
            for value in (None, "", " \n\t"):
                env = dict(valid)
                if value is None:
                    del env[absent]
                else:
                    env[absent] = value
                with self.subTest(absent=absent, value=value), self.assertRaises(gate.GateError) as caught:
                    gate.check_secrets(env)
                self.assertEqual(str(caught.exception), "missing required organization secrets: " + absent)
                self.assertFalse(any(secret in str(caught.exception) for secret in valid.values()))

    # Claim: temporary key preparation uses exclusive owner-only files and
    # escaped mask commands. Fixture keys are inert; this does not test Apple.
    def test_prepare_secrets_files_and_masks(self):
        env = {name: "synthetic" for name in gate.SECRET_NAMES}
        env["MACOS_SIGN_P12"] = base64.b64encode(b"fixture-not-a-real-p12").decode()
        env["ASC_KEY_P8"] = "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n"
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, env, clear=True):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                gate.prepare_secrets(Path(tmp))
            self.assertEqual((Path(tmp) / "certificate.p12").read_bytes(), b"fixture-not-a-real-p12")
            self.assertEqual((Path(tmp) / "AuthKey.p8").read_text(), env["ASC_KEY_P8"])
            for file in Path(tmp).iterdir():
                self.assertEqual(file.stat().st_mode & 0o777, 0o600)
            self.assertTrue(all(line.startswith("::add-mask::") for line in output.getvalue().splitlines()))
            self.assertIn("%0A", output.getvalue())
            with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(FileExistsError):
                gate.prepare_secrets(Path(tmp))
        for field, value in (("MACOS_SIGN_P12", "invalid!"), ("ASC_KEY_P8", "invalid pem")):
            with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, dict(env, **{field: value}), clear=True):
                with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(gate.GateError):
                    gate.prepare_secrets(Path(tmp))
                self.assertEqual(list(Path(tmp).iterdir()), [])

    # Claim: only an explicit Accepted notary result and an accepted, notarized
    # Gatekeeper source pass the portable verdict parsers; native commands must
    # also exit zero in the shell and remain untested on Linux.
    def test_notary_and_gatekeeper_verdicts(self):
        gate.check_notary(json.dumps({"status": "Accepted"}))
        for status in ("Invalid", "Rejected", "In Progress", "accepted", "", None):
            with self.subTest(status=status), self.assertRaisesRegex(gate.GateError, "not Accepted"):
                gate.check_notary(json.dumps({"status": status}))
        for value in ([], None, "Accepted", {}):
            with self.subTest(value=value), self.assertRaisesRegex(gate.GateError, "not Accepted"):
                gate.check_notary(json.dumps(value))
        gate.check_assessment("/tmp/App.app: accepted\nsource=Notarized Developer ID\norigin=Developer ID Application\n")
        for raw in (
            "/tmp/App.app: rejected\nsource=Notarized Developer ID\n",
            "/tmp/App.app: accepted\nsource=Unnotarized Developer ID\n",
            "/tmp/App.app: accepted\nsource=Developer ID\n", "",
        ):
            with self.subTest(raw=raw), self.assertRaisesRegex(gate.GateError, "Gatekeeper"):
                gate.check_assessment(raw)

    # Claim: select exactly the configured team/company Developer ID fingerprint,
    # refusing no valid identity, another team, and ambiguous duplicate identities.
    def test_identity_selection(self):
        line = '  1) ' + "A" * 40 + ' "' + gate.IDENTITY + '"\n'
        self.assertEqual(gate.signing_identity(line), "A" * 40)
        for raw in ("", line.replace("262RZ595FP", "WRONGTEAM1"), line * 2, line.replace("Developer ID Application", "Apple Development")):
            with self.subTest(raw=raw), self.assertRaises(gate.GateError):
                gate.signing_identity(raw)

    # Claim: the release's live-input controls kill named comparison bypasses;
    # a control that never detects the deliberate wrong value must fail itself.
    def test_negative_controls_detect_comparison_bypasses(self):
        with contextlib.redirect_stdout(io.StringIO()):
            gate.negative_controls(self.expected_req, self.expected_req, self.expected_ent, self.expected_ent)
        for name in ("compare_requirement", "compare_entitlements", "check_secrets"):
            with self.subTest(mutant=name), patch.object(gate, name, return_value=None):
                with self.assertRaisesRegex(gate.GateError, "negative control accepted"):
                    gate.negative_controls(self.expected_req, self.expected_req, self.expected_ent, self.expected_ent)

    # Claim: the actual release entry point, even invoked with xtrace, refuses
    # each missing secret before macOS/build/artifact work, and leaks no sibling
    # value. This is a Linux process check, not a mocked macOS signing success.
    def test_release_entrypoint_missing_secrets(self):
        for absent in gate.SECRET_NAMES:
            env = dict(os.environ)
            env.update({name: "sibling-value-never-print" for name in gate.SECRET_NAMES})
            del env[absent]
            result = subprocess.run(["bash", "-x", str(gate.ROOT / "scripts/release-macos.sh")], env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("missing required organization secrets: " + absent, result.stderr)
            self.assertNotIn("sibling-value-never-print", result.stdout + result.stderr)
            self.assertFalse((gate.ROOT / "dist").exists())


if __name__ == "__main__":
    unittest.main()
