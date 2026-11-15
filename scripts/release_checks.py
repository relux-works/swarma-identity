#!/usr/bin/env python3
"""Portable, fail-closed release checks. Uses only the Python standard library."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import sys

ROOT = Path(__file__).resolve().parents[1]
MACOS = ROOT / "release/macos"
SECRET_NAMES = (
    "MACOS_SIGN_P12", "MACOS_SIGN_P12_PASSWORD", "ASC_ISSUER_ID",
    "ASC_KEY_ID", "ASC_KEY_P8",
)
# Independent owner-supplied hashes: changing a manifest alone cannot repin inputs.
PINS = {
    "swarma-keychain_DevID.provisionprofile": "e88741d9873f302c8bce239b6688274a640345ce05941cc5176ce29ba8a8169f",
    "swarma-keychain.entitlements.plist": "70a5c31eb62f4c4664539d81c168a550ce17cc09401977f5a617be9827c3b650",
}
ENTITLEMENTS = {
    "com.apple.application-identifier": "262RZ595FP.works.relux.swarma-keychain",
    "com.apple.developer.team-identifier": "262RZ595FP",
    "keychain-access-groups": ["262RZ595FP.works.relux.swarma-keychain"],
}
IDENTITY = "Developer ID Application: Relux Works, LLC (262RZ595FP)"


class GateError(ValueError):
    pass


class UniqueDict(dict):
    def __setitem__(self, key, value):
        if key in self:
            raise GateError("duplicate plist key")
        super().__setitem__(key, value)


def canonical_entitlements(raw):
    try:
        value = plistlib.loads(raw, dict_type=UniqueDict)
        if not isinstance(value, dict):
            raise GateError("entitlements must be a dictionary")
        # Canonical serialization preserves types, including bool versus integer.
        return plistlib.dumps(value, fmt=plistlib.FMT_XML, sort_keys=True)
    except (ValueError, TypeError, OverflowError) as exc:
        raise GateError("invalid entitlements plist") from exc


def compare_entitlements(expected, actual):
    if canonical_entitlements(expected) != canonical_entitlements(actual):
        raise GateError("entitlements mismatch")


def requirement(raw):
    lines = [line.strip() for line in raw.splitlines() if line.strip()]
    # codesign's Executable= diagnostic is metadata, never part of the DR.
    lines = [line for line in lines if not line.startswith("Executable=")]
    if len(lines) != 1 or not lines[0].startswith("designated => "):
        raise GateError("expected exactly one designated requirement")
    return lines[0]


def compare_requirement(expected, actual):
    if requirement(expected) != requirement(actual):
        raise GateError("designated requirement mismatch")


def check_pins(directory):
    manifest = "".join(f"{digest}  {name}\n" for name, digest in PINS.items())
    if (directory / "SHA256SUMS").read_text() != manifest:
        raise GateError("input pin manifest mismatch")
    for name, digest in PINS.items():
        path = directory / name
        if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise GateError(f"input pin mismatch: {name}")
    compare_entitlements(
        plistlib.dumps(ENTITLEMENTS),
        (directory / "swarma-keychain.entitlements.plist").read_bytes(),
    )


def check_secrets(environment):
    missing = [name for name in SECRET_NAMES if not environment.get(name, "").strip()]
    if missing:
        raise GateError("missing required organization secrets: " + ", ".join(missing))


def mask(value):
    # GitHub workflow-command escaping also covers multiline PEM contents.
    for part in [value, *value.splitlines()]:
        if part:
            escaped = part.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
            print(f"::add-mask::{escaped}")


def prepare_secrets(directory):
    check_secrets(os.environ)
    for name in SECRET_NAMES:
        mask(os.environ[name])
    try:
        p12 = base64.b64decode("".join(os.environ["MACOS_SIGN_P12"].split()), validate=True)
    except ValueError as exc:
        raise GateError("MACOS_SIGN_P12 must be a base64-encoded PKCS#12 file") from exc
    if not p12:
        raise GateError("MACOS_SIGN_P12 decodes to an empty file")
    key = os.environ["ASC_KEY_P8"]
    if not key.startswith("-----BEGIN PRIVATE KEY-----") or "-----END PRIVATE KEY-----" not in key:
        raise GateError("ASC_KEY_P8 must contain a PEM private key")
    password = secrets.token_hex(32)
    mask(password)
    for name, data in {
        "certificate.p12": p12,
        "AuthKey.p8": key.encode(),
        "keychain-password": password.encode(),
    }.items():
        # Caller owns a fresh, mode-0700 directory; do not overwrite any file.
        with (directory / name).open("xb") as stream:
            os.chmod(stream.name, 0o600)
            stream.write(data)


def check_notary(raw):
    response = json.loads(raw)
    if not isinstance(response, dict) or response.get("status") != "Accepted":
        raise GateError("notarization status is not Accepted")


def check_assessment(raw):
    lines = raw.splitlines()
    if not any(line.endswith(": accepted") for line in lines) or "source=Notarized Developer ID" not in lines:
        raise GateError("Gatekeeper did not accept source=Notarized Developer ID")


def signing_identity(raw):
    matches = re.findall(r'^\s*\d+\) ([0-9A-Fa-f]{40}) "' + re.escape(IDENTITY) + r'"$', raw, re.M)
    if len(matches) != 1:
        raise GateError("temporary keychain must contain exactly one valid " + IDENTITY)
    return matches[0]


def negative_controls(expected_req, actual_req, expected_ent, actual_ent):
    # Positive controls bind these probes to the actual signed app, not a mock.
    compare_requirement(expected_req, actual_req)
    compare_entitlements(expected_ent, actual_ent)
    bad_req = requirement(actual_req).replace("works.relux.swarma-keychain", "works.relux.wrong-app")
    bad_ent = plistlib.loads(actual_ent)
    bad_ent["keychain-access-groups"] = ["262RZ595FP.works.relux.wrong-app"]
    for check, args, message in (
        (compare_requirement, (expected_req, bad_req), "designated requirement mismatch"),
        (compare_entitlements, (expected_ent, plistlib.dumps(bad_ent)), "entitlements mismatch"),
    ):
        try:
            check(*args)
        except GateError as exc:
            if str(exc) != message:
                raise GateError("negative control failed for an unrelated reason") from exc
        else:
            raise GateError("negative control accepted a deliberate mismatch")
    # Exercise the same missing-secret gate with valid synthetic siblings.
    for absent in SECRET_NAMES:
        env = {name: "control" for name in SECRET_NAMES if name != absent}
        try:
            check_secrets(env)
        except GateError as exc:
            if str(exc) != "missing required organization secrets: " + absent:
                raise GateError("missing-secret control failed for an unrelated reason") from exc
        else:
            raise GateError("missing-secret negative control accepted absent credentials")
    print("Requirement, entitlement and missing-secret negative controls passed.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("pins").add_argument("directory", nargs="?", type=Path, default=MACOS)
    sub.add_parser("secrets")
    sub.add_parser("prepare-secrets").add_argument("directory", type=Path)
    for name in ("requirement", "entitlements"):
        item = sub.add_parser(name)
        item.add_argument("expected", type=Path)
        item.add_argument("actual", type=Path)
    for name in ("notary", "assessment", "identity"):
        sub.add_parser(name).add_argument("file", type=Path)
    controls = sub.add_parser("controls")
    for name in ("expected_req", "actual_req", "expected_ent", "actual_ent"):
        controls.add_argument(name, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "pins":
            check_pins(args.directory)
        elif args.command == "secrets":
            check_secrets(os.environ)
        elif args.command == "prepare-secrets":
            prepare_secrets(args.directory)
        elif args.command == "requirement":
            compare_requirement(args.expected.read_text(), args.actual.read_text())
        elif args.command == "entitlements":
            compare_entitlements(args.expected.read_bytes(), args.actual.read_bytes())
        elif args.command == "notary":
            check_notary(args.file.read_text())
        elif args.command == "assessment":
            check_assessment(args.file.read_text())
        elif args.command == "identity":
            print(signing_identity(args.file.read_text()))
        elif args.command == "controls":
            negative_controls(args.expected_req.read_text(), args.actual_req.read_text(),
                              args.expected_ent.read_bytes(), args.actual_ent.read_bytes())
    except (GateError, OSError, ValueError, TypeError) as exc:
        # Exceptions from decoders can contain input; diagnostics never print it.
        message = str(exc) if isinstance(exc, GateError) else "invalid or missing release verification input"
        print(f"release gate: {message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
