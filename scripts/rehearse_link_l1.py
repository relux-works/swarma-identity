#!/usr/bin/env python3
"""Exercise the supported L1 prefix; exit 3 at the documented contract STOP."""

import argparse
import hashlib
import hmac
import importlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import time


CHAIN_LAB_HEAD = "5d1d02b6f148d441bc9157524c7a7f8c8e215674"
DAEMON_SHA256 = "dc7430676e445af3992430e036f7c1a17bea44f757e9cf25b69205e39625f2f7"
HARNESS_SHA256 = {
    "lab.py": "84e6260d2f15a1c1f6906b6673d14e6655647b8f3f1db403cbc2bc2f44359fca",
    "protocol.py": "be9351e0bfc3ce0c529b97961071f2884244e07c49595d1055baac142973983f",
    "transaction.py": "1b8dc65aa536917207817b00d8ca73e73069add3a0556351e1ebe776ffdd2d9e",
    "funding.py": "f723c41492f56f51beb7ac3830230a34e33fd18d8bee9bd18cb1db28a951ac42",
    "money.py": "bdd13fc62992baac61f4f33e2a2068355568828a6e06ab2f8f34f708db0c1c14",
    "name_operation.py": "b8aafbd4979fc30e1d5bd1bfeb0a8318e6aa9bc2fcae347b294e63b3d613e4b9",
}
STOP = "STOP:grant-draft-human-landlord"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    path.chmod(0o600)


def run(args):
    root = Path(args.root)
    workbench = Path(__file__).resolve().parent.parent
    require(root.is_absolute(), "absolute scratch root required")
    require(root.resolve().is_relative_to(workbench / ".temp"), "task scratch required")
    require(not root.exists(), "fresh scratch root required")
    source = Path(args.chain_lab).resolve()
    head = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    require(head == CHAIN_LAB_HEAD, "chain-lab revision mismatch")
    harness_dir = source / "experiments" / "fullnode-trusts"
    for name, digest in HARNESS_SHA256.items():
        require(hashlib.sha256((harness_dir / name).read_bytes()).hexdigest() == digest,
                "harness source mismatch")
    daemon = Path(args.core_bin).resolve() / "namecoind"
    require(hashlib.sha256(daemon.read_bytes()).hexdigest() == DAEMON_SHA256,
            "Core 28.0 release pin mismatch")
    identity = str(Path(args.identity).resolve(strict=True))
    sys.path.insert(0, str(harness_dir))
    sys.dont_write_bytecode = True
    lab = importlib.import_module("lab")
    root.mkdir(mode=0o700)
    private = root / "private"
    private.mkdir(mode=0o700)
    public = root / "public"
    public.mkdir(mode=0o700)
    node_dir = private / "node"
    node_dir.mkdir(mode=0o700)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    lab.LAB, lab.NODE, lab.PUBLIC, lab.PORT = root, node_dir, public, port
    lab.DEADLINE = time.time() + 180

    def scratch_bounds():
        require(time.time() < lab.DEADLINE, "rehearsal deadline reached")
        used = sum(path.stat().st_size for path in root.rglob("*") if path.is_file())
        require(used <= 1200 * 1024 * 1024, "task scratch size limit reached")
        return used

    lab.bounds = scratch_bounds
    password, salt = secrets.token_hex(32), secrets.token_hex(16)
    authhash = hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()
    methods = "getnetworkinfo,getblockchaininfo,getblockhash,getbestblockhash,name_show,gettxout"
    configuration = (
        "regtest=1\nserver=1\nlisten=0\ndnsseed=0\ndiscover=0\nnetworkactive=0\n"
        "txindex=1\npersistmempool=0\nprinttoconsole=0\n"
        "fallbackfee=0.002\ndeprecatedrpc=create_bdb\nrpcwhitelistdefault=0\n"
        f"rpcauth=l1-reader:{salt}${authhash}\nrpcwhitelist=l1-reader:{methods}\n"
        f"[regtest]\nconnect=0\nrpcbind=127.0.0.1\nrpcallowip=127.0.0.1\nrpcport={port}\n"
    )
    config_path = node_dir / "namecoin.conf"
    config_path.write_text(configuration, encoding="ascii")
    config_path.chmod(0o600)
    auth_path = private / "read.auth"
    auth_path.write_text("l1-reader:" + password, encoding="ascii")
    auth_path.chmod(0o600)
    read_config = private / "read.json"
    write_json(read_config, {
        "schema": "swarma-identity/config/1", "network": "regtest",
        "node": {"id": "l1-regtest", "rpc_url": f"http://127.0.0.1:{port}",
                 "auth_file": str(auth_path), "genesis_hash": lab.GENESIS["regtest"],
                 "rpc_profile": "namecoin-core-read/1"},
    })
    report = {
        "schema": "swarma-identity/link-l1-prefix/1", "status": "FAILED",
        "network": "regtest", "chain_lab_head": head, "core_sha256": DAEMON_SHA256,
        "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "identity_sha256": hashlib.sha256(Path(identity).read_bytes()).hexdigest(),
        "commands": [], "directions": {},
        "not_run": ["consent", "grant-sign-both-stages", "grant-anchor", "grantcheck-live",
                    "revocation-SEAL_SPENT", "wrong-grantee-key", "unconfirmed-issuance",
                    "tampered-contract-digest", "second-verifier-node", "native-signer", "mainnet"],
    }
    stage = "start-core"
    process = None

    def invoke(label, command, request, refusal=None, ledger=None):
        request_path = private / (label + ".json")
        write_json(request_path, request)
        argv = [identity, "grant", command, "--config", str(read_config),
                "--request", str(request_path), "--json"]
        if ledger is not None:
            argv += ["--seal-ledger", str(ledger)]
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False)
        envelope = json.loads(result.stdout)
        require(not result.stderr, "unexpected CLI diagnostic")
        record = {"command": "grant " + command, "label": label, "exit_code": result.returncode}
        if refusal is None:
            require(result.returncode == 0 and envelope["ok"], "positive command failed")
        else:
            require(result.returncode == 3 and not envelope["ok"], "missing named refusal")
            require(envelope["error"]["code"] == refusal, "wrong named refusal")
            require("result" not in envelope or envelope["result"] is None,
                    "refusal leaked partial result")
            record["refusal"] = refusal
        report["commands"].append(record)
        write_json(public / (label + ".json"), envelope)
        return envelope.get("result")

    try:
        with (private / "core.log").open("wb") as logfile:
            process = subprocess.Popen([str(daemon), "-datadir=" + str(node_dir)],
                                       stdout=logfile, stderr=logfile)
        report["core_pid"] = process.pid
        until = time.time() + 25
        while True:
            require(process.poll() is None, "Core exited during readiness")
            try:
                lab.check_network()
                break
            except (OSError, ValueError, lab.RPCError):
                require(time.time() < until, "Core readiness timeout")
                time.sleep(0.1)
        require(lab.rpc("getnetworkinfo")["version"] == 280000, "wrong Core version")
        stage = "setup-test-names-and-funding"
        for role in ("miner", "A", "B"):
            lab.rpc("createwallet", role, False, False, "", False, False)
        lab.STATE["miner"] = lab.rpc("getnewaddress", "", "bech32", wallet="miner")
        lab.mine(120)
        suffix = secrets.token_hex(6)
        parties = {}
        reservations = {}
        for role in ("A", "B"):
            grant_address = lab.rpc("getnewaddress", "", "bech32", wallet=role)
            grant_pub = lab.rpc("getaddressinfo", grant_address, wallet=role)["pubkey"][2:]
            funding_address = lab.rpc("getnewaddress", "", "bech32", wallet=role)
            funding_txid = lab.rpc("sendtoaddress", funding_address, 1, wallet="miner")
            name = "id/l1-" + role.lower() + "-" + suffix
            parties[role] = {"name": name, "key": grant_pub, "funding": funding_address,
                             "funding_txid": funding_txid}
        lab.mine(1)
        for role, party in parties.items():
            reservations[role] = lab.rpc("name_new", party["name"], wallet=role)
        lab.mine(12)
        for role, party in parties.items():
            reservation = reservations[role]
            value = json.dumps({"swarma": {"landlord": {"grant": party["key"]}}},
                               separators=(",", ":"))
            lab.rpc("name_firstupdate", party["name"], reservation[1], reservation[0],
                    value, wallet=role)
        lab.mine(1)
        for party in parties.values():
            party["funding_txid"] = lab.rpc("sendtoaddress", party["funding"], 1, wallet="miner")
        lab.mine(1)
        for role, party in parties.items():
            stage = role + "-seal"
            funding_txid = party["funding_txid"]
            parent = lab.txdata(funding_txid)
            output = next(item for item in parent["vout"]
                          if item["scriptPubKey"].get("address") == party["funding"])
            funding = {"script_hex": output["scriptPubKey"]["hex"], "fee_rate_sat_vbyte": 200,
                       "inputs": [{"txid": funding_txid, "vout": output["n"],
                                   "prev_tx_hex": lab.rpc("getrawtransaction", funding_txid)}]}
            require(funding["script_hex"].startswith("0014"), "P2WPKH funding required")
            funding_coin = lab.rpc("gettxout", funding_txid, output["n"], True)
            require(funding_coin is not None and funding_coin["confirmations"] >= 1,
                    "confirmed funding required")
            request = {"schema": "swarma-trust/seal/1", "network": "regtest",
                       "landlord_name": party["name"], "issuer_key": party["key"],
                       "amount_sat": 100000, "funding": funding}
            pool_before = lab.rpc("getrawmempool")
            invoke(role + "-wrong-network", "seal", dict(request, network="main"),
                   refusal="NETWORK_PIN")
            require(lab.rpc("getrawmempool") == pool_before, "refusal changed mempool")
            plan = invoke(role + "-seal", "seal", request)
            require(plan["dry_run"] is True, "unsigned plan required")
            signed = lab.rpc("signrawtransactionwithwallet",
                             plan["transaction"]["unsigned_tx_hex"], wallet=role)
            require(signed["complete"] is True, "external wallet signature incomplete")
            txid, _, _ = lab.broadcast_checked(signed["hex"], role + "_seal_funding")
            require(txid == plan["seal"]["txid"], "seal txid changed")
            lab.mine(1)
            coin = lab.rpc("gettxout", txid, 0, True)
            require(coin is not None and coin["confirmations"] >= 1, "seal not confirmed")
            require(coin["scriptPubKey"]["hex"] == plan["transaction"]["outputs"][0]["script_hex"],
                    "confirmed seal script mismatch")
            party["seal"] = plan["seal"]
            report["directions"][role] = {"landlord_name": party["name"],
                "issuer_key": party["key"], "seal": party["seal"],
                "confirmations": coin["confirmations"], "funding_type": "P2WPKH"}
        stage = "grant-draft-human-landlord"
        for role, other in (("A", "B"), ("B", "A")):
            now = int(time.time())
            request = {"schema": "swarma-trust/draft/1", "network": "regtest",
                       "landlord_name": parties[role]["name"], "agent_name": parties[other]["name"],
                       "grantee_key": parties[other]["key"], "grantee_name": parties[other]["name"],
                       "actions": ["instruct", "review"], "repos": [], "spend_budget": 0,
                       "not_before": now, "not_after": now + 3600, "note": "L1 role-boundary probe",
                       "seal": parties[role]["seal"], "consent_created_at": now}
            ledger = private / (role + "-seal-ledger.json")
            pool_before = lab.rpc("getrawmempool")
            invoke(role + "-draft-role-probe", "draft", request,
                   refusal="AGENT_NOT_V3", ledger=ledger)
            require(not ledger.exists(), "refused draft wrote ledger")
            require(lab.rpc("getrawmempool") == pool_before, "refused draft changed mempool")
            report["directions"][role]["draft_refusal"] = "AGENT_NOT_V3"
        report["status"] = STOP
    except Exception as error:
        report["failed_stage"] = stage
        report["failure_type"] = type(error).__name__
        if type(error) is RuntimeError:
            report["failure_reason"] = str(error)
        if "last_policy_refusal" in lab.R:
            report["core_policy_refusal"] = lab.R["last_policy_refusal"]
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            report["core_reaped"] = process.poll() is not None
            report["core_exit_code"] = process.returncode
        write_json(public / "result.json", report)
    print(json.dumps(report, sort_keys=True))
    return 3 if report["status"] == STOP and report.get("core_reaped") else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--network", required=True)
    parser.add_argument("--core-bin", required=True)
    parser.add_argument("--chain-lab", required=True)
    parser.add_argument("--identity", required=True)
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    if args.network != "regtest":
        print(json.dumps({"status": "NETWORK_REFUSED", "rpc_calls": 0, "wallets_created": 0}))
        return 2
    os.umask(0o077)

    def terminate(*_):
        raise RuntimeError("terminated")

    signal.signal(signal.SIGTERM, terminate)
    try:
        return run(args)
    except Exception as error:
        print(json.dumps({"status": "FAILED", "failed_stage": "preflight",
                          "failure_type": type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
