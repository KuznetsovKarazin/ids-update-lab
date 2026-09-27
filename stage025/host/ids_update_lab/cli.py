import argparse
import json
import sys
from pathlib import Path

from .artifacts import export_header, generate_demo
from .package import PackageError, contract_hash, generate_keys, load_private, load_public, verify


def main(argv=None):
    parser = argparse.ArgumentParser(description="IDS Update Lab: explicit, reproducible host workflows")
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("keygen", help="create a new local experiment RSA-2048 keypair; never overwrite")
    p.add_argument("--output", required=True)
    p = commands.add_parser("demo", help="generate SYNTHETIC plumbing fixtures, not scientific results")
    p.add_argument("--output", required=True)
    p.add_argument("--private-key", required=True)
    p = commands.add_parser("verify")
    p.add_argument("--package", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--contract", required=True)
    p = commands.add_parser("export-header")
    p.add_argument("--package", required=True)
    p.add_argument("--public-key", required=True)
    p.add_argument("--contract", required=True)
    p.add_argument("--output", default="firmware/main/generated/model_contract.h")
    p.add_argument("--metadata-dir", default="firmware/generated")
    p.add_argument("--data-origin", required=True, choices=["synthetic_plumbing", "TON_IoT"])
    p = commands.add_parser("train-ton", help="use local TON_IoT CSV only; explicit numeric allowlist")
    p.add_argument("--csv", required=True)
    p.add_argument("--features", required=True, help="comma-separated ordered numeric feature names (max 16)")
    p.add_argument("--units", required=True, help="comma-separated matching documented raw units")
    p.add_argument("--output", required=True)
    p.add_argument("--private-key", required=True)
    p.add_argument("--seed", type=int, default=20260923)
    p.add_argument("--max-golden", type=int, default=512)
    p.add_argument("--data-origin", choices=["TON_IoT", "synthetic_plumbing"], default="TON_IoT", help="use synthetic_plumbing ONLY for explicitly synthetic pipeline checks")
    p = commands.add_parser("run", help="run fixed A/B/fault protocol against serial MCU or native simulator")
    transport = p.add_mutually_exclusive_group(required=True)
    transport.add_argument("--port", help="physical ESP32-S3 serial port, e.g. COM10 or /dev/ttyACM0")
    transport.add_argument("--native", help="path to native simulator executable")
    p.add_argument("--native-store", help="fresh directory used by native simulator")
    p.add_argument("--model-only", action="store_true", help="native only: immutable factory preprocessing baseline")
    p.add_argument("--experiment", required=True, help="directory with releases, feature_contract and golden.jsonl")
    p.add_argument("--output", required=True, help="new immutable run directory")
    p.add_argument("--limit", type=int, help="optional first-N correctness smoke only; default uses complete frozen golden sample")
    p.add_argument("--board-id", help="physical board identifier recorded verbatim for repeated-measure analysis")
    p.add_argument("--firmware-bin", help="optional exact flashed application binary to hash into run provenance")
    p.add_argument("--repetitions", type=int, default=1, help="inference repetitions only; each new run performs exactly ONE update/fault trial")
    p.add_argument("--timeout", type=float, default=10.0)
    p.add_argument("--checkpoint", choices=["none", "after_erase", "after_write", "after_verify", "after_commit"], default="none")
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            generate_keys(args.output)
            print(json.dumps({"created": args.output, "warning": "private.pem is local signing material; do not commit or distribute"}))
        elif args.command == "demo":
            generate_demo(args.output, load_private(args.private_key))
            print(json.dumps({"created": args.output, "data_origin": "synthetic_plumbing"}))
        elif args.command == "export-header":
            print(export_header(args.package, args.public_key, args.contract, args.output, args.metadata_dir, args.data_origin))
        elif args.command == "verify":
            contract = json.loads(Path(args.contract).read_text())
            m = verify(Path(args.package).read_bytes(), load_public(args.public_key), contract_hash(contract), len(contract["feature_names"]))
            print(json.dumps({"valid": True, "version": m.version, "release": m.release, "schema": m.schema.hex()}))
        elif args.command == "train-ton":
            from .training import train_ton
            train_ton(args)
        elif args.command == "run":
            from .serial_runner import run
            run(args)
    except (PackageError, ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
