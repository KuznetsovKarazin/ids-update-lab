"""Local immutable experiment preparation; never uploads or downloads datasets."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives import serialization

from .package import Model, PackageError, contract_hash, contract_runtime_abi, infer, load_public, new_contract, sign, verify


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n", encoding="utf-8")


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def equivalent_release(model, version=2, release="release-B"):
    """Float32 approximation of the SAME affine decision function in new coordinates.

    This is a controlled deployment fixture, not an improved trained classifier.
    means_B=means_A+0.5*scales_A, scales_B=2*scales_A,
    weights_B=2*weights_A, bias_B=bias_A+0.5*sum(weights_A).
    Serialization/roundoff equivalence is measured on frozen records, not assumed.
    """
    means = tuple(float(np.float32(m + 0.5 * s)) for m, s in zip(model.means, model.scales))
    scales = tuple(float(np.float32(2 * s)) for s in model.scales)
    weights = tuple(float(np.float32(2 * w)) for w in model.weights)
    bias = float(np.float32(model.bias + 0.5 * sum(model.weights)))
    result = replace(model, version=version, release=release, means=means, scales=scales, weights=weights, bias=bias)
    result.payload()
    return result


def write_releases(output, model_a, model_b, contract, key, origin):
    output = Path(output)
    schema, runtime_abi = contract_hash(contract), contract_runtime_abi(contract)
    for model in (model_a, model_b):
        if model.schema != schema or model.runtime_abi != runtime_abi or len(model.means) != len(contract["feature_names"]):
            raise PackageError("release model does not match its feature contract")
    write_json(output / "feature_contract.json", contract)
    (output / "release-A.sids").write_bytes(sign(model_a, key))
    (output / "release-B.sids").write_bytes(sign(model_b, key))
    (output / "public.pem").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    write_json(output / "provenance.json", {"data_origin": origin, "hardware_measured": False,
        "package_sha256": {name: sha256_file(output / name) for name in ["release-A.sids", "release-B.sids"]},
        "schema_sha256": contract_hash(contract).hex(),
        "release_B_purpose": "controlled equivalent classifier under changed normalization; not retraining or drift adaptation",
        "model_only_policy": "authenticated candidate weights/bias with immutable factory means/scales/threshold"})


def generate_demo(output, key):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=False)
    contract = new_contract(["fixture_x", "fixture_y"], ["synthetic_unit", "synthetic_unit"])
    a = Model(1, "synthetic-A", contract_hash(contract), (0., 0.), (1., 1.), (1., -0.25), -0.1)
    b = equivalent_release(a, release="synthetic-B")
    # Include near-boundary points to expose stale preprocessing consistently.
    points = [[float(x), float(y)] for x in np.linspace(-1, 1, 21) for y in (-1, 0, 1)]
    records = []
    for i, raw in enumerate(points):
        pa, ya = infer(a, raw)
        pb, yb = infer(b, raw)
        pm, ym = infer(b, raw, a)
        records.append({"record_id": i, "data_origin": "synthetic_plumbing", "raw": raw,
            "expected_A": {"probability": pa, "label": ya}, "expected_B": {"probability": pb, "label": yb},
            "expected_B_model_only": {"probability": pm, "label": ym}})
    write_releases(output, a, b, contract, key, "synthetic_plumbing")
    with (output / "golden.jsonl").open("w") as stream:
        for row in records:
            stream.write(json.dumps(row, allow_nan=False) + "\n")
    write_json(output / "fixture_summary.json", {"data_origin": "synthetic_plumbing", "records": len(records),
        "A_B_label_disagreements": sum(r["expected_A"]["label"] != r["expected_B"]["label"] for r in records),
        "stale_preprocessing_label_disagreements": sum(r["expected_B"]["label"] != r["expected_B_model_only"]["label"] for r in records),
        "max_probability_delta_A_B": max(abs(r["expected_A"]["probability"] - r["expected_B"]["probability"]) for r in records),
        "warning": "plumbing checks only; not TON_IoT or actual MCU measurements"})
    return output


def export_header(package, public_key, contract_file, output, metadata_dir, data_origin):
    contract = json.loads(Path(contract_file).read_text())
    schema = contract_hash(contract)
    envelope = Path(package).read_bytes()
    public = load_public(public_key)
    model = verify(envelope, public, schema, len(contract["feature_names"]), contract_runtime_abi(contract))
    provenance_path = Path(package).parent / "provenance.json"
    if not provenance_path.exists():
        raise PackageError("export requires experiment provenance.json beside the signed package")
    provenance = json.loads(provenance_path.read_text())
    if provenance.get("data_origin") != data_origin or provenance.get("schema_sha256") != schema.hex():
        raise PackageError("claimed data origin or schema differs from experiment provenance")
    if provenance.get("package_sha256", {}).get(Path(package).name) != hashlib.sha256(envelope).hexdigest():
        raise PackageError("package hash not bound in experiment provenance")
    if data_origin == "TON_IoT":
        training = json.loads((Path(package).parent / "training_manifest.json").read_text())
        if training.get("data_origin") != "TON_IoT" or not training.get("source_sha256") or not training.get("equivalence_gate_passed"):
            raise PackageError("TON_IoT export requires a verified training manifest and passing equivalence gate")
    pem = public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    def array(data):
        return ",\n    ".join(", ".join(f"0x{v:02x}" for v in data[i:i + 16]) for i in range(0, len(data), 16))
    header = "// GENERATED. Public test material only; never place a private key here.\n#pragma once\nnamespace ids_generated {\n"
    header += f"inline constexpr unsigned kFeatureCount = {len(model.means)};\n"
    header += f"inline constexpr unsigned kRuntimeAbi = {model.runtime_abi};\n"
    header += f"inline constexpr unsigned kFactoryVersion = {model.version};\n"
    header += f"inline constexpr unsigned char kFeatureContractHash[32] = {{\n    {array(schema)}\n}};\n"
    header += f"inline constexpr unsigned char kFactoryEnvelope[] = {{\n    {array(envelope)}\n}};\n"
    header += f"inline constexpr unsigned char kPublicKeyPem[] = {{\n    {array(pem + bytes([0]))}\n}};\n"
    header += f"inline constexpr char kDataOrigin[] = {json.dumps(data_origin)};\n}}\n"
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(header)
    metadata_dir = Path(metadata_dir)
    metadata_dir.mkdir(parents=True, exist_ok=True)
    write_json(metadata_dir / "factory_metadata.json", {"data_origin": data_origin, "schema_sha256": schema.hex(),
        "version": model.version, "runtime_abi": model.runtime_abi, "release": model.release, "n_features": len(model.means),
        "factory_envelope_sha256": hashlib.sha256(envelope).hexdigest(),
        "public_key_sha256": hashlib.sha256(pem).hexdigest(), "hardware_measured": False})
    write_json(metadata_dir / "feature_contract.json", contract)
    return output
