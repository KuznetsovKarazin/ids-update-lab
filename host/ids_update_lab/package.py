"""Wire v1 implementation. See docs/WIRE_FORMAT.md for the normative contract."""
from dataclasses import dataclass
import hashlib
import json
import math
from pathlib import Path
import struct

import numpy as np
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ENVELOPE_MAGIC = b"SIDSPK1\0"
PAYLOAD_MAGIC = b"SIDSB01\0"
HEADER = struct.Struct("<8sIIII32s16sff")
MAX_FEATURES = 16
MAX_ENVELOPE = 544
ABI = 1


class PackageError(ValueError):
    pass


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def contract_hash(contract):
    keys = {"feature_names", "input_units", "missing_policy", "target", "contract_version"}
    if set(contract) != keys:
        raise PackageError("feature contract keys must match wire v1 exactly")
    names, units = contract["feature_names"], contract["input_units"]
    if not isinstance(names, list) or not 1 <= len(names) <= MAX_FEATURES:
        raise PackageError("feature_names must contain 1..16 names")
    if any(not isinstance(v, str) or not v or not v.isascii() for v in names):
        raise PackageError("feature names must be nonempty ASCII strings")
    if len(set(names)) != len(names):
        raise PackageError("feature names must be unique and ordered")
    if not isinstance(units, list) or len(units) != len(names) or any(not isinstance(u, str) or not u for u in units):
        raise PackageError("input_units must contain one explicit unit per feature")
    if contract["missing_policy"] != "reject_nonfinite" or contract["target"] != "attack_vs_normal" or type(contract["contract_version"]) is not int or contract["contract_version"] != 1:
        raise PackageError("unsupported feature contract semantics")
    return hashlib.sha256(canonical_json(contract)).digest()


def new_contract(names, units):
    result = dict(feature_names=list(names), input_units=list(units), missing_policy="reject_nonfinite", target="attack_vs_normal", contract_version=1)
    contract_hash(result)
    return result


@dataclass(frozen=True)
class Model:
    version: int
    release: str
    schema: bytes
    means: tuple
    scales: tuple
    weights: tuple
    bias: float
    threshold: float = 0.5
    runtime_abi: int = ABI

    def payload(self):
        n = len(self.means)
        if not 1 <= n <= MAX_FEATURES or len(self.scales) != n or len(self.weights) != n:
            raise PackageError("inconsistent feature dimensions")
        if type(self.version) is not int or not 0 < self.version <= 0xffffffff:
            raise PackageError("version must be positive uint32")
        if self.runtime_abi != ABI or len(self.schema) != 32:
            raise PackageError("invalid ABI or schema length")
        try:
            release = self.release.encode("ascii")
        except UnicodeEncodeError as exc:
            raise PackageError("release must be ASCII") from exc
        if not 1 <= len(release) <= 16 or any(c < 33 or c > 126 for c in release):
            raise PackageError("release must be 1..16 printable non-space ASCII bytes")
        floats = (self.threshold, self.bias, *self.means, *self.scales, *self.weights)
        if any(not math.isfinite(v) for v in floats) or not 0 < self.threshold < 1 or any(v <= 0 for v in self.scales):
            raise PackageError("invalid/nonfinite model parameter")
        try:
            result = HEADER.pack(PAYLOAD_MAGIC, 1, ABI, self.version, n, self.schema, release.ljust(16, b"\0"), self.threshold, self.bias)
            result += struct.pack("<" + "f" * (3 * n), *self.means, *self.scales, *self.weights)
        except (OverflowError, struct.error) as exc:
            raise PackageError("parameter cannot be represented in float32") from exc
        # Recheck representability: positive tiny scales/thresholds can round to zero.
        parse_payload(result)
        return result


def parse_payload(payload):
    if len(payload) < HEADER.size:
        raise PackageError("truncated payload")
    magic, fmt, abi, version, n, schema, release, threshold, bias = HEADER.unpack_from(payload)
    if magic != PAYLOAD_MAGIC or fmt != 1 or abi != ABI:
        raise PackageError("unsupported magic, format, or runtime ABI")
    if not 1 <= n <= MAX_FEATURES or len(payload) != 80 + 12 * n or version == 0:
        raise PackageError("invalid payload length, dimension, or version")
    identifier, sep, tail = release.partition(b"\0")
    if not identifier or any(c < 33 or c > 126 for c in identifier) or any(tail):
        raise PackageError("invalid release encoding")
    values = struct.unpack_from("<" + "f" * (3 * n), payload, HEADER.size)
    means, scales, weights = values[:n], values[n:2 * n], values[2 * n:]
    if any(not math.isfinite(v) for v in (threshold, bias, *values)) or not 0 < threshold < 1 or any(v <= 0 for v in scales):
        raise PackageError("invalid/nonfinite float32 parameter")
    return Model(version, identifier.decode("ascii"), schema, means, scales, weights, bias, threshold, abi)


def load_private(path):
    key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey) or key.key_size != 2048:
        raise PackageError("wire v1 requires RSA-2048 private key")
    return key


def load_public(path):
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, rsa.RSAPublicKey) or key.key_size != 2048:
        raise PackageError("wire v1 requires RSA-2048 public key")
    return key


def generate_keys(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = directory / "private.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    private.chmod(0o600)
    (directory / "public.pem").write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return key


def sign(model, private_key):
    if not isinstance(private_key, rsa.RSAPrivateKey) or private_key.key_size != 2048:
        raise PackageError("RSA-2048 private key required")
    payload = model.payload()
    signature = private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
    return struct.pack("<8sII", ENVELOPE_MAGIC, len(payload), len(signature)) + payload + signature


def verify(envelope, public_key, expected_schema=None, expected_count=None):
    if not isinstance(public_key, rsa.RSAPublicKey) or public_key.key_size != 2048:
        raise PackageError("RSA-2048 public key required")
    if not 16 <= len(envelope) <= MAX_ENVELOPE:
        raise PackageError("invalid envelope length")
    magic, length, signature_length = struct.unpack_from("<8sII", envelope)
    if magic != ENVELOPE_MAGIC or signature_length != 256 or len(envelope) != 16 + length + signature_length:
        raise PackageError("invalid envelope header/length")
    payload, signature = envelope[16:16 + length], envelope[16 + length:]
    try:
        public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature as exc:
        raise PackageError("signature verification failed") from exc
    model = parse_payload(payload)
    if expected_schema is not None and model.schema != expected_schema:
        raise PackageError("feature schema mismatch")
    if expected_count is not None and len(model.means) != expected_count:
        raise PackageError("feature count mismatch")
    return model


def infer(model, raw, preprocessing=None):
    """Sequential float32 golden path; overflow is a rejected inference."""
    prep = preprocessing or model
    if len(raw) != len(model.means) or len(prep.means) != len(raw):
        raise PackageError("input feature count mismatch")
    with np.errstate(over="ignore", invalid="ignore", divide="ignore", under="ignore"):
        x = np.asarray(raw, dtype=np.float32)
        if not np.isfinite(x).all():
            raise PackageError("nonfinite raw input")
        z = np.float32(model.bias)
        for i in range(len(raw)):
            normalized = np.float32(np.float32(x[i] - np.float32(prep.means[i])) / np.float32(prep.scales[i]))
            z = np.float32(z + np.float32(np.float32(model.weights[i]) * normalized))
        if not np.isfinite(z):
            raise PackageError("nonfinite accumulated score")
        if z >= 0:
            p = np.float32(np.float32(1) / np.float32(np.float32(1) + np.exp(np.float32(-z))))
        else:
            e = np.float32(np.exp(z))
            p = np.float32(e / np.float32(np.float32(1) + e))
    return float(p), int(p > np.float32(prep.threshold))


def infer_many(model, raw, preprocessing=None):
    """Vectorized records, with exactly the same per-feature float32 order."""
    prep = preprocessing or model
    with np.errstate(over="ignore", invalid="ignore", divide="ignore", under="ignore"):
        x = np.asarray(raw, dtype=np.float32)
        if x.ndim != 2 or x.shape[1] != len(model.means) or not np.isfinite(x).all():
            raise PackageError("invalid/nonfinite raw matrix")
        z = np.full(len(x), model.bias, dtype=np.float32)
        for i in range(x.shape[1]):
            normalized = (x[:, i] - np.float32(prep.means[i])) / np.float32(prep.scales[i])
            z = z + np.float32(model.weights[i]) * normalized
        if not np.isfinite(z).all():
            raise PackageError("nonfinite accumulated score")
        p = np.empty_like(z)
        positive = z >= 0
        p[positive] = np.float32(1) / (np.float32(1) + np.exp(-z[positive]))
        e = np.exp(z[~positive])
        p[~positive] = e / (np.float32(1) + e)
    return p, (p > np.float32(prep.threshold)).astype(np.int64)


class UpdateState:
    """Host-only semantic oracle, not a flash/power-loss emulator."""
    def __init__(self, factory_envelope, public_key, schema, count, model_only=False):
        self.public_key, self.schema, self.count = public_key, schema, count
        self.factory = verify(factory_envelope, public_key, schema, count)
        self.active = self.factory
        self.model_only = model_only

    def update(self, envelope):
        candidate = verify(envelope, self.public_key, self.schema, self.count)
        if candidate.version <= self.active.version:
            raise PackageError("non-monotonic version/replay")
        self.active = candidate
        return candidate

    def infer(self, raw):
        return infer(self.active, raw, self.factory if self.model_only else None)
