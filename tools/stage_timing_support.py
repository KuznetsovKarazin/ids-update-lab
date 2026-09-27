"""Strict integer accounting gates for the MCU timing-schema-2 protocol."""

BUNDLE_STAGES = ("candidate_verify", "erase", "body_write", "readback", "readback_verify", "commit")


def integer(row, name):
    value = row.get(name)
    if type(value) is not int or value < 0:
        raise RuntimeError(f"timing field {name} must be a nonnegative integer")
    return value


def schema(row):
    if type(row.get("timing_schema")) is not int or row["timing_schema"] != 2:
        raise RuntimeError("instrumented timing_schema=2 firmware is required")


def validate_status_timing(row):
    schema(row)
    if row.get("crypto_context") != "shared_warm":
        raise RuntimeError("MCU must report the shared warm cryptographic context")
    integer(row, "crypto_key_setup_us")
    integer(row, "crypto_first_verify_us")


def validate_bundle_timing(row):
    schema(row)
    if row.get("timing_measured") is not True or type(row.get("timing_executed_mask")) is not int or row["timing_executed_mask"] != 63:
        raise RuntimeError("accepted bundle must have all six measured timing stages (mask 63)")
    timing = row.get("timing_us")
    if not isinstance(timing, dict) or set(timing) != set(BUNDLE_STAGES) | {"total"}:
        raise RuntimeError("bundle timing_us does not contain the exact schema-2 stage fields")
    for name in (*BUNDLE_STAGES, "total"):
        integer(timing, name)
    if sum(timing[name] for name in BUNDLE_STAGES) > timing["total"] or timing["total"] > integer(row, "latency_us"):
        raise RuntimeError("bundle stage sum must be <= total <= latency_us")
    return timing


def validate_fw_begin(row):
    schema(row)
    if row.get("crypto_context") != "shared_warm":
        raise RuntimeError("FW_BEGIN requires the shared warm cryptographic context")
    signature = integer(row, "signature_verify_us")
    prepare = integer(row, "partition_prepare_us")
    total = integer(row, "begin_us")
    if signature + prepare > total:
        raise RuntimeError("FW_BEGIN stage sum exceeds begin_us")
    return {"begin_us": total, "write_sum_us": 0, "hash_sum_us": 0, "chunk_sum_us": 0, "chunk_count": 0}


def validate_fw_chunk(row, previous):
    schema(row)
    write = integer(row, "write_us")
    hashing = integer(row, "hash_us")
    chunk = integer(row, "chunk_us")
    if write + hashing > chunk:
        raise RuntimeError("FW_CHUNK write/hash sum exceeds chunk_us")
    expected = {"begin_us": previous["begin_us"], "write_sum_us": previous["write_sum_us"] + write,
        "hash_sum_us": previous["hash_sum_us"] + hashing, "chunk_sum_us": previous["chunk_sum_us"] + chunk,
        "chunk_count": previous["chunk_count"] + 1}
    for name in ("write_sum_us", "hash_sum_us", "chunk_sum_us", "chunk_count"):
        if integer(row, name) != expected[name]:
            raise RuntimeError(f"FW_CHUNK cumulative {name} differs from acknowledged chunks")
    return expected


def validate_fw_ready(row, previous):
    schema(row)
    for name, value in previous.items():
        if integer(row, name) != value:
            raise RuntimeError(f"FW_READY {name} differs from accumulated transfer timing")
    finalize = integer(row, "finalize_us")
    active = integer(row, "device_active_us")
    if active != previous["begin_us"] + previous["chunk_sum_us"] + finalize:
        raise RuntimeError("FW_READY device_active_us does not equal begin + chunks + finalize")
    return {**previous, "finalize_us": finalize, "device_active_us": active}
