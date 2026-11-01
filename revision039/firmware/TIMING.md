# Timing schema 2

This instrumentation is additive to existing command/reply fields. It changes
measurement and reporting, not signed formats, inference, the storage algorithm,
or software checkpoint positions. It has not itself been tested on a physical
board. Host/native values are not MCU measurements.

All durations are nonnegative integer microseconds from a monotonic clock.
ESP32 uses `esp_timer_get_time`; the shared core receives a `Clock` from its
caller. There is no implicit system clock and uninstrumented callers still work.
Zero is a valid duration at this resolution, not evidence a stage was skipped.
Timer overhead is included; it has not been calibrated/subtracted.

## Boot and STATUS

Both replies add:

- `timing_schema: 2`.
- `crypto_context: "shared_warm"` for the initialized MCU context after its first
  verification, or `"unavailable"` if these MCU setup metrics are unavailable.
- `crypto_key_setup_us`: initialization, PEM parsing, key checks and padding setup.
- `crypto_first_verify_us`: first hash/signature verification during boot. This
  includes cold RSA/Montgomery setup. It is separate from key parsing above.

The native adapter reports `null` for these two setup metrics. Full-firmware
metadata now calls the **same retained `ids::Crypto` instance** that validates the
factory bundle at boot. Full-firmware `signature_verify_us` therefore contains
metadata hashing plus warm RSA verification, without reparsing a fresh PEM key.
The schema change must accompany comparisons with old pilot data.

## UPDATE

Existing `latency_us` now captures the clock immediately after `Engine::update`
returns and before JSON construction. It excludes command reception and hex
decoding, response construction/transmission, and later reboot activity.

Additional fields are `timing_schema: 2`, `timing_measured: true`,
`timing_executed_mask`, and a `timing_us` object:

| Bit | `timing_us` key | Interval |
|---|---|---|
| 0 | `candidate_verify` | Complete candidate validation, including parsing, signature, parameters and payload digest |
| 1 | `erase` | Inactive-slot erase API call |
| 2 | `body_write` | Length and envelope write API call |
| 3 | `readback` | Readback API call and exact byte comparison |
| 4 | `readback_verify` | Complete validation of the read-back envelope, including signature |
| 5 | `commit` | Commit write, read and byte comparison |
| — | `total` | Inside Engine update, including control flow and instrumentation overhead |

The stage intervals are disjoint. Successful updates have mask 63. A signature
or replay rejection has mask 1; later stages remain zero. An attempted stage
sets its mask bit even if it fails. Schema/encoding errors rejected before
calling the Engine retain ordinary error replies without an update timing record.

For a reply that returns normally:

```
sum(six stage durations) <= timing_us.total <= latency_us
```

Physical/software restart inside a checkpoint prevents the normal update reply;
there is no completed aggregate duration for that interrupted command. These
checkpoints still occur **after** completed erase/write/verify/commit operations,
not during a flash operation. No physical power-loss guarantee is added.

## Full firmware

Successful `fw_begin` retains `signature_verify_us` and `partition_prepare_us`
and adds `timing_schema: 2`, `crypto_context: "shared_warm"`, and `begin_us`.
`begin_us` starts after metadata/signature hex decoding and includes verification,
policy checks, OTA preparation, SHA initialization and transfer-state setup.

Each successful `fw_chunk` retains `offset` and adds:

- `timing_schema: 2`, `write_us`, `hash_us`, `chunk_us`;
- `write_sum_us`, `hash_sum_us`, `chunk_sum_us`, `chunk_count`.

`write_us` brackets `esp_ota_write`; `hash_us` brackets streaming SHA update.
`chunk_us` starts after chunk syntax/offset/hex validation and includes these
operations and transfer counter updates. Cumulative sums cover successfully
acknowledged chunks since this accepted FW_BEGIN. They reset for every new
transfer. A failed chunk has no complete per-chunk timing record and its partial
work is not represented by these successful-chunk sums.

`fw_ready` retains `finalize_us` and adds schema, `begin_us`, the four cumulative
fields above, and `device_active_us`. Finalization includes hash completion,
stored-image validation by IDF, descriptor checking and boot-partition selection.
It stops before JSON output. Complete-image rejection and other FW_END errors
also expose these aggregate fields; their finalization includes abort cleanup
when needed. Other errors have schema 2 but no aggregate timing guarantee.

The runner can assert:

```
signature_verify_us + partition_prepare_us <= begin_us
write_us + hash_us <= chunk_us
write_sum_us == sum(per-chunk write_us)
hash_sum_us == sum(per-chunk hash_us)
chunk_sum_us == sum(per-chunk chunk_us)
chunk_count == number of successful chunk acknowledgments
device_active_us == begin_us + chunk_sum_us + finalize_us
```

Do not add `write_sum_us` or `hash_sum_us` to `chunk_sum_us`: they are nested.
`device_active_us` is the sum of these instrumented processing intervals,
**not** the transfer wall time, CPU-only execution time, or service downtime.
It excludes command reception, hex decoding, inter-command waits, responses,
and reboot. Interrupts and flash waits inside the measured calls remain included.

Expanded per-chunk replies increase application bytes and can change host
transfer time. Keep schema-1 pilot records and schema-2 trials separate. Report
actual command/response bytes and host wall time independently; do not convert
byte reduction into energy or flash-endurance claims.

## Validation

`tests/test_timing.cpp` uses the real shared Engine with a deterministic clock,
NOR storage/failure double, and explicit mock crypto. It checks exact disjoint
stage durations, errors in each storage stage, first/second signature failures,
no-clock behavior, and checkpoint overhead belonging only to total.
`tests/test_native.py` independently verifies genuine RSA/public fixtures,
persistence/replay behavior, and the schema-2 timing inequalities.
`tests/test_ota_timing.py` compiles the actual F dispatcher with deterministic
IDF/crypto doubles and checks exact per-chunk/cumulative accounting, cleanup time
on a rejected complete image, counter reset for the next transfer, and reuse of
the injected crypto object. These doubles are not hardware or cryptographic
validation; genuine ESP-IDF builds and subsequent board trials remain separate.
