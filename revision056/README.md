# Second-round validation (056)

The [frozen protocol](protocol.json) separates two new experiments: the existing
release-update implementation on two independently identified ESP32-C3 SuperMini
boards, and a controlled A/B release experiment on independently sourced CICIoT2023
records. Neither experiment is a reclassification of historical evidence.

At protocol publication, no new C3 measurements or CIC model predictions exist.
Software tests and successful compilation will be reported separately from physical
measurements. Unknown outcomes and any preparation failures remain explicit.

The CIC feature contract differs from TON_IoT. Its hash-based role assignment keeps
identical eight-feature inputs together, but is not a temporal ordering or a claim
of independent capture sessions. All source-shard choices precede model evaluation.

## Current status

The [CIC experiment](cic/README.md) and its full source re-scan have completed.
All eight C3 family/policy images compiled successfully under the pinned SDK.
Their immutable build metadata retains the preparation-time label `compiled_not_hardware_validated`. **Both C3 acquisitions have now completed.** The subsequent [057 audit](../revision057/README.md) verifies the raw physical measurements separately from those build records.

Two C3 SuperMini boards address repeatability between two instances and portability
from the original Xtensa ESP32-S3 implementation to RISC-V ESP32-C3. They are not
a second identical S3 board, and this three-board set is not a population-level
hardware benchmark. C3 results will be reported per board, compared only with the
S3 `-O2`, A-to-B cells under matching measurement boundaries.

## Prepare the acquisition checkout

Use a fresh checkout/directory, Python 3.12 or 3.13, and a data-capable USB cable.
The physical campaign installs the laboratory firmware and overwrites the test
application/model storage on the selected C3. Connect **one C3 at a time** directly
by USB; this campaign does not use the Pico, TPS22919 board or power-cut wiring.
Close serial monitors before acquisition. The runner requests temporary Windows
system-awake status and restores it on exit; it does not change persistent power
settings or prevent manual sleep or USB driver failures. The ROM chip, MAC and at least 4 MB of
detected flash are checked before each provisioning write.

```powershell
py -3.12 -m venv .venv056
$Py = (Resolve-Path .\.venv056\Scripts\python.exe).Path
& $Py -m pip install -r .\revision056\requirements-hardware.txt
& $Py .\release\restore_artifacts056.py --artifact c3_prebuilt056 --artifact c3_panel056 --destination .
```

The portable acquisition ZIP already contains the C3 images and panel; its
`START_C3_RU.md` gives the corresponding shorter commands. No compilation is needed
on the Windows acquisition PC.

## Inspect, then acquire each board

First list ports with `& $Py -m serial.tools.list_ports -v`. Substitute the actual
C3 port for `COM7` below; do not assume the former S3/Pico COM numbers still apply.
Inspection reads ROM identity and flash capacity and resets the board; it issues
no flash write or erase.

```powershell
& $Py .\revision056\hardware\inspect_c3.py --port COM7 --output ..\c3-board1-identity
& $Py .\revision056\hardware\run_board056.py --identity ..\c3-board1-identity\identity.json --output ..\c3-board1-056
```

Disconnect board 1, connect board 2, list ports again, and run:

```powershell
& $Py .\revision056\hardware\inspect_c3.py --port COM7 --output ..\c3-board2-identity
& $Py .\revision056\hardware\run_board056.py --identity ..\c3-board2-identity\identity.json --output ..\c3-board2-056
```

Use fresh names if these directories exist. If a port changed after inspection,
add `--port COMn` to `run_board056.py`; the ROM MAC must still match. A failed
campaign stops, preserves all partial evidence and produces an archive. Do not
silently rerun it under the same name, delete a failed observation or substitute
a later successful endpoint. Investigate the first failure before continuing.

Each successful board campaign contains the unchanged 26 × 1024 numerical panel
and 120 measured installations: 4 families × 3 policies × 10 blocks, A-to-B only.
Preparation, warm-up and negative controls are recorded separately. Numerical
disagreements are retained and do not cause threshold/parameter retuning.
Both per-board output ZIPs are required for the subsequent manuscript update.

```powershell
& $Py .\revision056\hardware\analyze_boards056.py --board ..\c3-board1-056 --board ..\c3-board2-056 --output ..\c3-analysis056
```

The analyzer requires two distinct MACs, verifies campaign hashes, binds numerical
observations and cost receipts to raw serial bytes, and emits per-board summaries.
It does not synthesize missing measurements or pool the two boards.

## Build from source

Install ESP-IDF v5.3.2 at commit
`9d7f2d69f50d1288526d4f1027108e314e8c879f` with all matching submodules and the C3
toolchain; source its `export.sh`. In that SDK's Python environment install
`numpy==2.3.5`. Retain the SDK's compatible `cryptography<43` requirement; the
host fitting environment is separate. The verified build used CMake 3.30.2 and
Ninja 1.11.1.1.

```bash
python revision056/build_c3.py --optimizations O2 --work ../c3-build-work --output ../c3-rebuilt
```

The C3 firmware differs from the preserved 039 firmware only in its selected IDF
target and the reported chip string (`CONFIG_IDF_TARGET`). The inference/update
algorithms, 160 MHz setting, partition layout, strict floating-point flags and
counter definitions are retained. The build checks the actual SDK configuration,
image checksums/ELF identity, safe template patching, namespaced inflater linkage,
and source/file hashes. Original build logs and exact source metadata are included
with the prebuilt archive. Compilation and software tests are not device execution.
