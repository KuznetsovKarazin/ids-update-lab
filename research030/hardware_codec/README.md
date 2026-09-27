# Stage 030 binary contract

This directory contains a deliberately public **laboratory private key**. It is
included so the Windows queue can sign newly fitted releases without a build
toolchain. Anybody holding this kit can sign a package; it does not establish a
production trust boundary. No Secure Boot, flash encryption, or eFuse operation
is enabled by these templates.

The signed raw feature schema has eight nonnegative finite float32 values in
the order and units in `feature_contract.json`. Its SHA256 is over UTF-8 JSON
with sorted keys and separators `,` and `:`. Runtime ABI is a separate signed
field and must match the compiled executable:

| ABI | Model | Input preprocessing | Decision |
|---|---|---|---|
| 2 | Logistic regression | log1p then signed mean/scale | probability > threshold |
| 3 | Decision tree | Raw counters | probability > threshold |
| 4 | MLP 8→16→8→1 | log1p then signed mean/scale | probability > threshold |
| 5 | Integer MLP 8→16→8→1 | log1p, signed mean/scale, signed input quantizer | q ≥ q_threshold |

ABI 4 and 5 use ReLU in the two hidden layers. Floating thresholds may be 0 or
1; threshold 1 produces the all-normal decision. Integer threshold 128 also
produces all-normal. Model validity and detection quality are separate checks.

The old envelope header and RSA-2048 PKCS#1 v1.5/SHA256 authentication remain.
MLP payload magic is `SIDSM01\0`; bytes 0–75 follow the common header, byte 76
holds layer count 3, bytes 80–143 hold means and scales (float32 little endian),
and bytes 144–159 hold dimensions [8,16,8,1] as uint32 little endian. ABI 4 then
stores, for each layer, input-major float32 weights and float32 biases.

ABI 5 instead has input_scale (float32) and q_threshold (int32), followed per
layer by multiplier (uint32), right shift (uint32), output_scale (float32),
input-major int8 weights and int32 biases. Activations and weights use
[-127,127]. Input quantization rounds to nearest with ties away from zero;
hidden ReLU follows requantization and clipping. Accumulation is int32;
requantization multiplies in int64 and shifts with ties away from zero, without
implementation-dependent signed shifts. Bounds are checked at package decode.
The last probability is stable sigmoid(float32(q) × output_scale), while the
decision uses the integer comparison. This is a custom integer runtime, **not
TFLite Micro**, and makes no claim of bitwise identity to that framework.

Model data and preprocessing are decoded from the same signed payload and
selected by the same journal commit. Every update retains two 64 KiB capacity
slots but erases only the necessary 4 KiB sectors. The template bootstrap is a
zero placeholder, not a trained detector; the host must replace it with trained
A before a scientific run.

`patch_image()` checks the original ESP checksum and SHA256, verifies the new
envelope, checks the runtime ABI, patches the dedicated 4116-byte factory
region and app descriptor version, then recomputes the ESP checksum and SHA256.
The compiled ELF hash remains the identity of the original **template ELF**.
The separately recorded full patched-image SHA256 is the executable artifact
identity. The full-image manifest authenticates this entire image, its version,
runtime ABI and schema. On boot, its signed factory version must equal the
patched app descriptor version before the image is marked valid.

Whole-image transfer accepts up to 1024 payload bytes per acknowledged command.
It is still a stop-and-wait hex serial protocol. Its end-to-end energy includes
that protocol; it is not an intrinsic lower bound for OTA implementations.

`ENERGY_MARKER <ms>` accepts 1–11000 ms and performs CPU arithmetic plus SHA256,
yielding every approximately 40 ms to service the watchdog. It changes neither
model storage nor radio state. Its reply records actual device start, end and
duration. Energy analysis must establish marker visibility and synchronization
from the actual FNB58 recording, rather than assuming it.
