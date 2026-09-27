# Rebuilding the stage025 firmware

The Windows experiment runner uses the supplied factory images. Rebuilding is
optional and requires Linux or WSL. No private signing key is required: the
builder checks and embeds the frozen, previously signed factory envelopes.

The reference build uses ESP-IDF **v5.3.2**, commit
`9d7f2d69f50d1288526d4f1027108e314e8c879f`, including its pinned submodules.
Install it according to the ESP-IDF installation instructions, for target
`esp32s3`, and activate its `export.sh`. The SDK's own `tools/tools.json` pins the
Xtensa compiler to `esp-13.2.0_20240530` (GCC 13.2.0).

Additional Python packages used by this build, installed in the activated SDK
environment:

```bash
python -m pip install cmake==3.30.2 ninja==1.11.1.4 numpy==2.3.5
python /absolute/path/stage025/tools/build025.py --output /absolute/path/stage025-rebuild
```

The output directory must not exist and must be outside the kit. The builder
creates four images: LR and decision tree, each with `full_slot` and
`necessary_sectors`. It records SDK/submodule/compiler identities, Python
packages, hashes of the frozen source, build logs, image identities and resolved
`sdkconfig` files. Every image is checked for its exact factory envelope and ELF
hash. Within each model family, resolved configuration values must differ only
in the selected erase policy.

The matched settings are 160 MHz CPU, 80 MHz DIO flash, 4 MiB flash, 100 Hz
FreeRTOS tick, GCC `-Og`, and a 65536-byte main task stack. Physical model
partitions remain 64 KiB; the comparison concerns the erased prefix. The build
command does not flash a device or change eFuses.

`BUILD_METADATA.json` describes the reference binaries supplied with this kit.
A rebuild produces its own metadata, because build timestamps and file paths
can change binary hashes. Keep that output separate; replacing experiment
binaries requires a new reviewed kit manifest and separately identified run.
