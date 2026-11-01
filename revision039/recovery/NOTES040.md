# Recovery040: correction and evidence scope

Original software author: Oleksandr Kuznetsov.

This continuation repairs the compressed full-image updater used in revision039.
The source campaign remains immutable. No model, decision threshold, numerical
panel, golden reference, or numerical tolerance is changed.

## Recorded failure and correction

The submitted archive has SHA-256
`6d0a337ef3307faa9823cd6191376b715fecbbd5d1a39e5c4a5309e5ecaf2d89`.
Its LR/Og compressed negative image-hash test returned
`decompression_or_write` at the last compressed chunk. The same bytes form a
valid zlib stream; its reconstructed image deliberately has a wrong signed hash.

The old ESP32-S3 ELF binds `tinfl_decompress` to the ROM symbol at `0x40000828`.
That implementation has a different decompressor-state ABI from the vendored
miniz 3.0.2 header. All six exported inflater functions now have an `ids039_`
prefix. The build rejects an OTA object referencing unprefixed inflater symbols
and verifies the decoder's executable symbol in the linked application ELF.
Each corrected full-image build includes a pinned `inflater_linkage.json`.

Eight full-image templates (four model families, Og and O2) were rebuilt.
Bundle templates and their metadata remain byte-for-byte unchanged. Their
historical source fingerprints remain in their own metadata. The combined build
index explicitly distinguishes original bundle builds from corrected full-image
builds. The old partial cost measurements are preserved as pre-fix pilot data
and excluded from the new primary estimates.

Host regression checks reproduce the old symbol collision, reject bad hashes
without selecting the image, and verify the complete recorded compressed byte
stream. This is not a claim of successful execution of the new firmware on an
ESP32-S3. The recovery command therefore runs two short MCU pilots before the
primary acquisition.

## Numerical findings retained

The completed Og block contains 26,624 comparisons on 1,024 unique inputs and
26 model conditions. The 512 real retained inputs and 256 random synthetic
inputs show no label mismatch or probability-tolerance exceedance for any
condition. Seven label disagreements occur on targeted decision-boundary
inputs. Nine INT8 output-code differences arise from three synthetic inputs
repeated under three threshold conditions. The largest probability difference
is 0.4236266614662171 and remains in the record.

The unchanged C++ kernel on the host reproduces all 26,624 MCU labels and all
10,240 MCU integer output codes. Boundary traces demonstrate how one ULP in
floating-point preprocessing can cross an input-quantization boundary. Exact
intermediate MCU float bits were not recorded, so this analysis distinguishes
reproduced output behavior from a direct device-internal trace.

The `numerical_audit` folder contains the read-only reproducer, summary tables,
and individual discrepancies. The original panel and original hardware logs
are read from the preserved user campaign rather than copied into this kit.

## What this run does not measure

This continuation does not acquire energy or physical power-loss evidence.
It uses one explicitly identified ESP32-S3. It does not establish universal
numerical equivalence or an independent detection-quality test.
