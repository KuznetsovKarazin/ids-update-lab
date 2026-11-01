# Phase-triggered physical power cuts (revision039)

Original software author: **Oleksandr Kuznetsov**. This module addresses R1.10.
Its preparation and software tests are **not** physical experimental results.

## Before connecting anything

The user currently has ESP32-S3, Pico 2, and FNB58. That list does not include a
verified power switch or a timing instrument. The default configuration is
disabled and the runner refuses to energize or cut a target until wiring gates
are explicitly completed. The ordinary numerical/timing campaigns do not need
this apparatus and should run first.

Required additions are an external active-high load switch with a 3.3-V-compatible
enable input, default-off pull-down, suitable voltage/current rating, and a
documented sufficiently fast discharge path; an ADC voltage divider; wires; and
a method to validate the target supply fall time relative to the phase marker.
Select the exact module and divider after checking the actual ESP32 board power
connections. A relay can cut power, but its latency/bounce may make short write
phases inaccessible. A MOSFET/load-switch part name alone does not establish the
complete board's power-fall time: capacitance and backpower matter.

**Never power the ESP32 from a Pico GPIO.** The GPIO drives the external switch's
enable input only. Pico and ESP32 share ground. Pico remains independently
powered. All target power paths, including USB VBUS and signal-line backpower,
must be checked. Native USB data may reconnect after an outage; its VBUS supply
must not bypass the switch. Never connect 5 V to a Pico GPIO or ADC input.

Proposed pin assignment (verify actual exposed ESP32 pin before use):

| Signal | Pico 2 | Target / external circuit |
|---|---|---|
| Enable | GP15 | Active-high external load-switch EN, external pull-down |
| Phase input | GP14 | ESP32 GPIO4 strobe, 3.3 V logic, common ground |
| Rail monitor | GP26 / ADC0 | Target **3.3 V rail** through a verified divider |
| Ground | GND | Common target/switch/divider ground |

The ESP firmware must be the revision039 **phase-enabled package** build.
Ordinary timing builds have phase hooks disabled; do not use this intrusive
build to replace the headline optimized timing measurements.

## Evidence and limits

`PHASE_ARM <name>` selects one of `model_erase`, `model_body`, `slot_commit`,
`selector_body`, `selector_commit`, `rotation_erase`, `rotation_body`, or
`rotation_commit`. Firmware sets the strobe high immediately around the selected
`esp_partition` erase/write API call and low afterwards. Pico PIO waits for its
rising edge, delays a preselected number of cycles, checks the marker is still
high, and switches EN low. If the marker has already fallen, it **does not cut**.

The PIO delay runs at nominal 1 MHz with three nominal instruction cycles of
overhead and additional input synchronization. The code records these timing
boundaries rather than claiming a calibrated microsecond cut instant.

ADC samples are raw 16-bit API readings. Calibrate `adc_volts_per_count` and
`adc_zero_volts` against an independent voltage reference/meter. Require the
actual target rail to stay below `rail_off_max_volts` during the outage. The
sample clock begins after the CPU observes the PIO event, so the ADC trace
**does not measure switch-edge-to-rail-collapse latency**.

For an inside-API-window interpretation, validate the full apparatus with an
independent phase/voltage capture. Save that evidence, put its path and SHA-256
into the configuration, and record a conservative observed supply-collapse
upper bound. The full series refuses a phase whose minimum uncut duration is
too short for that bound. The resulting `phase_confirmed` field means **supported
by the external bound and preflight windows**; exact internal flash instruction
or cell-programming timing is never claimed. Preserve the external trace and
its assumptions with the results. FNB58's nominal 100 samples/s is insufficient
to validate a short flash-write timing bound.

`--allow-unconfirmed-phase-timing` is available only for an explicitly exploratory
phase-triggered power-cut series. Its confirmed physical OFF cases do not by
themselves close the reviewer request about interruption within the operation.

## Commands (Windows PowerShell)

Use the standalone snapshot and Python environment prepared by
`revision039\Start-Revision039.ps1`. Replace serial ports with observed ports;
COM11 is only an example for Pico. Close other serial monitors.

1. Set the paths. The main `Prepare` command already creates the frozen power-cut
plan at `$PowerPlan`; it does not access either board.

```powershell
Set-Location E:\ids-update-lab
$Py = 'E:\ids-update-lab\.venv039\Scripts\python.exe'
$Kit = 'E:\ids-update-lab\revision039-kit'
$PowerPlan = 'E:\ids-update-lab\runs\revision039\prepared\powercut'
$PowerRoot = 'E:\ids-update-lab\runs\revision039\powercut'
$Config = 'E:\ids-update-lab\powercut_config.json'
```

This chooses A/B-MLP-F32, the largest current package, and creates 200 trials (25
per phase), random order and fixed seed. Signed candidates alternate between
the two real parameter sets with strictly increasing versions. The candidate
always differs from the currently selected A/B parameters, even after a failed
update consumes an attempted version number.
Thus old/new states have different model parameters as well as versions.
This is a storage recovery experiment, not an IDS-quality or speed comparison.

Only if the plan has not been prepared, create it from the frozen public models:

```powershell
& $Py "$Kit\revision039\powercut\run_powercut039.py" plan --root $Kit --model "$Kit\paper037\evidence_inputs\training\models\B_mlp_float.json" --model-a "$Kit\paper037\evidence_inputs\training\models\A_mlp_float.json" --output $PowerPlan
```

2. **Before connecting the external cut circuit**, provision the ESP32 over its
ordinary USB connection. This replaces its laboratory firmware and clears its
model slots/selector journal. It checks the ROM chip and MAC against `--board-id`
before writing, validates all phase-build hashes, patches the exact planned A
model into the factory image, and checks the boot identity and inference.

```powershell
& $Py "$Kit\revision039\powercut\run_powercut039.py" flash --root $Kit --plan $PowerPlan --prebuilt-root "$Kit\revision039\build\prebuilt\phase_gpio4\O2" --port COM13 --board-id esp32s3-a0f262ebb558 --output "$PowerRoot\flash"
```

Keep this flash directory as evidence. If you want to verify and prepare image
files without board access first, add `--prepare-only` and use a **different**
output directory; that does not flash the board. After actual provisioning,
disconnect the direct USB power path before installing the reviewed switching
circuit. Restore target USB data through a path whose VBUS cannot bypass it.

3. Install official **Pico 2** MicroPython (not the Pico/RP2040 image), copy
`pico_power039.py` to the Pico as `main.py`, and a reviewed copy of
`powercut_config.example.json` as `powercut_config.json`. An editor such as
Thonny or the official `mpremote` tool can copy them. Keep `enabled=false` until
the external wiring is reviewed. Fill every condition from actual checks, not
by blindly changing all booleans. Keep the local config byte-identical to the
one on Pico; the controller reports its SHA-256 and the host enforces it.

The files to copy are in `$Kit\revision039\powercut\`. Keep your reviewed local
configuration at `$Config`; never replace it with the disabled example after
performing the hardware checks.

4. Perform the isolated OFF/ON
and uncut phase-width preflight. The commands below **write laboratory model
storage**; they never erase or rewrite old result files:

```powershell
& $Py "$Kit\revision039\powercut\run_powercut039.py" preflight --root $Kit --plan $PowerPlan --config $Config --mcu-port COM13 --controller-port COM11 --board-id esp32s3-a0f262ebb558 --output "$PowerRoot\preflight"
```

Preflight installs two known signed updates to occupy both slots, verifies
inference, checks real rail removal, then collects three uncut pulses for each
phase. Ordinary signed updates advance the journal until rotation occurs; no
special destructive journal reset is used. The preflight board ID is a supplied
label; the preceding flash directory provides the independent ROM identity check.

5. After documenting fall-time validation and copying the final exact config to
Pico, rerun preflight into a **new** directory if the config changed. Run:

```powershell
& $Py "$Kit\revision039\powercut\run_powercut039.py" run --root $Kit --plan $PowerPlan --config $Config --preflight "$PowerRoot\preflight" --mcu-port COM13 --controller-port COM11 --board-id esp32s3-a0f262ebb558 --output "$PowerRoot\results"
```

Do not manually unplug USB during this run. Trial outcome is old valid, new
valid, fail closed, no response, or unexpected/mixed. Failed/missed attempts
remain in the records and denominator. An unexpected state stops the campaign
without reflashing away its evidence. A current-version replay check follows
each successfully recovered trial. The serial `UPDATE` that lost its reply is
never retried.

If only the host process was interrupted, the same command with `--resume` can
continue. It checks the current state of an unfinished trial **before** issuing
any preparation update, marks the interrupted trial without replaying it, and
preserves its evidence gap. Unsafe/unavailable prior outcomes block automatic
resumption. Summary snapshots use new filenames and never relabel an earlier
failure as successful.

## What to send back

Include the plan, complete preflight directory, complete result directory,
reviewed config, external timing capture, firmware/build hashes, and a photo
or schematic of the final power/data paths. A completed script can still have
unconfirmed/missed phase trials; inspect `all_planned_phases_have_confirmed_cut`
and the per-phase counts. Zero observed failures is not a general reliability
guarantee, and fail-closed behavior is not equivalent to service availability.

Software validation:

```powershell
& $Py -m unittest discover -s "$Kit\revision039\powercut\tests" -v
```

Primary controller API references: MicroPython `rp2.StateMachine`, `rp2.asm_pio`,
RP2 GPIO and ADC quick reference. Record the exact installed MicroPython version
(the controller `ID` reply contains it):
https://docs.micropython.org/en/latest/library/rp2.html
https://docs.micropython.org/en/latest/rp2/quickref.html
https://micropython.org/download/RPI_PICO2/
