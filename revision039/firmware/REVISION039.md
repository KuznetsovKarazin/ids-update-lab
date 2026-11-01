# Revision039 firmware

Author of revision039 integration: Oleksandr Kuznetsov. Copied from frozen
`research030/firmware`; that source remains unchanged. Detector arithmetic,
contract, package layout and selector journal format are retained. Additions:

- actual streaming zlib full-image updater (`FWZ_*`), alongside existing `FW_*`;
- integer ABI5 `q_score` in `INFER`, from the same final integer accumulator/grid;
- optional selected-operation GPIO strobe, default disabled.

Use `revision039/build/build039.py` for pinned ESP-IDF 5.3.2 `Og`/`O2` builds.
`-ffp-contract=off` is retained, no fast-math. Timing builds disable phase GPIO.

Phase build: `CONFIG_IDS_PHASE_GPIO_ENABLED=y`, `CONFIG_IDS_PHASE_GPIO=4` (default;
verify the actual board and wiring). At boot GPIO starts low and disarmed.
`PHASE_STATUS` returns enabled/gpio/phase/hits; `PHASE_ARM <phase>` selects one
phase and resets hits; `PHASE_DISARM` drives low and clears the selection. Phases:
`model_erase`, `model_body`, `slot_commit`, `selector_body`, `selector_commit`,
`rotation_erase`, `rotation_body`, `rotation_commit`. The pin is high across the
actual partition erase/program API call and low on return; no deliberate pause
is inserted. A journal page erase tags its following body/commit as rotation.
Selector commit is at offset 112 in a 128-byte record. State is not persistent.

The strobe marks an **API execution window**, not an observed flash-cell pulse.
The controller must establish supply removal and account for switch/rail delay.
Neither this firmware nor a GPIO event certifies physical power interruption by
itself. See `revision039/powercut` for controller and evidence requirements.
