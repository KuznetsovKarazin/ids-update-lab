# Analysis materials for Preserving Detector Semantics in TinyML Updates

This directory contains the analysis scripts, exported diagnostic models, derived summaries, and figures supporting the study. The manuscript and its submission template are maintained separately and are not part of the public software or evidence release.

- Repository: https://github.com/KuznetsovKarazin/ids-update-lab
- Evidence archive: https://doi.org/10.5281/zenodo.22978008
- Reproduction instructions: [`../release/REPRODUCE.md`](../release/REPRODUCE.md)

The `analysis/`, `new_calibration/`, `new_analysis/`, and `new_diagnostics/` directories contain the relevant scripts and numerical summaries. The historical `manuscript/figures/` and `manuscript/tables/` paths contain derived figure and table outputs, not the manuscript text. Figure-generation scripts retain these output paths for compatibility.

Original TON_IoT CSV files, saved traffic samples, and the full per-record evaluation database are excluded. The reproduction guide explains acquisition of the hash-pinned source files, deterministic reconstruction of fitting/calibration samples and the 258 implementation-check inputs, and verification against the preserved array fingerprints. A companion exporter produces source-file and CSV data-row references from verified samples. Rebuilding figures from summaries is separate from rerunning these analyses or conducting MCU experiments.

Oleksandr Kuznetsov is the sole author of the original project software. The article retains its six authors. The restricted 258-input MCU coverage and software-only interruption scope remain unchanged.
