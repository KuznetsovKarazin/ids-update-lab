# License scope

The original IDS Update Lab software is Copyright (c) 2026 Oleksandr Kuznetsov
and is released under the MIT License in `LICENSE`. This includes the original
Python/C/C++ source, experiment runners, analysis scripts and configuration.
Earlier iot-audit material retains its 2025 notice.

Original documentation, figures, laboratory photographs,
aggregate numerical results and measurement records are offered under the
Creative Commons Attribution 4.0 International license (CC-BY-4.0):
https://creativecommons.org/licenses/by/4.0/
Legal code: https://creativecommons.org/licenses/by/4.0/legalcode.en
Credit the software author for software. When reusing evidence, cite the versioned
artifact and the associated article, state changes, and retain provenance. The
manuscript is not distributed in this release; its separate authorship is listed
in AUTHORS.md.

Trained model parameters are included as original project artifacts under MIT;
this does not grant rights over their source dataset. Raw TON_IoT records,
sampled data arrays, exported dataset check vectors and per-record evaluation
databases are excluded. Acquire source data under the provider's terms.

Third-party components and linked firmware libraries keep their own notices and
licenses. Neither the MIT license nor CC-BY is a blanket relicensing of those
components. See `THIRD_PARTY_NOTICES.md` and `LICENSES/upstream/`. The latter
contains notices for inspected ESP-IDF 5.3.2 components; it is not a complete
linker-derived SBOM. Python dependencies are installed separately.

The explicitly public laboratory development key is a test fixture. It provides
no production signing secrecy and must not be used as a production trust root.
