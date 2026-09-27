# Third-party attribution and retained notices

Oleksandr Kuznetsov is credited for the original IDS Update Lab software. This attribution does not replace the authorship or notices of dependencies, templates or source datasets. The distribution manifest determines which components are included.

| Material | Attribution and scope |
|---|---|
| Material copied from the earlier `iot-audit` project | Its inspected license states MIT, Copyright (c) 2025 Oleksandr Kuznetsov. The original notice is retained in `LICENSES/legacy-iot-audit-MIT.txt` for material covered by it. |
| ESP-IDF, toolchain libraries and linked firmware components | Inspected ESP-IDF 5.3.2, newlib, FreeRTOS, MbedTLS, Xtensa and TLSF license/notice texts are retained in `LICENSES/upstream/`, with source URLs and hashes in its `PROVENANCE.json`. Preserve other notices supplied with the exact toolchain and included components. A project-level license does not replace the notices applicable to linked third-party code in distributed binaries. |
| Python dependencies | Obtain the pinned packages using the relevant requirements files. Each package remains under its own license. Naming a dependency is not a claim that its source is distributed in this archive. |
| TON_IoT, X-IIoTID and other source datasets | Cite the originating datasets. Their providers' terms govern source records and derived samples where applicable. Dataset availability is not a permission to apply the project's software license to them. |
| Original measurement logs, aggregate tables and plots | Their provenance and scope are documented separately. The separately retained manuscript is not part of the public distribution; software authorship does not overwrite its six-author attribution. |

Some project folders use the name `vendor` to preserve copies of earlier project scripts. For example, `research030/energy/VENDOR_PROVENANCE.json` identifies its three copied scripts as originating in `completion020/tools/`. A folder name alone does not imply third-party authorship: retain the recorded provenance and inspect the source notice.

This notice identifies the inspected components; it is not an exhaustive software bill of materials for the final public candidate. Keep every existing dependency notice in the files actually released.
