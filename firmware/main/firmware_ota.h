#pragma once

#include <cstddef>
#include <cstdint>
#include "ids_core.h"

// Same retained crypto instance used by Engine. It and schema storage must
// outlive this module; factory validation warms crypto before serving commands.
void firmware_ota_init(ids::Crypto& crypto, uint32_t factory_version,
                       const uint8_t feature_schema[32]);

// Returns false only if the command is not one of FW_BEGIN/CHUNK/END/ABORT.
// Replies are one-line JSON. Successful FW_END selects the image, but does not
// reboot automatically: the host can record the reply before issuing REBOOT.
bool firmware_ota_process(const char *line);

// Baseline boot self-check: PROJECT_VER must be the decimal factory version.
// Call before marking an OTA image valid. This does not burn any eFuse.
bool firmware_ota_image_version_matches(uint32_t factory_version);
bool firmware_ota_boot_check();
