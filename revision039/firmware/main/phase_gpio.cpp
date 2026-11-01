// Author: Oleksandr Kuznetsov
#include "phase_gpio.h"
#include "sdkconfig.h"
#include "driver/gpio.h"
#include <cstdio>
#include <cstring>
#include <cinttypes>
namespace {
const char* selected = "none";
uint32_t hits = 0;
[[maybe_unused]] constexpr const char* names[] = {"model_erase", "model_body", "slot_commit",
    "selector_body", "selector_commit", "rotation_erase", "rotation_body", "rotation_commit"};
void response(const char* event, bool ok) {
#if CONFIG_IDS_PHASE_GPIO_ENABLED
    std::printf("{\"event\":\"%s\",\"ok\":%s,\"enabled\":true,\"gpio\":%d,\"phase\":\"%s\",\"hits\":%" PRIu32 "}\n",
        event, ok ? "true" : "false", CONFIG_IDS_PHASE_GPIO, selected, hits);
#else
    std::printf("{\"event\":\"%s\",\"ok\":%s,\"enabled\":false,\"gpio\":null,\"phase\":\"none\",\"hits\":0}\n",
        event, ok ? "true" : "false");
#endif
}
}
void phase_gpio_init() {
    selected = "none"; hits = 0;
#if CONFIG_IDS_PHASE_GPIO_ENABLED
    gpio_config_t config{}; config.pin_bit_mask = 1ULL << CONFIG_IDS_PHASE_GPIO;
    config.mode = GPIO_MODE_OUTPUT; config.pull_up_en = GPIO_PULLUP_DISABLE;
    config.pull_down_en = GPIO_PULLDOWN_DISABLE; config.intr_type = GPIO_INTR_DISABLE;
    ESP_ERROR_CHECK(gpio_set_level(gpio_num_t(CONFIG_IDS_PHASE_GPIO), 0));
    ESP_ERROR_CHECK(gpio_config(&config));
#endif
}
void phase_gpio_begin(const char* name) {
#if CONFIG_IDS_PHASE_GPIO_ENABLED
    if (std::strcmp(selected, name) == 0) {
        ++hits; gpio_set_level(gpio_num_t(CONFIG_IDS_PHASE_GPIO), 1);
    }
#else
    (void)name;
#endif
}
void phase_gpio_end() {
#if CONFIG_IDS_PHASE_GPIO_ENABLED
    gpio_set_level(gpio_num_t(CONFIG_IDS_PHASE_GPIO), 0);
#endif
}
bool phase_gpio_command(const char* line) {
    if (!std::strcmp(line, "PHASE_STATUS")) { response("phase_status", true); return true; }
    if (!std::strcmp(line, "PHASE_DISARM")) {
        phase_gpio_end(); selected = "none"; response("phase_control", true); return true;
    }
    if (!std::strncmp(line, "PHASE_ARM ", 10)) {
        phase_gpio_end(); selected = "none"; hits = 0;
#if CONFIG_IDS_PHASE_GPIO_ENABLED
        for (const char* name : names) if (!std::strcmp(line + 10, name)) {
            selected = name; response("phase_control", true); return true;
        }
#endif
        response("phase_control", false); return true;
    }
    return false;
}
