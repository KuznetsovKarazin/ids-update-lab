// Author: Oleksandr Kuznetsov
#pragma once
#include <cstddef>
void phase_gpio_init();
bool phase_gpio_command(const char* line);
void phase_gpio_begin(const char* name);
void phase_gpio_end();
class PhaseScope {
public:
    explicit PhaseScope(const char* name) { phase_gpio_begin(name); }
    ~PhaseScope() { phase_gpio_end(); }
};
