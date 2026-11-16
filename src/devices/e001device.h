#pragma once

#include <cstdint>

#include "../device.h"

class e001device : public Device {
public:
    e001device();
    void Reset();

    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

private:
    uint32_t regs[16] = {};
};
