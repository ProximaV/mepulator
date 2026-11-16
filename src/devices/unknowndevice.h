#pragma once

#include <cstdint>

#include "../device.h"

class EEPROM;

class UnknownDevice : public Device {
public:
    explicit UnknownDevice(uint32_t base, EEPROM *keyring_ = nullptr);
    void Reset();

    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

private:
    uint32_t my_base;
    EEPROM *keyring = nullptr;
    uint32_t regs[0x400] = {};
};
