#include "unknowndevice.h"

#include <cstring>

#include "../log.h"
#include "eeprom.h"

UnknownDevice::UnknownDevice(uint32_t base, EEPROM *keyring_)
    : my_base(base), keyring(keyring_) {
    Reset();
}

void UnknownDevice::Reset() {
    std::memset(regs, 0, sizeof(regs));
}

uint32_t UnknownDevice::Read32(uint32_t addr) {
    const uint32_t off = addr & 0xFFFu;
    if (my_base == 0xE0020000u) {
        if (off == 0x20) {
            return 0; // RAZ/WI gate register
        }
        if (off >= 0x100 && off < 0x120 && keyring) {
            uint8_t slot602[EEPROM::kSlotBytes] = {};
            keyring->GetKeySlot(0x602, slot602, sizeof(slot602));
            uint32_t val = 0;
            std::memcpy(&val, &slot602[off - 0x100], sizeof(val));
            return val;
        }
    }

    if ((off >> 2) < (sizeof(regs) / sizeof(regs[0]))) {
        LOG("MMIO Read [0x%08x] => 0x%08x", my_base + off, regs[off >> 2]);
        return regs[off >> 2];
    }
    return 0;
}

void UnknownDevice::Write32(uint32_t addr, uint32_t value) {
    const uint32_t off = addr & 0xFFFu;
    if (my_base == 0xE0020000u && off == 0x20) {
        return; // RAZ/WI
    }
    if ((off >> 2) < (sizeof(regs) / sizeof(regs[0]))) {
        if (my_base == 0xE0020000u && off >= 0x100 && off < 0x120 && keyring) {
            uint8_t slot602[EEPROM::kSlotBytes] = {};
            keyring->GetKeySlot(0x602, slot602, sizeof(slot602));
            std::memcpy(&slot602[off - 0x100], &value, sizeof(value));
            keyring->SetKeySlot(0x602, slot602, sizeof(slot602));
        }
        regs[off >> 2] = value;
        LOG("MMIO Write [0x%08x] <= 0x%08x", my_base + off, value);
    }
}
