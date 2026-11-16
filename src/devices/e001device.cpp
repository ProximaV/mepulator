#include "e001device.h"

#include <cstring>

#include "../log.h"

e001device::e001device() {
    Reset();
}

void e001device::Reset() {
    std::memset(regs, 0, sizeof(regs));
    regs[0] = 0x80000005u;
}

uint32_t e001device::Read32(uint32_t addr) {
    const uint32_t off = addr & 0xFFFu;
    if (off < sizeof(regs)) {
        return regs[off >> 2];
    }
    LOG_WARN("e001device::Read32 unmapped offset 0x%x", off);
    return 0;
}

void e001device::Write32(uint32_t addr, uint32_t value) {
    const uint32_t off = addr & 0xFFFu;
    if (off < sizeof(regs)) {
        regs[off >> 2] = value;
        return;
    }
    LOG_WARN("e001device::Write32 unmapped offset 0x%x <= 0x%08x", off, value);
}
