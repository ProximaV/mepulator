#include "armcomm.h"

#include <cstring>

#include "../cpu.h"
#include "../log.h"

ARMComm::ARMComm(Cpu *cpu_) : cpu(cpu_) {
    Reset();
}

void ARMComm::Reset() {
    std::lock_guard<std::mutex> lock(mu);
    std::memset(regs, 0, sizeof(regs));
}

uint32_t ARMComm::Read32(uint32_t addr) {
    std::lock_guard<std::mutex> lock(mu);
    const uint32_t off = addr & 0xFFFu;
    if (off < sizeof(regs)) {
        return regs[off >> 2];
    }
    LOG_WARN("ARMComm::Read32 unmapped offset 0x%x", off);
    return 0;
}

void ARMComm::Write32(uint32_t addr, uint32_t value) {
    Cpu *target_cpu = nullptr;
    {
        std::lock_guard<std::mutex> lock(mu);
        const uint32_t off = addr & 0xFFFu;

        if (off == 0x10 && value == 0xFFFFFFFFu) {
            // Early boot probe on F00D firmware (e.g. 1.692)
            return;
        }

        if (off == 0x10) {
            regs[0] = 0; // Clear F00D->ARM status when new command written or cleared
            regs[0x10 >> 2] = value;
            if (value != 0) {
                target_cpu = cpu;
            }
        } else if (off < sizeof(regs)) {
            regs[off >> 2] = value;
        } else {
            LOG_WARN("ARMComm::Write32 unmapped offset 0x%x <= 0x%08x", off, value);
        }
    }

    if (target_cpu) {
        target_cpu->RaiseIrq(8);
    }
}

void ARMComm::ArmSendCommand(uint32_t cmd, bool raise_irq) {
    Write32(0x10, cmd);
    if (!raise_irq && cpu) {
        cpu->ClearIrq(8);
    }
}

uint32_t ARMComm::ArmReadReply() const {
    std::lock_guard<std::mutex> lock(mu);
    return regs[0];
}
