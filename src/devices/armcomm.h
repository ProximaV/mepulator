#pragma once

#include <cstdint>
#include <mutex>

#include "../device.h"

class Cpu;

class ARMComm : public Device {
public:
    explicit ARMComm(Cpu *cpu_ = nullptr);

    void AttachCpu(Cpu *cpu_) { cpu = cpu_; }
    void Reset();

    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

    // Convenience helpers for ARM-side emulation or debugger control
    void ArmSendCommand(uint32_t cmd, bool raise_irq = true);
    uint32_t ArmReadReply() const;

private:
    Cpu *cpu = nullptr;
    mutable std::mutex mu;
    uint32_t regs[32] = {}; // 0x00..0x7C (0x00 = reg00, 0x10 = reg10, etc.)
};
