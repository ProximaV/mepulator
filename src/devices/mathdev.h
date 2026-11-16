#pragma once

#include <cstdint>

#include "../device.h"

class Cpu;

class Math : public Device {
public:
    explicit Math(Cpu *cpu_ = nullptr);

    void AttachCpu(Cpu *cpu_) { cpu = cpu_; }
    void Reset();

    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

    void PowMod();

    uint32_t flags = 0;
    uint8_t ram[0x800] = {};
    uint32_t exponent = 0;
    uint32_t cmd = 0;

private:
    Cpu *cpu = nullptr;
};
