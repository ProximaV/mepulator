#pragma once

#include <cstdint>
#include <random>

#include "../device.h"

class Cpu;
class EEPROM;
class Memory;

struct bigmac_regs {
    uint32_t src;       // 0x00
    uint32_t dst;       // 0x04
    uint32_t sz;        // 0x08
    uint32_t func;      // 0x0C
    uint32_t keyslot;   // 0x10
    uint32_t iv;        // 0x14
    uint32_t unk_0x18;  // 0x18
    uint32_t commit;    // 0x1C
    uint32_t unk_0x20;  // 0x20
    uint32_t busy;      // 0x24
    uint32_t unk[(0x80 - 0x28) / 4];
};

static_assert(sizeof(bigmac_regs) == 0x80, "bigmac_regs must be 0x80 bytes per channel");

class Bigmac : public Device {
public:
    Bigmac(Memory *mem_, EEPROM *keyring_ = nullptr, Cpu *cpu_ = nullptr);

    void AttachKeyring(EEPROM *keyring_) { keyring = keyring_; }
    void AttachCpu(Cpu *cpu_) { cpu = cpu_; }
    void Reset();

    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

    void DoFunc(int channel);

    Memory *mem = nullptr;
    EEPROM *keyring = nullptr;
    Cpu *cpu = nullptr;

    bigmac_regs channels[2] = {};
    uint32_t control[0x100 / 4] = {};
    uint32_t control2[0x100 / 4] = {};

private:
    bool ResolveKey(const bigmac_regs *ch, size_t key_bytes, uint8_t *out_key) const;

    bool ext_key_written = false;
    std::mt19937 rng{0xF00DC7A5u};
};
