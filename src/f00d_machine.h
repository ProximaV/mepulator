#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#include "cpu.h"
#include "device.h"
#include "devices/armcomm.h"
#include "devices/bigmac.h"
#include "devices/e001device.h"
#include "devices/eeprom.h"
#include "devices/mathdev.h"
#include "devices/unknowndevice.h"

class IntcMmioDevice : public Device {
public:
    explicit IntcMmioDevice(Cpu *cpu_ = nullptr) : cpu(cpu_) {}
    void AttachCpu(Cpu *cpu_) { cpu = cpu_; }

    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

private:
    Cpu *cpu = nullptr;
    uint32_t extra_regs[16] = {};
};

class F00DMachine {
public:
    F00DMachine();

    // Initialize memory map, devices, and reset CPU to entry_pc.
    // Preserves EEPROM contents unless clear_eeprom is true.
    void Reset(uint32_t entry_pc = 0x00800000u,
               bool map_large_dram = true,
               bool clear_eeprom = false);

    // Ensure RAM exists for [addr, addr+sz) and write binary contents.
    bool LoadBytes(uint32_t addr, const void *data, size_t sz, const char *name = "CODE");
    bool LoadBinaryFile(uint32_t addr, const char *path, const char *name = "ROM");
    bool LoadEepromFile(const char *path);

    StopInfo Step(bool ignore_bpt_at_pc = false);
    StopInfo RunSteps(uint64_t max_steps,
                      bool ignore_bpt_at_first_pc = false,
                      const std::atomic<bool> *cancel = nullptr);

    std::string FormatStatus() const;

    Cpu cpu;
    EEPROM eeprom;
    EEPROMProgrammer keyring_ctrl;
    ARMComm armcomm;
    e001device e001;
    UnknownDevice sec_gate;
    Math math;
    Bigmac bigmac;
    UnknownDevice emmc_dev;
    UnknownDevice xbar_dev;
    IntcMmioDevice intc_mmio;
};
