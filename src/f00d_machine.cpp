#include "f00d_machine.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

#include "log.h"

uint32_t IntcMmioDevice::Read32(uint32_t addr) {
    const uint32_t off = addr & 0xFFFu;
    if (cpu && off < 0x20) {
        return cpu->GetIntc(off >> 2);
    }
    if ((off >> 2) < 16) {
        return extra_regs[off >> 2];
    }
    return 0;
}

void IntcMmioDevice::Write32(uint32_t addr, uint32_t value) {
    const uint32_t off = addr & 0xFFFu;
    if (cpu && off < 0x20) {
        cpu->SetIntc(off >> 2, value);
        return;
    }
    if ((off >> 2) < 16) {
        extra_regs[off >> 2] = value;
    }
}

F00DMachine::F00DMachine()
    : keyring_ctrl(&eeprom),
      armcomm(&cpu),
      sec_gate(0xE0020000u, &eeprom),
      math(&cpu),
      bigmac(&cpu.mem, &eeprom, &cpu),
      emmc_dev(0xE0070000u),
      xbar_dev(0xE00C0000u),
      intc_mmio(&cpu) {
    Reset(0x00800000u, true, true);
}

void F00DMachine::Reset(uint32_t entry_pc, bool map_large_dram, bool clear_eeprom) {
    cpu.mem.Clear();
    if (clear_eeprom) {
        eeprom.Reset();
    }
    keyring_ctrl.Reset();
    armcomm.Reset();
    e001.Reset();
    sec_gate.Reset();
    math.Reset();
    bigmac.Reset();
    emmc_dev.Reset();
    xbar_dev.Reset();

    // Standard PS Vita F00D RAM regions & uncached startup mirror (0x00040000 <-> 0x00800000)
    cpu.mem.MapRam(0x00000000u, 0x00040000u, "BOOTROM_LOW", MEM_PERM_RWX);
    cpu.mem.MapRam(kSramCachedBase, 0x00200000u, "CMEP_SRAM", MEM_PERM_RWX);
    cpu.mem.MapAlias(kSramUncachedBase, kSramCachedBase, kSramUncachedSize, "CMEP_SRAM_UNCACHED", MEM_PERM_RWX);
    cpu.mem.MapRam(0x00300000u, 0x00010000u, "CMEP_ICACHE", MEM_PERM_RW);
    cpu.mem.MapRam(0x00310000u, 0x00010000u, "CMEP_ICACHE_TAG", MEM_PERM_RW);
    cpu.mem.MapRam(0x00320000u, 0x00010000u, "CMEP_DCACHE", MEM_PERM_RW);
    cpu.mem.MapRam(0x00330000u, 0x00010000u, "CMEP_DCACHE_TAG", MEM_PERM_RW);
    cpu.mem.MapRam(0x40000000u, 0x00200000u, "SECURE_RAM", MEM_PERM_RWX);
    if (map_large_dram) {
        cpu.mem.MapRam(0x50000000u, 0x02000000u, "NONSEC_DRAM", MEM_PERM_RWX);
    }

    // MMIO peripherals
    const uint8_t mmio_perm = MEM_PERM_READ | MEM_PERM_WRITE;
    cpu.mem.MapDevice(0xE0000000u, 0x1000u, &armcomm, "MAILBOX", mmio_perm);
    cpu.mem.MapDevice(0xE0010000u, 0x1000u, &e001, "SYS_E001", mmio_perm);
    cpu.mem.MapDevice(0xE0020000u, 0x1000u, &sec_gate, "SEC_GATE", mmio_perm);
    cpu.mem.MapDevice(0xE0030000u, 0x1000u, &keyring_ctrl, "KEYRING_CTRL", mmio_perm);
    cpu.mem.MapDevice(0xE0040000u, 0x1000u, &math, "BIGNUM", mmio_perm);
    cpu.mem.MapDevice(0xE0050000u, 0x1000u, &bigmac, "DMAC5_BIGMAC", mmio_perm);
    cpu.mem.MapDevice(0xE0058000u, EEPROM::kSize, &eeprom, "KEYRING_EEPROM", mmio_perm);
    cpu.mem.MapDevice(0xE0070000u, 0x1000u, &emmc_dev, "EMMC_MISC", mmio_perm);
    cpu.mem.MapDevice(0xE00C0000u, 0x1000u, &xbar_dev, "XBAR_CLK", mmio_perm);
    cpu.mem.MapDevice(0xE04E0000u, 0x1000u, &bigmac, "DMAC5_MIRROR", mmio_perm);
    cpu.mem.MapDevice(0xE3000000u, 0x1000u, &intc_mmio, "INTC_MMIO", mmio_perm);

    cpu.Reset(entry_pc);
}

bool F00DMachine::LoadBytes(uint32_t addr, const void *data, size_t sz, const char *name) {
    if (!data || sz == 0) {
        return false;
    }
    const uint32_t u32_sz = static_cast<uint32_t>(std::min<size_t>(sz, 0x10000000u));
    cpu.mem.EnsureRamRange(addr, u32_sz, name, MEM_PERM_RWX);
    return cpu.mem.TryWrite(addr, u32_sz, data, false);
}

bool F00DMachine::LoadBinaryFile(uint32_t addr, const char *path, const char *name) {
    if (!path || !*path) {
        return false;
    }
    std::FILE *fp = std::fopen(path, "rb");
    if (!fp) {
        LOG_ERR("F00DMachine::LoadBinaryFile failed to open '%s'", path);
        return false;
    }
    std::fseek(fp, 0, SEEK_END);
    const long fsz = std::ftell(fp);
    std::fseek(fp, 0, SEEK_SET);
    if (fsz <= 0) {
        std::fclose(fp);
        LOG_ERR("F00DMachine::LoadBinaryFile empty file '%s'", path);
        return false;
    }

    std::vector<uint8_t> buf(static_cast<size_t>(fsz));
    const size_t nread = std::fread(buf.data(), 1, buf.size(), fp);
    std::fclose(fp);
    if (nread == 0) {
        return false;
    }
    return LoadBytes(addr, buf.data(), nread, name);
}

bool F00DMachine::LoadEepromFile(const char *path) {
    return eeprom.Load(path);
}

StopInfo F00DMachine::Step(bool ignore_bpt_at_pc) {
    return cpu.Step(ignore_bpt_at_pc);
}

StopInfo F00DMachine::RunSteps(uint64_t max_steps,
                               bool ignore_bpt_at_first_pc,
                               const std::atomic<bool> *cancel) {
    StopInfo info;
    for (uint64_t i = 0; max_steps == 0 || i < max_steps; ++i) {
        if (cancel && cancel->load()) {
            return StopInfo{StopReason::None, cpu.control.pc & ~1u, 0, false};
        }
        info = cpu.Step(i == 0 && ignore_bpt_at_first_pc);
        if (info.reason != StopReason::None) {
            return info;
        }
    }
    return info;
}

std::string F00DMachine::FormatStatus() const {
    char buf[512];
    std::snprintf(
        buf, sizeof(buf),
        "PC=0x%08X SP=0x%08X LP=0x%08X TP=0x%08X GP=0x%08X PSW=0x%08X\n"
        "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X EPC=0x%08X EXC=0x%08X\n"
        "INTC IVB=0x%08X ISR=0x%08X IER=0x%08X IET=0x%08X steps=%llu%s",
        cpu.control.pc, cpu.r[MEP_REG_sp], cpu.control.lp, cpu.r[MEP_REG_tp],
        cpu.r[MEP_REG_gp], cpu.control.psw,
        cpu.r[0], cpu.r[1], cpu.r[2], cpu.r[3], cpu.control.epc, cpu.control.exc,
        cpu.intc.ivb, cpu.intc.isr, cpu.intc.ier, cpu.intc.iet,
        static_cast<unsigned long long>(cpu.step_count),
        cpu.sleeping ? " [SLEEPING]" : "");
    return std::string(buf);
}
