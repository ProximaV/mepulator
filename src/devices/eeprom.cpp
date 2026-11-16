#include "eeprom.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "../log.h"

EEPROM::EEPROM() {
    Reset();
}

void EEPROM::Reset() {
    std::memset(memory, 0, sizeof(memory));
}

uint8_t EEPROM::Read8(uint32_t addr) {
    if (addr < kSize) {
        return memory[addr];
    }
    LOG_WARN("EEPROM::Read8 out of bounds addr 0x%08x", addr);
    return 0;
}

uint16_t EEPROM::Read16(uint32_t addr) {
    if (addr + 1 < kSize) {
        uint16_t val = 0;
        std::memcpy(&val, &memory[addr], sizeof(val));
        return val;
    }
    LOG_WARN("EEPROM::Read16 out of bounds addr 0x%08x", addr);
    return 0;
}

uint32_t EEPROM::Read32(uint32_t addr) {
    if (addr + 3 < kSize) {
        uint32_t val = 0;
        std::memcpy(&val, &memory[addr], sizeof(val));
        return val;
    }
    LOG_WARN("EEPROM::Read32 out of bounds addr 0x%08x", addr);
    return 0;
}

void EEPROM::Write32(uint32_t addr, uint32_t value) {
    LOG_WARN("EEPROM::Write32 direct write to [0x%08x] <= 0x%08x (use programmer 0xE0030000)", addr, value);
    if (addr + 3 < kSize) {
        std::memcpy(&memory[addr], &value, sizeof(value));
    }
}

bool EEPROM::Load(const char *path) {
    if (!path || !*path) {
        return false;
    }
    std::FILE *fp = std::fopen(path, "rb");
    if (!fp) {
        LOG_WARN("EEPROM::Load: optional eeprom file '%s' not found; using blank keyring", path);
        return false;
    }
    const size_t n = std::fread(memory, 1, sizeof(memory), fp);
    std::fclose(fp);
    LOG("Loaded %zu bytes into EEPROM keyring from '%s'", n, path);
    return true;
}

bool EEPROM::SetKeySlot(uint32_t slot, const uint8_t *key, size_t len) {
    if (slot >= kMaxSlots || !key) {
        return false;
    }
    const size_t n = std::min(len, static_cast<size_t>(kSlotBytes));
    std::memset(&memory[slot * kSlotBytes], 0, kSlotBytes);
    std::memcpy(&memory[slot * kSlotBytes], key, n);
    return true;
}

bool EEPROM::GetKeySlot(uint32_t slot, uint8_t *out, size_t len) const {
    if (slot >= kMaxSlots || !out) {
        return false;
    }
    const size_t n = std::min(len, static_cast<size_t>(kSlotBytes));
    std::memcpy(out, &memory[slot * kSlotBytes], n);
    return true;
}

EEPROMProgrammer::EEPROMProgrammer(EEPROM *eeprom_) : eeprom(eeprom_) {
    Reset();
}

void EEPROMProgrammer::Reset() {
    std::memset(state, 0, sizeof(state));
    slot_prot.clear();
}

uint32_t EEPROMProgrammer::Read32(uint32_t addr) {
    const uint32_t off = addr & 0xFFFu;
    if (off == 0x2C) {
        const uint32_t line = state[0x28 / 4];
        auto it = slot_prot.find(line);
        if (it != slot_prot.end()) {
            return it->second;
        }
        if (line == 0x501) {
            return 0x10000007u;
        }
        if (line >= 0x502 && line <= 0x515) {
            return 0x18000003u;
        }
        return 0xDEADu;
    }
    if (off == 0x04 || off == 0x20 || off == 0x24) {
        return 0; // Ready / idle status
    }
    if (off < sizeof(state)) {
        return state[off >> 2];
    }
    LOG_WARN("EEPROMProgrammer::Read32 unmapped addr 0x%x", off);
    return 0;
}

void EEPROMProgrammer::Write32(uint32_t addr, uint32_t value) {
    const uint32_t off = addr & 0xFFFu;
    if (off >= sizeof(state)) {
        LOG_WARN("EEPROMProgrammer::Write32 out of bounds addr 0x%x <= 0x%08x", off, value);
        return;
    }

    if (off <= 0x1C || off == 0x28) {
        state[off >> 2] = value;
    } else if (off == 0x20) {
        state[off >> 2] = value;
        if (eeprom && value < EEPROM::kMaxSlots) {
            eeprom->SetKeySlot(value, reinterpret_cast<const uint8_t *>(state), 0x20);
            LOG("EEPROMProgrammer::Write slot 0x%x", value);
        } else {
            LOG_ERR("EEPROMProgrammer::Write invalid slot 0x%x", value);
        }
    } else if (off == 0x24) {
        state[off >> 2] = value;
        const uint32_t line = state[0x28 / 4];
        slot_prot[line] = value;
        LOG("EEPROMProgrammer::SetProt slot 0x%x <= 0x%08x", line, value);
    } else {
        state[off >> 2] = value;
    }
}
