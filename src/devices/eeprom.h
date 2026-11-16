#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include "../device.h"

class EEPROMProgrammer;

class EEPROM : public Device {
public:
    static constexpr uint32_t kSize = 0x10000;
    static constexpr uint32_t kSlotBytes = 32;
    static constexpr uint32_t kMaxSlots = kSize / kSlotBytes;

    EEPROM();
    void Reset();

    uint8_t Read8(uint32_t addr) override;
    uint16_t Read16(uint32_t addr) override;
    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

    bool Load(const char *path);

    // Programmatic keyslot helpers (each slot is 32 bytes)
    bool SetKeySlot(uint32_t slot, const uint8_t *key, size_t len);
    bool GetKeySlot(uint32_t slot, uint8_t *out, size_t len) const;

    uint8_t memory[kSize] = {};

private:
    friend class EEPROMProgrammer;
};

class EEPROMProgrammer : public Device {
public:
    explicit EEPROMProgrammer(EEPROM *eeprom_);
    void Reset();

    uint32_t Read32(uint32_t addr) override;
    void Write32(uint32_t addr, uint32_t value) override;

    EEPROM *eeprom = nullptr;
    uint32_t state[0x40 / 4] = {};
    std::unordered_map<uint32_t, uint32_t> slot_prot;
};
