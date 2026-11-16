#pragma once

#include <inttypes.h>
#include <stdint.h>
#include <string>
#include <vector>

#include "device.h"

enum class BankType {
	Undefined,
	Memory,
	Device
};

enum MemPerm : uint8_t {
	MEM_PERM_READ  = 1,
	MEM_PERM_WRITE = 2,
	MEM_PERM_EXEC  = 4,
	MEM_PERM_RW    = 3,
	MEM_PERM_RX    = 5,
	MEM_PERM_RWX   = 7,
};

struct MemoryBank {
	uint32_t pa = 0;
	uint32_t sz = 0;
	BankType type = BankType::Undefined;
	void *buffer = nullptr;
	bool owns_buffer = true;
	Device *device = nullptr;
	std::string name;
	uint8_t perm = MEM_PERM_RWX;
};

struct MemoryRegion {
	uint32_t start = 0;
	uint32_t size = 0;
	std::string name;
	bool is_device = false;
	uint8_t perm = MEM_PERM_RWX;
};

struct Watchpoint {
	uint32_t addr = 0;
	uint32_t size = 1;
	int type = 0; // bit 0 (1) = write, bit 1 (2) = read, 3 = read/write
};

struct Memory {
	Memory() = default;
	~Memory();

	Memory(const Memory &) = delete;
	Memory &operator=(const Memory &) = delete;

	void Clear();

	bool TryRead(uint32_t pa, uint32_t sz, void *dest, bool check_watchpoints = false);
	bool TryWrite(uint32_t pa, uint32_t sz, const void *src, bool check_watchpoints = false);

	void Read(uint32_t pa, uint32_t sz, void *dest);
	void Write(uint32_t pa, uint32_t sz, const void *src);

	// Reads 4 bytes for instruction decode, gracefully falling back to 2 bytes at segment end.
	bool FetchInsn32(uint32_t pc, uint32_t *out);

	bool MapFile(uint32_t pa, uint32_t sz, const char *path, const char *name = "ROM");
	void MapDevice(uint32_t pa, uint32_t sz, Device *device, const char *name = "MMIO", uint8_t perm = MEM_PERM_RW);
	void MapRam(uint32_t pa, uint32_t sz, const char *name = "RAM", uint8_t perm = MEM_PERM_RWX);
	bool MapAlias(uint32_t alias_pa, uint32_t target_pa, uint32_t sz, const char *name = "ALIAS", uint8_t perm = MEM_PERM_RWX);
	void EnsureRamRange(uint32_t pa, uint32_t sz, const char *name = "RAM", uint8_t perm = MEM_PERM_RWX);

	std::vector<MemoryRegion> GetRegions() const;

	void AddWatchpoint(uint32_t addr, uint32_t size, int type);
	void RemoveWatchpoint(uint32_t addr, uint32_t size, int type);
	void ClearWatchpoints();

	void ClearFaults() {
		unmapped_fault = false;
		fault_addr = 0;
		fault_is_write = false;
		watchpoint_hit = false;
		watchpoint_addr = 0;
		watchpoint_is_write = false;
	}

	bool unmapped_fault = false;
	uint32_t fault_addr = 0;
	bool fault_is_write = false;

	bool watchpoint_hit = false;
	uint32_t watchpoint_addr = 0;
	bool watchpoint_is_write = false;

private:
	MemoryBank *GetBank(uint32_t pa, uint32_t sz);
	void CheckWatchpoints(uint32_t pa, uint32_t sz, bool is_write);

	std::vector<MemoryBank> banks;
	std::vector<Watchpoint> watchpoints;
};
