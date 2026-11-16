#include "memory.h"

#include <algorithm>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cpu.h"
#include "log.h"

Memory::~Memory() {
	Clear();
}

void Memory::Clear() {
	for (auto &bank : banks) {
		if (bank.type == BankType::Memory && bank.buffer && bank.owns_buffer) {
			std::free(bank.buffer);
		}
		bank.buffer = nullptr;
	}
	banks.clear();
	watchpoints.clear();
	ClearFaults();
}

namespace {

bool RangesOverlap(uint64_t a_start, uint64_t a_end, uint64_t b_start, uint64_t b_end) {
	return a_start < b_end && b_start < a_end;
}

bool WatchpointMatchesAlias(uint64_t a_start, uint64_t a_end, uint64_t w_start, uint64_t w_end) {
	const uint64_t uncached_end = static_cast<uint64_t>(kSramUncachedBase) + kSramUncachedSize;
	const uint64_t cached_end = static_cast<uint64_t>(kSramCachedBase) + kSramUncachedSize;

	const uint64_t u_start = std::max<uint64_t>(w_start, kSramUncachedBase);
	const uint64_t u_end = std::min<uint64_t>(w_end, uncached_end);
	if (u_start < u_end && RangesOverlap(a_start, a_end, u_start + kSramRemapOffset, u_end + kSramRemapOffset)) {
		return true;
	}

	const uint64_t c_start = std::max<uint64_t>(w_start, kSramCachedBase);
	const uint64_t c_end = std::min<uint64_t>(w_end, cached_end);
	if (c_start < c_end && RangesOverlap(a_start, a_end, c_start - kSramRemapOffset, c_end - kSramRemapOffset)) {
		return true;
	}

	return false;
}

} // namespace

void Memory::CheckWatchpoints(uint32_t pa, uint32_t sz, bool is_write) {
	if (watchpoints.empty() || sz == 0)
		return;
	uint64_t a_start = pa;
	uint64_t a_end = a_start + sz;
	int needed = is_write ? 1 : 2;
	for (const auto &wp : watchpoints) {
		if ((wp.type & needed) == 0)
			continue;
		uint64_t w_start = wp.addr;
		uint64_t w_end = w_start + (wp.size ? wp.size : 1);
		if (RangesOverlap(a_start, a_end, w_start, w_end)) {
			watchpoint_hit = true;
			watchpoint_addr = wp.addr;
			watchpoint_is_write = is_write;
			return;
		}
	}
	for (const auto &wp : watchpoints) {
		if ((wp.type & needed) == 0)
			continue;
		uint64_t w_start = wp.addr;
		uint64_t w_end = w_start + (wp.size ? wp.size : 1);
		if (WatchpointMatchesAlias(a_start, a_end, w_start, w_end)) {
			watchpoint_hit = true;
			watchpoint_addr = wp.addr;
			watchpoint_is_write = is_write;
			return;
		}
	}
}

bool Memory::TryRead(uint32_t pa, uint32_t sz, void *dest, bool check_watchpoints) {
	if (sz == 0)
		return true;
	if (!dest)
		return false;

	if (check_watchpoints)
		CheckWatchpoints(pa, sz, false);

	MemoryBank *bank = GetBank(pa, sz);
	if (!bank) {
		// Try byte-by-byte across contiguous banks if a read spans adjacent banks
		uint8_t *out = static_cast<uint8_t *>(dest);
		for (uint32_t i = 0; i < sz; ++i) {
			MemoryBank *b = GetBank(pa + i, 1);
			if (!b) {
				std::memset(dest, 0, sz);
				return false;
			}
			if (b->type == BankType::Memory) {
				out[i] = static_cast<const uint8_t *>(b->buffer)[(pa + i) - b->pa];
			} else if (b->type == BankType::Device) {
				out[i] = b->device->Read8((pa + i) - b->pa);
			} else {
				std::memset(dest, 0, sz);
				return false;
			}
		}
		return true;
	}

	switch (bank->type) {
	case BankType::Memory:
		std::memcpy(dest, static_cast<const char *>(bank->buffer) + (pa - bank->pa), sz);
		return true;
	case BankType::Device: {
		uint32_t device_addr = pa - bank->pa;
		switch (sz) {
		case 1:
			*static_cast<uint8_t *>(dest) = bank->device->Read8(device_addr);
			return true;
		case 2:
			*static_cast<uint16_t *>(dest) = bank->device->Read16(device_addr);
			return true;
		case 4:
			*static_cast<uint32_t *>(dest) = bank->device->Read32(device_addr);
			return true;
		default: {
			// Support debugger memory window reads of arbitrary size on MMIO regions
			uint8_t *out = static_cast<uint8_t *>(dest);
			uint32_t off = 0;
			while (off + 4 <= sz && ((device_addr + off) & 3u) == 0) {
				uint32_t val = bank->device->Read32(device_addr + off);
				std::memcpy(out + off, &val, 4);
				off += 4;
			}
			while (off < sz) {
				out[off] = bank->device->Read8(device_addr + off);
				++off;
			}
			return true;
		}
		}
	}
	default:
		std::memset(dest, 0, sz);
		return false;
	}
}

bool Memory::TryWrite(uint32_t pa, uint32_t sz, const void *src, bool check_watchpoints) {
	if (sz == 0)
		return true;
	if (!src)
		return false;

	if (check_watchpoints)
		CheckWatchpoints(pa, sz, true);

	MemoryBank *bank = GetBank(pa, sz);
	if (!bank) {
		const uint8_t *in = static_cast<const uint8_t *>(src);
		for (uint32_t i = 0; i < sz; ++i) {
			MemoryBank *b = GetBank(pa + i, 1);
			if (!b)
				return false;
			if (b->type == BankType::Memory) {
				static_cast<uint8_t *>(b->buffer)[(pa + i) - b->pa] = in[i];
			} else if (b->type == BankType::Device) {
				b->device->Write8((pa + i) - b->pa, in[i]);
			} else {
				return false;
			}
		}
		return true;
	}

	switch (bank->type) {
	case BankType::Memory:
		std::memcpy(static_cast<char *>(bank->buffer) + (pa - bank->pa), src, sz);
		return true;
	case BankType::Device: {
		uint32_t device_addr = pa - bank->pa;
		switch (sz) {
		case 1:
			bank->device->Write8(device_addr, *static_cast<const uint8_t *>(src));
			return true;
		case 2:
			bank->device->Write16(device_addr, *static_cast<const uint16_t *>(src));
			return true;
		case 4:
			bank->device->Write32(device_addr, *static_cast<const uint32_t *>(src));
			return true;
		default: {
			const uint8_t *in = static_cast<const uint8_t *>(src);
			uint32_t off = 0;
			while (off + 4 <= sz && ((device_addr + off) & 3u) == 0) {
				uint32_t val = 0;
				std::memcpy(&val, in + off, 4);
				bank->device->Write32(device_addr + off, val);
				off += 4;
			}
			while (off < sz) {
				bank->device->Write8(device_addr + off, in[off]);
				++off;
			}
			return true;
		}
		}
	}
	default:
		return false;
	}
}

void Memory::Read(uint32_t pa, uint32_t sz, void *dest) {
	if (!TryRead(pa, sz, dest, true)) {
		unmapped_fault = true;
		fault_addr = pa;
		fault_is_write = false;
		LOG_ERR("failed to read 0x%08x size 0x%x\n", pa, sz);
	}
}

void Memory::Write(uint32_t pa, uint32_t sz, const void *src) {
	if (!TryWrite(pa, sz, src, true)) {
		unmapped_fault = true;
		fault_addr = pa;
		fault_is_write = true;
		LOG_ERR("failed to write 0x%08x size 0x%x\n", pa, sz);
	}
}

bool Memory::FetchInsn32(uint32_t pc, uint32_t *out) {
	*out = 0;
	if (TryRead(pc, 4, out, false))
		return true;
	uint16_t hw = 0;
	if (TryRead(pc, 2, &hw, false)) {
		*out = static_cast<uint32_t>(hw);
		return true;
	}
	unmapped_fault = true;
	fault_addr = pc;
	fault_is_write = false;
	return false;
}

MemoryBank *Memory::GetBank(uint32_t pa, uint32_t sz) {
	uint64_t req_start = pa;
	uint64_t req_end = req_start + sz;
	for (auto &bank : banks) {
		uint64_t bank_start = bank.pa;
		uint64_t bank_end = bank_start + bank.sz;
		if (bank_start <= req_start && bank_end >= req_end)
			return &bank;
	}
	return nullptr;
}

bool Memory::MapFile(uint32_t pa, uint32_t sz, const char *path, const char *name) {
	FILE *fin = fopen(path, "rb");
	if (!fin) {
		LOG_ERR("failed to open file '%s'\n", path);
		return false;
	}

	if (sz == 0) {
		fseek(fin, 0, SEEK_END);
		long file_len = ftell(fin);
		fseek(fin, 0, SEEK_SET);
		if (file_len <= 0) {
			fclose(fin);
			LOG_ERR("file '%s' is empty or unreadable\n", path);
			return false;
		}
		sz = static_cast<uint32_t>(file_len);
	}

	void *buf = std::calloc(1, sz);
	if (!buf) {
		fclose(fin);
		LOG_ERR("out of memory mapping %s (0x%x bytes)\n", path, sz);
		return false;
	}

	size_t nread = fread(buf, 1, sz, fin);
	fclose(fin);
	if (nread == 0) {
		std::free(buf);
		LOG_ERR("failed to read bytes from '%s'\n", path);
		return false;
	}

	MemoryBank *existing = GetBank(pa, sz);
	if (existing && existing->type == BankType::Memory) {
		std::memcpy(static_cast<char *>(existing->buffer) + (pa - existing->pa), buf, nread);
		std::free(buf);
		return true;
	}

	MemoryBank bank;
	bank.type = BankType::Memory;
	bank.pa = pa;
	bank.sz = sz;
	bank.buffer = buf;
	bank.name = name ? name : "ROM";
	bank.perm = MEM_PERM_RWX;
	banks.push_back(std::move(bank));
	return true;
}

void Memory::MapDevice(uint32_t pa, uint32_t sz, Device *device, const char *name, uint8_t perm) {
	MemoryBank bank;
	bank.type = BankType::Device;
	bank.pa = pa;
	bank.sz = sz;
	bank.device = device;
	bank.name = name ? name : "MMIO";
	bank.perm = perm;
	banks.push_back(std::move(bank));
}

void Memory::MapRam(uint32_t pa, uint32_t sz, const char *name, uint8_t perm) {
	if (sz == 0)
		return;
	void *buf = std::calloc(1, sz);
	if (!buf) {
		LOG_ERR("out of memory allocating RAM 0x%08x size 0x%x\n", pa, sz);
		return;
	}
	MemoryBank bank;
	bank.type = BankType::Memory;
	bank.pa = pa;
	bank.sz = sz;
	bank.buffer = buf;
	bank.owns_buffer = true;
	bank.name = name ? name : "RAM";
	bank.perm = perm;
	banks.push_back(std::move(bank));
}

bool Memory::MapAlias(uint32_t alias_pa, uint32_t target_pa, uint32_t sz, const char *name, uint8_t perm) {
	if (sz == 0)
		return false;
	MemoryBank *backing = GetBank(target_pa, sz);
	if (!backing || backing->type != BankType::Memory || !backing->buffer) {
		LOG_ERR("MapAlias failed: target 0x%08x size 0x%x has no RAM backing\n", target_pa, sz);
		return false;
	}
	MemoryBank alias;
	alias.type = BankType::Memory;
	alias.pa = alias_pa;
	alias.sz = sz;
	alias.buffer = static_cast<uint8_t *>(backing->buffer) + (target_pa - backing->pa);
	alias.owns_buffer = false;
	alias.name = name ? name : "ALIAS";
	alias.perm = perm;
	banks.push_back(std::move(alias));
	return true;
}

void Memory::EnsureRamRange(uint32_t pa, uint32_t sz, const char *name, uint8_t perm) {
	if (sz == 0)
		return;
	// If already completely covered by a single bank, nothing to do.
	if (GetBank(pa, sz) != nullptr)
		return;

	// Find uncovered subranges [cur, end)
	uint64_t start = pa;
	uint64_t end = start + sz;
	std::vector<std::pair<uint64_t, uint64_t>> covered;
	for (const auto &b : banks) {
		uint64_t bs = b.pa;
		uint64_t be = bs + b.sz;
		uint64_t os = std::max(start, bs);
		uint64_t oe = std::min(end, be);
		if (os < oe)
			covered.emplace_back(os, oe);
	}
	std::sort(covered.begin(), covered.end());
	uint64_t cur = start;
	for (const auto &c : covered) {
		if (cur < c.first) {
			MapRam(static_cast<uint32_t>(cur), static_cast<uint32_t>(c.first - cur), name, perm);
		}
		if (cur < c.second)
			cur = c.second;
	}
	if (cur < end) {
		MapRam(static_cast<uint32_t>(cur), static_cast<uint32_t>(end - cur), name, perm);
	}
}

std::vector<MemoryRegion> Memory::GetRegions() const {
	std::vector<MemoryRegion> regions;
	regions.reserve(banks.size());
	for (const auto &b : banks) {
		MemoryRegion r;
		r.start = b.pa;
		r.size = b.sz;
		r.name = b.name;
		r.is_device = (b.type == BankType::Device);
		r.perm = b.perm;
		regions.push_back(std::move(r));
	}
	std::sort(regions.begin(), regions.end(), [](const MemoryRegion &a, const MemoryRegion &b) {
		return a.start < b.start;
	});
	return regions;
}

void Memory::AddWatchpoint(uint32_t addr, uint32_t size, int type) {
	uint32_t norm_sz = size ? size : 1;
	for (auto &wp : watchpoints) {
		if (wp.addr == addr && wp.size == norm_sz) {
			wp.type |= type;
			return;
		}
	}
	watchpoints.push_back({ addr, norm_sz, type });
}

void Memory::RemoveWatchpoint(uint32_t addr, uint32_t size, int type) {
	uint32_t norm_sz = size ? size : 1;
	for (auto it = watchpoints.begin(); it != watchpoints.end();) {
		if (it->addr == addr && (size == 0 || it->size == norm_sz)) {
			it->type &= ~type;
			if (it->type == 0) {
				it = watchpoints.erase(it);
				continue;
			}
		}
		++it;
	}
}

void Memory::ClearWatchpoints() {
	watchpoints.clear();
}
