#include "device.h"
#include "log.h"

uint8_t Device::Read8(uint32_t addr) {
	uint32_t aligned = Read32(addr & ~3u);
	return static_cast<uint8_t>((aligned >> ((addr & 3u) * 8)) & 0xFFu);
}

uint16_t Device::Read16(uint32_t addr) {
	uint32_t aligned = Read32(addr & ~3u);
	return static_cast<uint16_t>((aligned >> ((addr & 2u) * 8)) & 0xFFFFu);
}

uint32_t Device::Read32(uint32_t addr) {
	LOG_ERR("device does not support Read32(0x%x)\n", addr);
	return 0;
}

void Device::Write8(uint32_t addr, uint8_t value) {
	uint32_t aligned_addr = addr & ~3u;
	uint32_t shift = (addr & 3u) * 8;
	uint32_t word = Read32(aligned_addr);
	word = (word & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift);
	Write32(aligned_addr, word);
}

void Device::Write16(uint32_t addr, uint16_t value) {
	uint32_t aligned_addr = addr & ~3u;
	uint32_t shift = (addr & 2u) * 8;
	uint32_t word = Read32(aligned_addr);
	word = (word & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(value) << shift);
	Write32(aligned_addr, word);
}

void Device::Write32(uint32_t addr, uint32_t value) {
	LOG_ERR("device does not support Write32(0x%x, 0x%x)\n", addr, value);
}
