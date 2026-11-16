#pragma once

#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>
#include <string>

static inline constexpr uint32_t GetBits(uint32_t x, unsigned off, unsigned len) {
	return (len >= 32) ? (x >> off) : ((x >> off) & ((1u << len) - 1u));
}

static inline constexpr uint32_t GetBit(uint32_t x, unsigned off) {
	return GetBits(x, off, 1);
}

static inline constexpr uint32_t SetBit(uint32_t x, unsigned off, uint32_t value) {
	return (x & ~(1u << off)) | ((value & 1u) << off);
}

static inline constexpr uint32_t SignExt(uint32_t value, unsigned from, unsigned to = 32) {
	(void)to;
	if (from == 0 || from >= 32)
		return value;
	unsigned shift = 32 - from;
	return static_cast<uint32_t>(static_cast<int32_t>(value << shift) >> shift);
}

void hex_dump(unsigned paddr, const uint8_t *addr, size_t size);
bool startswith(const std::string &haystack, const std::string &needle);
