#include "insn.h"

#include <algorithm>
#include <cstdint>
#include <limits>

#include "cpu.h"
#include "log.h"
#include "util.h"

namespace {

template <typename T>
inline uint32_t LoadImpl(Cpu *cpu, uint32_t addr) {
    T val = 0;
    cpu->mem.Read(addr, sizeof(T), &val);
    cpu->CheckDsuDataBreak(addr, sizeof(T), static_cast<uint32_t>(val), false);
    return static_cast<uint32_t>(val);
}

template <typename T>
inline void StoreImpl(Cpu *cpu, uint32_t val, uint32_t addr) {
    const T v = static_cast<T>(val);
    cpu->mem.Write(addr, sizeof(T), &v);
    cpu->CheckDsuDataBreak(addr, sizeof(T), static_cast<uint32_t>(v), true);
}

inline uint32_t Load1Impl(Cpu *cpu, uint32_t addr) { return LoadImpl<uint8_t>(cpu, addr); }
inline uint32_t Load2Impl(Cpu *cpu, uint32_t addr) { return LoadImpl<uint16_t>(cpu, addr); }
inline uint32_t Load4Impl(Cpu *cpu, uint32_t addr) { return LoadImpl<uint32_t>(cpu, addr); }
inline void Store1ValAddr(Cpu *cpu, uint32_t val, uint32_t addr) { StoreImpl<uint8_t>(cpu, val, addr); }
inline void Store2ValAddr(Cpu *cpu, uint32_t val, uint32_t addr) { StoreImpl<uint16_t>(cpu, val, addr); }
inline void Store4ValAddr(Cpu *cpu, uint32_t val, uint32_t addr) { StoreImpl<uint32_t>(cpu, val, addr); }

inline void DoBranch(Cpu *cpu, uint32_t newpc) {
    const uint32_t target = newpc & ~1u;
    CRN(pc) = target;
    cpu->branched = true;
    if (cpu->IsRepeatActive() && !cpu->InActiveRepeatRange(target)) {
        cpu->CancelRepeat();
    }
}

inline uint32_t CountLeadingZeros32(uint32_t v) {
    if (v == 0) {
        return 32;
    }
    uint32_t n = 0;
    for (uint32_t bit = 0x80000000u; bit != 0; bit >>= 1) {
        if ((v & bit) != 0) {
            break;
        }
        ++n;
    }
    return n;
}

inline uint32_t SaturateSigned32(int64_t v) {
    if (v > INT32_MAX) {
        return static_cast<uint32_t>(INT32_MAX);
    }
    if (v < INT32_MIN) {
        return static_cast<uint32_t>(INT32_MIN);
    }
    return static_cast<uint32_t>(static_cast<int32_t>(v));
}

inline uint32_t ClipSigned(int32_t v, uint32_t bits) {
    if (bits == 0) {
        return 0;
    }
    if (bits >= 32) {
        return static_cast<uint32_t>(v);
    }
    const int64_t hi = (int64_t{1} << (bits - 1)) - 1;
    const int64_t lo = -(int64_t{1} << (bits - 1));
    int64_t val = v;
    if (val > hi) {
        val = hi;
    } else if (val < lo) {
        val = lo;
    }
    return static_cast<uint32_t>(static_cast<int32_t>(val));
}

inline uint32_t ClipUnsigned(int32_t v, uint32_t bits) {
    if (bits == 0 || v < 0) {
        return 0;
    }
    if (bits >= 32) {
        return static_cast<uint32_t>(v);
    }
    const uint64_t hi = (uint64_t{1} << bits) - 1;
    const uint64_t val = static_cast<uint32_t>(v);
    return static_cast<uint32_t>(val > hi ? hi : val);
}

inline uint32_t AbsDiffS32(int32_t a, int32_t b) {
    int64_t diff = static_cast<int64_t>(a) - static_cast<int64_t>(b);
    if (diff < 0) {
        diff = -diff;
    }
    return static_cast<uint32_t>(diff);
}

inline uint32_t AveS32(int32_t a, int32_t b) {
    const int64_t sum = static_cast<int64_t>(a) + static_cast<int64_t>(b) + 1;
    return static_cast<uint32_t>(sum >> 1);
}

} // namespace

#define Load1(addr) Load1Impl(cpu, (addr))
#define Load2(addr) Load2Impl(cpu, (addr))
#define Load4(addr) Load4Impl(cpu, (addr))
#define Store1(val, addr) Store1ValAddr(cpu, (val), (addr))
#define Store2(val, addr) Store2ValAddr(cpu, (val), (addr))
#define Store4(val, addr) Store4ValAddr(cpu, (val), (addr))
#define BRA(addr) DoBranch(cpu, (addr))
#define INSN(name) static void name(Cpu *cpu, uint32_t insn)

#include "insn_gen.cpp"

const insn_t *decode_insn(uint32_t raw) {
    const uint32_t count = static_cast<uint32_t>(sizeof(insn_table) / sizeof(insn_table[0]));
    for (uint32_t i = 0; i < count; ++i) {
        if ((raw & insn_table[i].mask) == insn_table[i].match) {
            return &insn_table[i];
        }
    }
    return nullptr;
}

uint32_t insn_table_size() {
    return static_cast<uint32_t>(sizeof(insn_table) / sizeof(insn_table[0]));
}
