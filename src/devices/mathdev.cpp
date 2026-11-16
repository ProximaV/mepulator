#include "mathdev.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "mbedtls/bignum.h"

#include "../cpu.h"
#include "../log.h"

namespace {

inline void ReverseBytes(uint8_t *arr, size_t sz) {
    for (size_t i = 0; i < sz / 2; ++i) {
        std::swap(arr[i], arr[sz - i - 1]);
    }
}

} // namespace

Math::Math(Cpu *cpu_) : cpu(cpu_) {
    Reset();
}

void Math::Reset() {
    flags = 0;
    std::memset(ram, 0, sizeof(ram));
    exponent = 0;
    cmd = 0;
}

uint32_t Math::Read32(uint32_t addr) {
    addr &= 0xFFFu;
    if (addr == 0x800) {
        return 0; // Idle
    }
    if (addr == 0x804) {
        return flags;
    }
    if (addr == 0x808) {
        return exponent;
    }
    if (addr + 3 < sizeof(ram)) {
        uint32_t val = 0;
        std::memcpy(&val, &ram[addr], sizeof(val));
        return val;
    }
    LOG_WARN("Math::Read32 unmapped offset 0x%03x", addr);
    return 0;
}

void Math::Write32(uint32_t addr, uint32_t value) {
    addr &= 0xFFFu;
    if (addr == 0x800) {
        cmd = value;
        flags = 0x4000000u;
        PowMod();
        return;
    }
    if (addr == 0x808) {
        exponent = value;
        return;
    }
    if (addr + 3 < sizeof(ram)) {
        std::memcpy(&ram[addr], &value, sizeof(value));
        return;
    }
    LOG_WARN("Math::Write32 unmapped offset 0x%03x <= 0x%08x", addr, value);
}

void Math::PowMod() {
    if ((cmd >> 27) != 0x12) {
        LOG_WARN("Math::PowMod unsupported cmd=0x%08x", cmd);
        flags = 0;
        return;
    }

    const uint32_t mod_size_words = (cmd & 0x3FC0000u) >> 18;
    const uint32_t exp_size_words = (cmd & 0x3FE00u) >> 9;

    if (mod_size_words == 0 || mod_size_words > 0x40 || exp_size_words == 0 || exp_size_words > 0x40) {
        LOG_ERR("Math::PowMod invalid size mod_words=0x%x exp_words=0x%x", mod_size_words, exp_size_words);
        flags = 0;
        return;
    }

    const size_t mod_bytes = static_cast<size_t>(mod_size_words) * 4;
    const size_t exp_bytes = static_cast<size_t>(exp_size_words) * 4;

    if (0x400 + mod_bytes > sizeof(ram) || 0x108 + mod_bytes > sizeof(ram) || 0x508 + mod_bytes > sizeof(ram)) {
        LOG_ERR("Math::PowMod buffer range exceeded for mod_bytes=0x%zx", mod_bytes);
        flags = 0;
        return;
    }

    std::vector<uint8_t> be_mod(mod_bytes);
    std::vector<uint8_t> be_sig(mod_bytes);
    std::vector<uint8_t> be_res(mod_bytes);
    std::vector<uint8_t> be_exp(exp_bytes);

    std::memcpy(be_mod.data(), &ram[0x400], mod_bytes);
    std::memcpy(be_sig.data(), &ram[0x108], mod_bytes);
    ReverseBytes(be_mod.data(), mod_bytes);
    ReverseBytes(be_sig.data(), mod_bytes);

    if (exp_size_words == 1) {
        std::memcpy(be_exp.data(), &exponent, 4);
        ReverseBytes(be_exp.data(), 4);
    } else {
        std::memcpy(be_exp.data(), &ram[0x300], exp_bytes);
        ReverseBytes(be_exp.data(), exp_bytes);
    }

    mbedtls_mpi n_mod, n_exp, n_sig, n_res;
    mbedtls_mpi_init(&n_mod);
    mbedtls_mpi_init(&n_exp);
    mbedtls_mpi_init(&n_sig);
    mbedtls_mpi_init(&n_res);

    int rc = mbedtls_mpi_read_binary(&n_mod, be_mod.data(), mod_bytes);
    if (rc == 0) rc = mbedtls_mpi_read_binary(&n_sig, be_sig.data(), mod_bytes);
    if (rc == 0) rc = mbedtls_mpi_read_binary(&n_exp, be_exp.data(), exp_bytes);
    if (rc == 0) rc = mbedtls_mpi_exp_mod(&n_res, &n_sig, &n_exp, &n_mod, nullptr);
    if (rc == 0) rc = mbedtls_mpi_write_binary(&n_res, be_res.data(), mod_bytes);

    mbedtls_mpi_free(&n_mod);
    mbedtls_mpi_free(&n_exp);
    mbedtls_mpi_free(&n_sig);
    mbedtls_mpi_free(&n_res);

    if (rc != 0) {
        LOG_ERR("Math::PowMod mbedtls failed: -0x%04x", static_cast<unsigned>(-rc));
        flags = 0;
        return;
    }

    ReverseBytes(be_res.data(), mod_bytes);
    std::memcpy(&ram[0x508], be_res.data(), mod_bytes);
    flags = mod_size_words << 16;

    if (cpu) {
        cpu->RaiseIrq(9);
    }
}
