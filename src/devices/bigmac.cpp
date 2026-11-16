#include "bigmac.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "mbedtls/aes.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"

#include "../cpu.h"
#include "../log.h"
#include "../memory.h"
#include "eeprom.h"

namespace {

inline void Byteswap(uint8_t *arr, size_t sz) {
    for (size_t i = 0; i < sz / 2; ++i) {
        std::swap(arr[i], arr[sz - i - 1]);
    }
}

bool AesEcbCrypt(uint8_t *data, size_t data_sz, const uint8_t *key, size_t key_bits, bool encrypt) {
    if ((key_bits != 128 && key_bits != 192 && key_bits != 256) || (data_sz & 0xFu) != 0) {
        LOG_ERR("Bigmac AES-ECB invalid key_bits=%zu data_sz=0x%zx", key_bits, data_sz);
        return false;
    }
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    const int key_rc = encrypt
        ? mbedtls_aes_setkey_enc(&ctx, key, static_cast<unsigned>(key_bits))
        : mbedtls_aes_setkey_dec(&ctx, key, static_cast<unsigned>(key_bits));
    if (key_rc != 0) {
        mbedtls_aes_free(&ctx);
        LOG_ERR("Bigmac AES-ECB setkey failed: %d", key_rc);
        return false;
    }

    const int mode = encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
    for (size_t off = 0; off < data_sz; off += 16) {
        uint8_t out_blk[16] = {};
        if (mbedtls_aes_crypt_ecb(&ctx, mode, data + off, out_blk) != 0) {
            mbedtls_aes_free(&ctx);
            LOG_ERR("Bigmac AES-ECB crypt failed at offset 0x%zx", off);
            return false;
        }
        std::memcpy(data + off, out_blk, 16);
    }
    mbedtls_aes_free(&ctx);
    return true;
}

bool AesCbcCrypt(uint8_t *data, size_t data_sz, const uint8_t *key, size_t key_bits, uint8_t *iv, bool encrypt) {
    if ((key_bits != 128 && key_bits != 192 && key_bits != 256) || (data_sz & 0xFu) != 0) {
        LOG_ERR("Bigmac AES-CBC invalid key_bits=%zu data_sz=0x%zx", key_bits, data_sz);
        return false;
    }
    if (data_sz == 0) {
        return true;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    const int key_rc = encrypt
        ? mbedtls_aes_setkey_enc(&ctx, key, static_cast<unsigned>(key_bits))
        : mbedtls_aes_setkey_dec(&ctx, key, static_cast<unsigned>(key_bits));
    if (key_rc != 0) {
        mbedtls_aes_free(&ctx);
        LOG_ERR("Bigmac AES-CBC setkey failed: %d", key_rc);
        return false;
    }

    std::vector<uint8_t> out(data_sz);
    const int mode = encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT;
    const int rc = mbedtls_aes_crypt_cbc(&ctx, mode, data_sz, iv, data, out.data());
    mbedtls_aes_free(&ctx);
    if (rc != 0) {
        LOG_ERR("Bigmac AES-CBC crypt failed: %d", rc);
        return false;
    }
    std::memcpy(data, out.data(), data_sz);
    return true;
}

bool AesCtrCrypt(uint8_t *data, size_t data_sz, const uint8_t *key, size_t key_bits, uint8_t *iv) {
    if (key_bits != 128 && key_bits != 192 && key_bits != 256) {
        LOG_ERR("Bigmac AES-CTR invalid key_bits=%zu", key_bits);
        return false;
    }
    if (data_sz == 0) {
        return true;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    if (mbedtls_aes_setkey_enc(&ctx, key, static_cast<unsigned>(key_bits)) != 0) {
        mbedtls_aes_free(&ctx);
        LOG_ERR("Bigmac AES-CTR setkey failed");
        return false;
    }

    size_t nc_off = 0;
    uint8_t counter[16];
    uint8_t stream_block[16] = {};
    std::memcpy(counter, iv, 16);
    Byteswap(counter, 16);

    std::vector<uint8_t> out(data_sz);
    const int rc = mbedtls_aes_crypt_ctr(&ctx, data_sz, &nc_off, counter, stream_block, data, out.data());
    mbedtls_aes_free(&ctx);
    if (rc != 0) {
        LOG_ERR("Bigmac AES-CTR crypt failed: %d", rc);
        return false;
    }

    Byteswap(counter, 16);
    std::memcpy(iv, counter, 16);
    std::memcpy(data, out.data(), data_sz);
    return true;
}

void ComputeHmacSha256(const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len, uint8_t output[32]) {
    uint8_t key_block[64] = {};
    if (key_len > 64) {
        mbedtls_sha256(key, key_len, key_block, 0);
    } else {
        std::memcpy(key_block, key, key_len);
    }

    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = key_block[i] ^ 0x36u;
        opad[i] = key_block[i] ^ 0x5cu;
    }

    uint8_t inner[32] = {};
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, ipad, 64);
    mbedtls_sha256_update(&ctx, data, data_len);
    mbedtls_sha256_finish(&ctx, inner);

    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, opad, 64);
    mbedtls_sha256_update(&ctx, inner, 32);
    mbedtls_sha256_finish(&ctx, output);

    mbedtls_sha256_free(&ctx);
}

void ComputeHmacSha1(const uint8_t *data, size_t data_len, const uint8_t *key, size_t key_len, uint8_t output[20]) {
    uint8_t key_block[64] = {};
    if (key_len > 64) {
        mbedtls_sha1(key, key_len, key_block);
    } else {
        std::memcpy(key_block, key, key_len);
    }

    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = key_block[i] ^ 0x36u;
        opad[i] = key_block[i] ^ 0x5cu;
    }

    uint8_t inner[20] = {};
    mbedtls_sha1_context ctx;
    mbedtls_sha1_init(&ctx);

    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, ipad, 64);
    mbedtls_sha1_update(&ctx, data, data_len);
    mbedtls_sha1_finish(&ctx, inner);

    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, opad, 64);
    mbedtls_sha1_update(&ctx, inner, 20);
    mbedtls_sha1_finish(&ctx, output);

    mbedtls_sha1_free(&ctx);
}

} // namespace

Bigmac::Bigmac(Memory *mem_, EEPROM *keyring_, Cpu *cpu_)
    : mem(mem_), keyring(keyring_), cpu(cpu_) {
    Reset();
}

void Bigmac::Reset() {
    std::memset(channels, 0, sizeof(channels));
    std::memset(control, 0, sizeof(control));
    std::memset(control2, 0, sizeof(control2));
    ext_key_written = false;
    rng.seed(0xF00DC7A5u);
}

bool Bigmac::ResolveKey(const bigmac_regs *ch, size_t key_bytes, uint8_t *out_key) const {
    const size_t n = std::min(key_bytes, static_cast<size_t>(32));
    const bool use_keyslot = ((ch->func & 0x400u) != 0) || (ch->keyslot != 0 && !ext_key_written && keyring != nullptr);
    if (use_keyslot && keyring) {
        return keyring->GetKeySlot(ch->keyslot, out_key, n);
    }
    std::memcpy(out_key, control2, n);
    return true;
}

uint32_t Bigmac::Read32(uint32_t addr) {
    addr &= 0xFFFu;
    if (addr == 0x3C) {
        return static_cast<uint32_t>(rng());
    }
    if (addr == 0x24) {
        return channels[0].busy;
    }
    if (addr >= 0x200 && addr < 0x300) {
        return control2[(addr - 0x200u) >> 2];
    }
    if (addr >= 0x100 && addr < 0x200) {
        const uint32_t ch_idx = (addr - 0x100u) / sizeof(bigmac_regs);
        const uint32_t reg_off = (addr - 0x100u) % sizeof(bigmac_regs);
        const uint8_t *base = reinterpret_cast<const uint8_t *>(&channels[ch_idx]);
        uint32_t val = 0;
        std::memcpy(&val, base + reg_off, sizeof(val));
        return val;
    }
    if (addr < sizeof(control)) {
        return control[addr >> 2];
    }
    LOG_WARN("Bigmac::Read32 unmapped addr 0x%03x", addr);
    return 0;
}

void Bigmac::Write32(uint32_t addr, uint32_t value) {
    addr &= 0xFFFu;
    if (addr >= 0x200 && addr < 0x300) {
        control2[(addr - 0x200u) >> 2] = value;
        ext_key_written = true;
        return;
    }

    if (addr >= 0x100 && addr < 0x200) {
        const int ch_idx = static_cast<int>((addr - 0x100u) / sizeof(bigmac_regs));
        const uint32_t reg_off = (addr - 0x100u) % sizeof(bigmac_regs);
        bigmac_regs *ch = &channels[ch_idx];
        std::memcpy(reinterpret_cast<uint8_t *>(ch) + reg_off, &value, sizeof(value));

        if (reg_off == 0x1C) { // commit
            ch->busy = 1;
            DoFunc(ch_idx);
            ch->busy = 0;
            ext_key_written = false;
        }
        return;
    }

    if (addr < sizeof(control)) {
        control[addr >> 2] = value;
        return;
    }
    LOG_WARN("Bigmac::Write32 unmapped addr 0x%03x <= 0x%08x", addr, value);
}

void Bigmac::DoFunc(int channel) {
    if (!mem || channel < 0 || channel > 1) {
        return;
    }
    bigmac_regs *ch = &channels[channel];
    const uint32_t op = ch->func & 0x3Fu;
    const uint32_t key_sel = (ch->func >> 8) & 3u;
    size_t key_bits = 128;
    if (key_sel == 2) key_bits = 192;
    else if (key_sel == 3) key_bits = 256;

    // Explicit legacy functions and decoded DMAC5 opcodes
    if (ch->func == 0 || ch->func == 0x2080 || op == 0x00) {
        if (ch->sz == 0) return;
        std::vector<uint8_t> data(ch->sz);
        if (mem->TryRead(ch->src, ch->sz, data.data())) {
            mem->TryWrite(ch->dst, ch->sz, data.data());
        }
        return;
    }

    if (ch->func == 0x0C || op == 0x0C) {
        if (ch->sz == 0) return;
        const uint8_t fill = static_cast<uint8_t>((control2[1] != 0 ? control2[1] : ch->src) & 0xFFu);
        std::vector<uint8_t> data(ch->sz, fill);
        mem->TryWrite(ch->dst, ch->sz, data.data());
        return;
    }

    if (op == 0x03) { // SHA-1
        std::vector<uint8_t> data(ch->sz);
        if (ch->sz == 0 || mem->TryRead(ch->src, ch->sz, data.data())) {
            uint8_t hash[20] = {};
            mbedtls_sha1(data.data(), ch->sz, hash);
            mem->TryWrite(ch->dst, sizeof(hash), hash);
        }
        return;
    }

    if (ch->func == 0x2093 || op == 0x13) { // SHA-256
        std::vector<uint8_t> data(ch->sz);
        if (ch->sz == 0 || mem->TryRead(ch->src, ch->sz, data.data())) {
            uint8_t hash[32] = {};
            mbedtls_sha256(data.data(), ch->sz, hash, 0);
            mem->TryWrite(ch->dst, sizeof(hash), hash);
        }
        return;
    }

    if (op == 0x23) { // HMAC-SHA1
        uint8_t key[32] = {};
        ResolveKey(ch, key_sel == 0 ? 32 : key_bits / 8, key);
        std::vector<uint8_t> data(ch->sz);
        if (ch->sz == 0 || mem->TryRead(ch->src, ch->sz, data.data())) {
            uint8_t digest[20] = {};
            ComputeHmacSha1(data.data(), ch->sz, key, key_sel == 0 ? 20 : key_bits / 8, digest);
            mem->TryWrite(ch->dst, sizeof(digest), digest);
        }
        return;
    }

    if (ch->func == 0x20b3 || op == 0x33) { // HMAC-SHA256
        uint8_t key[32] = {};
        const size_t klen = (key_sel == 0) ? 32 : (key_bits / 8);
        ResolveKey(ch, klen, key);
        std::vector<uint8_t> data(ch->sz);
        if (ch->sz == 0 || mem->TryRead(ch->src, ch->sz, data.data())) {
            uint8_t digest[32] = {};
            ComputeHmacSha256(data.data(), ch->sz, key, klen, digest);
            mem->TryWrite(ch->dst, sizeof(digest), digest);
        }
        return;
    }

    if (op == 0x01 || op == 0x09) { // AES-ECB enc/dec
        uint8_t key[32] = {};
        ResolveKey(ch, key_bits / 8, key);
        std::vector<uint8_t> data(ch->sz);
        if (mem->TryRead(ch->src, ch->sz, data.data())) {
            if (AesEcbCrypt(data.data(), ch->sz, key, key_bits, op == 0x01)) {
                mem->TryWrite(ch->dst, ch->sz, data.data());
            }
        }
        return;
    }

    if (ch->func == 0x218a || ch->func == 0x238a || op == 0x02 || op == 0x0A) { // AES-CBC enc/dec
        uint8_t key[32] = {};
        uint8_t iv[16] = {};
        ResolveKey(ch, key_bits / 8, key);
        if (ch->iv != 0) {
            mem->TryRead(ch->iv, sizeof(iv), iv);
        } else {
            std::memcpy(iv, reinterpret_cast<const uint8_t *>(control2) + 32, sizeof(iv));
        }
        std::vector<uint8_t> data(ch->sz);
        if (mem->TryRead(ch->src, ch->sz, data.data())) {
            if (AesCbcCrypt(data.data(), ch->sz, key, key_bits, iv, op == 0x02)) {
                if (ch->iv != 0) {
                    mem->TryWrite(ch->iv, sizeof(iv), iv);
                }
                mem->TryWrite(ch->dst, ch->sz, data.data());
            }
        }
        return;
    }

    if (ch->func == 0x21a1 || op == 0x21) { // AES-CTR
        uint8_t key[32] = {};
        uint8_t iv[16] = {};
        ResolveKey(ch, key_bits / 8, key);
        if (ch->iv != 0) {
            mem->TryRead(ch->iv, sizeof(iv), iv);
        } else {
            std::memcpy(iv, reinterpret_cast<const uint8_t *>(control2) + 32, sizeof(iv));
        }
        std::vector<uint8_t> data(ch->sz);
        if (mem->TryRead(ch->src, ch->sz, data.data())) {
            if (AesCtrCrypt(data.data(), ch->sz, key, key_bits, iv)) {
                if (ch->iv != 0) {
                    mem->TryWrite(ch->iv, sizeof(iv), iv);
                }
                mem->TryWrite(ch->dst, ch->sz, data.data());
            }
        }
        return;
    }

    LOG_WARN("Bigmac::DoFunc unknown func 0x%08x (ch=%d src=0x%08x dst=0x%08x sz=0x%x)",
             ch->func, channel, ch->src, ch->dst, ch->sz);
}
