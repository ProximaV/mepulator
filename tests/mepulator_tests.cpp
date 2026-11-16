#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "cpu.h"
#include "debugger.h"
#include "f00d_machine.h"
#include "insn.h"
#include "log.h"

namespace {

int g_failures = 0;

#define CHECK(cond)                                                              \
    do {                                                                         \
        if (!(cond)) {                                                           \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            ++g_failures;                                                        \
        }                                                                        \
    } while (0)

#define CHECK_EQ(a, b)                                                                 \
    do {                                                                               \
        const auto _va = static_cast<uint64_t>(a);                                     \
        const auto _vb = static_cast<uint64_t>(b);                                     \
        if (_va != _vb) {                                                              \
            std::fprintf(stderr, "FAIL %s:%d: %s (0x%llx) != %s (0x%llx)\n",           \
                         __FILE__, __LINE__, #a, static_cast<unsigned long long>(_va), \
                         #b, static_cast<unsigned long long>(_vb));                    \
            ++g_failures;                                                              \
        }                                                                              \
    } while (0)

#define CHECK_STREQ(a, b)                                                          \
    do {                                                                           \
        const std::string _sa(a);                                                  \
        const std::string _sb(b);                                                  \
        if (_sa != _sb) {                                                          \
            std::fprintf(stderr, "FAIL %s:%d: %s ('%s') != %s ('%s')\n",           \
                         __FILE__, __LINE__, #a, _sa.c_str(), #b, _sb.c_str());    \
            ++g_failures;                                                          \
        }                                                                          \
    } while (0)

void Write16(Memory &mem, uint32_t addr, uint16_t val) {
    CHECK(mem.TryWrite(addr, sizeof(val), &val, false));
}

void Write32(Memory &mem, uint32_t addr, uint32_t val) {
    CHECK(mem.TryWrite(addr, sizeof(val), &val, false));
}

uint32_t Read32(Memory &mem, uint32_t addr) {
    uint32_t v = 0;
    CHECK(mem.TryRead(addr, sizeof(v), &v, false));
    return v;
}

uint16_t Read16(Memory &mem, uint32_t addr) {
    uint16_t v = 0;
    CHECK(mem.TryRead(addr, sizeof(v), &v, false));
    return v;
}

uint8_t Read8(Memory &mem, uint32_t addr) {
    uint8_t v = 0;
    CHECK(mem.TryRead(addr, sizeof(v), &v, false));
    return v;
}

void WriteInsn16(Memory &mem, uint32_t addr, uint16_t hw0) {
    Write16(mem, addr, hw0);
}

void WriteInsn32(Memory &mem, uint32_t addr, uint16_t hw0, uint16_t hw1) {
    Write16(mem, addr, hw0);
    Write16(mem, addr + 2, hw1);
}

void EmitAndCheck16(Memory &mem, uint32_t addr, uint16_t hw0) {
    const insn_t *d = decode_insn(hw0);
    CHECK(d != nullptr);
    if (d) {
        CHECK_EQ(d->sz, 2u);
    }
    WriteInsn16(mem, addr, hw0);
}

void EmitAndCheck32(Memory &mem, uint32_t addr, uint16_t hw0, uint16_t hw1) {
    const uint32_t raw = static_cast<uint32_t>(hw0) | (static_cast<uint32_t>(hw1) << 16);
    const insn_t *d = decode_insn(raw);
    CHECK(d != nullptr);
    if (d) {
        CHECK_EQ(d->sz, 4u);
    }
    WriteInsn32(mem, addr, hw0, hw1);
}

// 16-bit MeP instruction encoders (matching src/insn.in)
constexpr uint16_t EncMovi8(uint8_t rn, int8_t imm8) {
    return static_cast<uint16_t>(0x5000u | ((rn & 0xFu) << 8) | static_cast<uint8_t>(imm8));
}
constexpr uint16_t EncAddImm6(uint8_t rn, int8_t imm6) {
    return static_cast<uint16_t>(0x6000u | ((rn & 0xFu) << 8) | ((imm6 & 0x3F) << 2));
}
constexpr uint16_t EncExth(uint8_t rn) { return static_cast<uint16_t>(0x102Du | ((rn & 0xFu) << 8)); }
constexpr uint16_t EncExtuh(uint8_t rn) { return static_cast<uint16_t>(0x10ADu | ((rn & 0xFu) << 8)); }
constexpr uint16_t EncSsarb(uint8_t i2, uint8_t rm) {
    return static_cast<uint16_t>(0x100Cu | ((i2 & 3u) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncAdvck3(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x0007u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncSbvck3(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x0005u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncSl1ad3(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x2006u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncSl2ad3(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x2007u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncFsft(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x200Fu | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncMul(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x1004u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncMulu(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x1005u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncMulr(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x1006u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncMulru(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x1007u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncDiv(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x1008u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncDivu(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x1009u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncBsetm(uint8_t bit3, uint8_t rm) {
    return static_cast<uint16_t>(0x2000u | ((bit3 & 7u) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncBclrm(uint8_t bit3, uint8_t rm) {
    return static_cast<uint16_t>(0x2001u | ((bit3 & 7u) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncBnotm(uint8_t bit3, uint8_t rm) {
    return static_cast<uint16_t>(0x2002u | ((bit3 & 7u) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncBtstm(uint8_t bit3, uint8_t rm) {
    return static_cast<uint16_t>(0x2003u | ((bit3 & 7u) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncTas(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x2004u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncSlt3Imm5(uint8_t rn, uint8_t imm5) {
    return static_cast<uint16_t>(0x6001u | ((rn & 0xFu) << 8) | ((imm5 & 0x1Fu) << 3));
}
constexpr uint16_t EncSraRm(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x200Du | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncSraImm5(uint8_t rn, uint8_t imm5) {
    return static_cast<uint16_t>(0x6003u | ((rn & 0xFu) << 8) | ((imm5 & 0x1Fu) << 3));
}
constexpr uint16_t EncStcbR(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x700Cu | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncLdcbR(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x700Du | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}
constexpr uint16_t EncSwi(uint8_t i2) { return static_cast<uint16_t>(0x7006u | ((i2 & 3u) << 4)); }
constexpr uint16_t EncJsrv(uint8_t rm) { return static_cast<uint16_t>(0x180Fu | ((rm & 0xFu) << 4)); }
constexpr uint16_t EncReti() { return 0x7012u; }
constexpr uint16_t EncRet() { return 0x7002u; }
constexpr uint16_t EncSleep() { return 0x7062u; }
constexpr uint16_t EncLdc(uint8_t rn, uint8_t cr) {
    return static_cast<uint16_t>(0x700Au | ((rn & 0xFu) << 8) | ((cr & 0xFu) << 4) | ((cr >> 4) & 1u));
}
constexpr uint16_t EncStc(uint8_t rn, uint8_t cr) {
    return static_cast<uint16_t>(0x7008u | ((rn & 0xFu) << 8) | ((cr & 0xFu) << 4) | ((cr >> 4) & 1u));
}
constexpr uint16_t EncAnd(uint8_t rn, uint8_t rm) {
    return static_cast<uint16_t>(0x1001u | ((rn & 0xFu) << 8) | ((rm & 0xFu) << 4));
}

std::string HexStr(const std::string &s) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : s) {
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0xFu]);
    }
    return out;
}

uint32_t DecodeLE32Hex(const std::string &hex) {
    uint32_t val = 0;
    for (int i = 0; i < 4; ++i) {
        const unsigned b = static_cast<unsigned>(std::strtoul(hex.substr(i * 2, 2).c_str(), nullptr, 16));
        val |= static_cast<uint32_t>(b) << (i * 8);
    }
    return val;
}

std::string EncodeLE32Hex(uint32_t val) {
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%02x%02x%02x%02x",
                  val & 0xFFu, (val >> 8) & 0xFFu, (val >> 16) & 0xFFu, (val >> 24) & 0xFFu);
    return std::string(buf);
}

// -----------------------------------------------------------------------------
// 1. CPU & Fixed Instruction Decoder Tests
// -----------------------------------------------------------------------------
void TestFixedInstructionsAndControlBus() {
    F00DMachine m;
    m.Reset(0x00800100u);
    Cpu &c = m.cpu;

    // Reset C5 hardware defaults from wiki/hardware reference
    CHECK_EQ(c.control.cfg, 0xF00004AAu);
    CHECK_EQ(c.control.ccfg, 0x5B105B08u);
    CHECK_EQ(c.control.rcfg, 0x01000100u);
    CHECK_EQ(c.control.opt, 0x03FD0201u);
    CHECK_EQ(c.control.id, 0x00000100u);
    CHECK_EQ(c.intc.ivb, 0x00800000u);
    CHECK_EQ(c.GetIntc(0), 0x00800000u);
    CHECK_EQ(c.GetCR(0), 0x00800100u);

    // Build a linear program testing each fixed instruction at 0x00800100+
    uint32_t pc = 0x00800100u;

    // and3 $r1, $r2, 0x0FF0 (1100_nnnn_mmmm_0101 imm16)
    c.r[2] = 0xABCD1234u;
    EmitAndCheck32(c.mem, pc, 0xC125u, 0x0FF0u);
    pc += 4;

    // slt3 $r0, $r3, 10 (signed < imm5=10)
    c.r[3] = static_cast<uint32_t>(-5);
    EmitAndCheck16(c.mem, pc, EncSlt3Imm5(3, 10));
    pc += 2;

    // sra_rm $r4, $r5 (arithmetic right shift!)
    c.r[4] = static_cast<uint32_t>(-32); // 0xFFFFFFE0
    c.r[5] = 2u;
    EmitAndCheck16(c.mem, pc, EncSraRm(4, 5));
    pc += 2;

    // sra_imm5 $r6, 3
    c.r[6] = static_cast<uint32_t>(-64);
    EmitAndCheck16(c.mem, pc, EncSraImm5(6, 3));
    pc += 2;

    // stcb $r7, 0x2048 ($tmp = CR18 = 0x2000 + 18*4) & ldcb $r8, 0x2048
    c.r[7] = 0xCAFEBABEu;
    EmitAndCheck32(c.mem, pc, 0xF704u, 0x2048u);
    pc += 4;
    EmitAndCheck32(c.mem, pc, 0xF814u, 0x2048u);
    pc += 4;

    // stcb_r $r7, $r9 & ldcb_r $r10, $r9 (INTC.IER at 0x0002)
    c.r[9] = 0x0002u;
    EmitAndCheck16(c.mem, pc, EncStcbR(7, 9));
    pc += 2;
    EmitAndCheck16(c.mem, pc, EncLdcbR(10, 9));
    pc += 2;

    // jmp target24 to 0x00800200: 1101_1TTT_TTTT_1000 tttt_tttt_tttt_tttt
    const uint32_t target = 0x00800200u;
    const uint16_t jmp_hw0 = static_cast<uint16_t>(0xD808u | (((target >> 1) & 0x7Fu) << 4));
    const uint16_t jmp_hw1 = static_cast<uint16_t>((target >> 8) & 0xFFFFu);
    EmitAndCheck32(c.mem, pc, jmp_hw0, jmp_hw1);

    // Step through and verify every result
    c.Step(); // and3
    CHECK_EQ(c.r[1], 0x0230u);
    c.Step(); // slt3_imm5: -5 < 10 -> 1
    CHECK_EQ(c.r[0], 1u);
    c.Step(); // sra_rm: -32 >> 2 = -8
    CHECK_EQ(static_cast<int32_t>(c.r[4]), -8);
    c.Step(); // sra_imm5: -64 >> 3 = -8
    CHECK_EQ(static_cast<int32_t>(c.r[6]), -8);
    c.Step(); // stcb
    CHECK_EQ(c.control.tmp, 0xCAFEBABEu);
    c.Step(); // ldcb
    CHECK_EQ(c.r[8], 0xCAFEBABEu);
    c.Step(); // stcb_r
    c.Step(); // ldcb_r
    CHECK_EQ(c.r[10], 0xCAFEBABEu);
    c.Step(); // jmp_target24
    CHECK_EQ(c.control.pc, 0x00800200u);

    // Verify sleep instruction sets sleeping = true
    EmitAndCheck16(c.mem, 0x00800200u, EncSleep());
    c.stop_on_halt = true;
    StopInfo st = c.Step();
    CHECK(c.sleeping);
    CHECK_EQ(static_cast<int>(st.reason), static_cast<int>(StopReason::Halt));
}

void TestNewCoreAndDspInstructions() {
    F00DMachine m;
    m.Reset(0x00800100u);
    Cpu &c = m.cpu;
    uint32_t pc = 0x00800100u;

    // 1. exth & extuh
    c.r[1] = 0x00008001u;
    EmitAndCheck16(c.mem, pc, EncExth(1));
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[1], 0xFFFF8001u);

    c.r[2] = 0xFFFF8002u;
    EmitAndCheck16(c.mem, pc, EncExtuh(2));
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[2], 0x00008002u);

    // 2. ssarb & fsft: sar = ((1 + 1) & 3) * 8 = 16; ((r4 << 32) | r3) >> 16
    c.r[11] = 1u;
    EmitAndCheck16(c.mem, pc, EncSsarb(1, 11));
    pc += 2;
    c.Step();
    CHECK_EQ(c.control.sar, 16u);

    c.r[3] = 0x12345678u;
    c.r[4] = 0xAABBCCDDu;
    EmitAndCheck16(c.mem, pc, EncFsft(3, 4));
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[3], 0xCCDD1234u);

    // 3. sl1ad3 & sl2ad3 -> output to r0
    c.r[5] = 10u;
    c.r[6] = 3u;
    EmitAndCheck16(c.mem, pc, EncSl1ad3(5, 6)); // 2*10 + 3 = 23
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[0], 23u);

    EmitAndCheck16(c.mem, pc, EncSl2ad3(5, 6)); // 4*10 + 3 = 43
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[0], 43u);

    // 4. advck3 & sbvck3 -> output to r0
    c.r[7] = 0xFFFFFFFFu;
    c.r[8] = 2u;
    EmitAndCheck16(c.mem, pc, EncAdvck3(7, 8)); // carry = 1
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[0], 1u);

    c.r[7] = 1u;
    c.r[8] = 5u;
    EmitAndCheck16(c.mem, pc, EncSbvck3(7, 8)); // borrow = 1
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[0], 1u);

    // 5. mul / madd / divu
    c.r[12] = static_cast<uint32_t>(-3);
    c.r[13] = 4u;
    EmitAndCheck16(c.mem, pc, EncMul(12, 13)); // hi:lo = -12
    pc += 2;
    c.Step();
    CHECK_EQ(c.control.lo, static_cast<uint32_t>(-12));
    CHECK_EQ(c.control.hi, 0xFFFFFFFFu);

    EmitAndCheck32(c.mem, pc, static_cast<uint16_t>(0xF001u | (12u << 8) | (13u << 4)), 0x3004u); // madd
    pc += 4;
    c.Step();
    CHECK_EQ(c.control.lo, static_cast<uint32_t>(-24));
    CHECK_EQ(c.control.hi, 0xFFFFFFFFu);

    EmitAndCheck16(c.mem, pc, EncDivu(5, 6)); // 10 / 3 = 3 rem 1
    pc += 2;
    c.Step();
    CHECK_EQ(c.control.lo, 3u);
    CHECK_EQ(c.control.hi, 1u);

    // 6. ldz, sadd, clip
    c.r[14] = 0x00100000u; // clz = 11
    EmitAndCheck32(c.mem, pc, static_cast<uint16_t>(0xF1E1u), 0x0000u); // ldz $r1, $r14
    pc += 4;
    c.Step();
    CHECK_EQ(c.r[1], 11u);

    c.r[1] = 0x7FFFFFF0u;
    c.r[14] = 0x100u;
    EmitAndCheck32(c.mem, pc, static_cast<uint16_t>(0xF1E1u), 0x0008u); // sadd $r1, $r14 -> 0x7FFFFFFF
    pc += 4;
    c.Step();
    CHECK_EQ(c.r[1], 0x7FFFFFFFu);

    c.r[2] = 500u;
    EmitAndCheck32(c.mem, pc, static_cast<uint16_t>(0xF201u), static_cast<uint16_t>(0x1008u | (7u << 3))); // clip $r2, 7 -> +63
    pc += 4;
    c.Step();
    CHECK_EQ(c.r[2], 63u);

    // 7. bit memory ops bsetm/btstm + tas + bclrm + bnotm
    const uint32_t mem_addr = 0x00801000u;
    Write32(c.mem, mem_addr, 0u);
    c.r[14] = mem_addr;
    EmitAndCheck16(c.mem, pc, EncBsetm(3, 14)); // byte |= 8
    pc += 2;
    c.Step();
    CHECK_EQ(Read8(c.mem, mem_addr), 8u);

    EmitAndCheck16(c.mem, pc, EncBtstm(3, 14)); // r0 = 8
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[0], 8u);

    EmitAndCheck16(c.mem, pc, EncBclrm(3, 14)); // byte &= ~8 -> 0
    pc += 2;
    c.Step();
    CHECK_EQ(Read8(c.mem, mem_addr), 0u);

    EmitAndCheck16(c.mem, pc, EncTas(1, 14)); // old=0, sets 1
    pc += 2;
    c.Step();
    CHECK_EQ(c.r[1], 0u);
    CHECK_EQ(Read8(c.mem, mem_addr), 1u);

    // 8. casw3, jsrv, bsrv
    m.Reset(0x00800300u);
    pc = 0x00800300u;
    Write32(c.mem, mem_addr, 0x11223344u);
    c.r[1] = 0x11223344u; // expected
    c.r[2] = mem_addr;    // addr
    c.r[3] = 0x55667788u; // replacement
    EmitAndCheck32(c.mem, pc, static_cast<uint16_t>(0xF121u), static_cast<uint16_t>(0x2002u | (3u << 8))); // casw3
    pc += 4;
    c.r[4] = 0x00800400u;
    EmitAndCheck16(c.mem, pc, EncJsrv(4));
    pc += 2;
    c.Step(); // casw3 swaps & writes old to r3
    CHECK_EQ(Read32(c.mem, mem_addr), 0x55667788u);
    CHECK_EQ(c.r[3], 0x11223344u);
    c.Step(); // jsrv -> lp = 0x00800306, pc = 0x00800400
    CHECK_EQ(c.control.lp, 0x00800306u);
    CHECK_EQ(c.control.pc, 0x00800400u);

    // bsrv disp24 (+0x100 from 0x00800400 -> 0x00800500)
    const uint32_t disp24 = 0x000100u;
    const uint16_t bsrv_hw0 = static_cast<uint16_t>(0xD80Bu | (((disp24 >> 1) & 0x7Fu) << 4));
    const uint16_t bsrv_hw1 = static_cast<uint16_t>((disp24 >> 8) & 0xFFFFu);
    EmitAndCheck32(c.mem, 0x00800400u, bsrv_hw0, bsrv_hw1);
    c.Step();
    CHECK_EQ(c.control.lp, 0x00800404u);
    CHECK_EQ(c.control.pc, 0x00800500u);
}

void TestCpuInterruptsSwiAndRepeat() {
    F00DMachine m;
    m.Reset(0x00800100u);
    Cpu &c = m.cpu;

    // 1. Hardware IRQ dispatch (vector = (IVB & ~0xFF) + 0x80 + irq * 4) + RETI return
    c.sleeping = true;
    c.control.psw = 0x1u; // PSW.IEC = 1
    c.intc.ivb = 0x00800000u;
    c.intc.ier = (1u << 2);
    c.intc.ilr0 = (1u << 8); // priority 1 for IRQ 2
    const uint32_t irq2_vec = 0x00800080u + 2u * 4u;
    // Place movi8 $r4, 0x55 then reti at irq2_vec (4 bytes)
    EmitAndCheck16(c.mem, irq2_vec, EncMovi8(4, 0x55));
    EmitAndCheck16(c.mem, irq2_vec + 2u, EncReti());
    EmitAndCheck16(c.mem, 0x00800100u, EncMovi8(1, 42));

    c.RaiseIrq(2);
    CHECK(!c.sleeping);

    StopInfo st = c.Step(false);
    CHECK_EQ(static_cast<int>(st.reason), static_cast<int>(StopReason::None));
    CHECK_EQ(c.control.psw & 1u, 0u);
    CHECK_EQ(c.control.epc, 0x00800100u);
    CHECK_EQ(c.r[4], 0x55u);
    CHECK_EQ(c.control.pc, irq2_vec + 2u);

    c.Step(); // reti -> returns to 0x00800100, restores PSW.IEC=1
    CHECK_EQ(c.control.pc, 0x00800100u);
    CHECK_EQ(c.control.psw & 1u, 1u);

    // 2. SWI vector dispatch & debugger trap mode
    const uint32_t swi1_vec = 0x00800040u + 1u * 4u;
    EmitAndCheck16(c.mem, swi1_vec, EncReti());
    EmitAndCheck16(c.mem, 0x00800100u, EncSwi(1));
    c.swi_breaks_to_debugger = false;
    c.Step();
    CHECK_EQ(c.control.pc, swi1_vec);
    CHECK_EQ(c.control.epc, 0x00800102u);
    c.Step(); // reti -> 0x00800102
    CHECK_EQ(c.control.pc, 0x00800102u);

    EmitAndCheck16(c.mem, 0x00800102u, EncSwi(2));
    c.swi_breaks_to_debugger = true;
    StopInfo swi_stop = c.Step();
    CHECK_EQ(static_cast<int>(swi_stop.reason), static_cast<int>(StopReason::Swi));

    // 3. Hardware repeat loop via decoded repeat instruction:
    // repeat $r1, disp17=4 -> rpe = 0x00800204 (loop body = 0x00800204 + following delay/tail insn 0x00800206)
    m.Reset(0x00800200u);
    c.r[1] = 2u; // execute block twice
    EmitAndCheck32(c.mem, 0x00800200u, 0xE109u, 0x0002u);
    EmitAndCheck16(c.mem, 0x00800204u, EncAddImm6(2, 1)); // r2 += 1 (at rpe)
    EmitAndCheck16(c.mem, 0x00800206u, 0x0000u);           // nop (tail insn immediately after rpe)
    EmitAndCheck16(c.mem, 0x00800208u, EncMovi8(3, 99));
    c.r[2] = 0u;
    c.Step(); // repeat setup
    c.Step(); // iter 1: add r2, 1 (pc=0x800206)
    c.Step(); // iter 1 tail nop -> loops back to 0x800204, rpc=1
    CHECK_EQ(c.control.pc, 0x00800204u);
    c.Step(); // iter 2: add r2, 1 (pc=0x800206)
    c.Step(); // iter 2 tail nop -> exits loop to 0x800208!
    CHECK_EQ(c.r[2], 2u);
    CHECK_EQ(c.control.pc, 0x00800208u);

    // 4. Infinite erepeat loop: disp17=4 -> rpe = 0x00800304 (body = 0x00800304..0x00800306)
    m.Reset(0x00800300u);
    EmitAndCheck32(c.mem, 0x00800300u, 0xE019u, 0x0002u);
    EmitAndCheck16(c.mem, 0x00800304u, EncAddImm6(5, 1));
    EmitAndCheck16(c.mem, 0x00800306u, 0x0000u); // nop tail
    c.r[5] = 0u;
    c.Step(); // erepeat
    CHECK(c.erepeat_active);
    c.Step(); // +1
    c.Step(); // tail -> loops back to 0x00800304
    CHECK_EQ(c.control.pc, 0x00800304u);
    c.Step(); // +1 again -> r5 == 2
    CHECK_EQ(c.r[5], 2u);
}

// -----------------------------------------------------------------------------
// 2. MMIO Device Tests via F00DMachine
// -----------------------------------------------------------------------------
void TestIntcAndSecGateAndEeprom() {
    F00DMachine m;
    m.Reset(0x00800000u);

    // IntcMmio at 0xE3000000
    Write32(m.cpu.mem, 0xE3000000u, 0x00820000u); // IVB
    Write32(m.cpu.mem, 0xE3000008u, 0x0000000Fu); // IER
    Write32(m.cpu.mem, 0xE300000Cu, 0x00000003u); // IET
    Write32(m.cpu.mem, 0xE3000010u, 0x12345678u); // ILR0
    CHECK_EQ(m.cpu.intc.ivb, 0x00820000u);
    CHECK_EQ(m.cpu.intc.ier, 0x0000000Fu);
    CHECK_EQ(m.cpu.intc.iet, 0x00000003u);
    CHECK_EQ(m.cpu.intc.ilr0, 0x12345678u);
    CHECK_EQ(Read32(m.cpu.mem, 0xE3000008u), 0x0000000Fu);

    // SecGate 0xE0020000: +0x20 is RAZ/WI gate, +0x100..+0x11F exposes keyslot 0x602
    uint8_t slot602[0x20];
    for (uint8_t i = 0; i < 0x20; ++i) {
        slot602[i] = static_cast<uint8_t>(0xA0u + i);
    }
    CHECK(m.eeprom.SetKeySlot(0x602u, slot602, sizeof(slot602)));
    Write32(m.cpu.mem, 0xE0020020u, 0x12345678u);
    CHECK_EQ(Read32(m.cpu.mem, 0xE0020020u), 0u);
    CHECK_EQ(Read32(m.cpu.mem, 0xE0020100u),
             static_cast<uint32_t>(slot602[0]) |
             (static_cast<uint32_t>(slot602[1]) << 8) |
             (static_cast<uint32_t>(slot602[2]) << 16) |
             (static_cast<uint32_t>(slot602[3]) << 24));

    // EEPROM direct read/write + keyslot API
    Write32(m.cpu.mem, 0xE0058000u, 0xDEADBEEFu);
    CHECK_EQ(Read32(m.cpu.mem, 0xE0058000u), 0xDEADBEEFu);

    uint8_t key10[0x20] = {};
    for (int i = 0; i < 0x20; ++i) key10[i] = static_cast<uint8_t>(i + 1);
    CHECK(m.eeprom.SetKeySlot(0x10u, key10, 0x20));
    std::vector<uint8_t> out_slot(0x20, 0);
    CHECK(m.eeprom.GetKeySlot(0x10u, out_slot.data(), out_slot.size()));
    CHECK_EQ(std::memcmp(out_slot.data(), key10, 0x20), 0);

    // EEPROMProgrammer at 0xE0030000: program slot 0x15 + query protection line 0x501
    Write32(m.cpu.mem, 0xE0030000u, 0x11223344u); // key word 0
    Write32(m.cpu.mem, 0xE0030004u, 0x55667788u); // key word 1
    Write32(m.cpu.mem, 0xE0030020u, 0x15u);       // write slot 0x15
    CHECK_EQ(Read32(m.cpu.mem, 0xE0030004u), 0u); // idle/ready
    std::vector<uint8_t> out15(0x20, 0);
    CHECK(m.eeprom.GetKeySlot(0x15u, out15.data(), out15.size()));
    uint32_t w0 = 0;
    std::memcpy(&w0, out15.data(), sizeof(w0));
    CHECK_EQ(w0, 0x11223344u);

    Write32(m.cpu.mem, 0xE0030028u, 0x501u);
    CHECK_EQ(Read32(m.cpu.mem, 0xE003002Cu), 0x10000007u);

    // ARMComm mailbox 0xE0000000 + e001 0xE0010000
    Write32(m.cpu.mem, 0xE0000004u, 0x55667788u);
    CHECK_EQ(Read32(m.cpu.mem, 0xE0000004u), 0x55667788u);
    Write32(m.cpu.mem, 0xE0010000u, 0x12345678u);
    CHECK_EQ(Read32(m.cpu.mem, 0xE0010000u), 0x12345678u);
}

void TestMathPowMod() {
    F00DMachine m;
    m.Reset(0x00800000u);
    Memory &mem = m.cpu.mem;

    // Math layout: +0x108 base, +0x300 exp (multi-word), +0x400 mod, +0x508 out,
    // +0x800 cmd ((0x12<<27)|(mod_words<<18)|(exp_words<<9)), +0x804 flags, +0x808 exp (1-word)
    // 1-word (32-bit): 5^13 mod 19 = 17
    Write32(mem, 0xE0040108u, 5u);
    Write32(mem, 0xE0040808u, 13u);
    Write32(mem, 0xE0040400u, 19u);
    Write32(mem, 0xE0040800u, (0x12u << 27) | (1u << 18) | (1u << 9));
    CHECK_EQ(Read32(mem, 0xE0040508u), 17u);
    CHECK_EQ(Read32(mem, 0xE0040804u), 1u << 16);

    // 2-word (64-bit): 100^5 mod 1000000007 = 999999937
    Write32(mem, 0xE0040108u, 100u);
    Write32(mem, 0xE004010Cu, 0u);
    Write32(mem, 0xE0040300u, 5u);
    Write32(mem, 0xE0040304u, 0u);
    Write32(mem, 0xE0040400u, 1000000007u);
    Write32(mem, 0xE0040404u, 0u);
    Write32(mem, 0xE0040800u, (0x12u << 27) | (2u << 18) | (2u << 9));
    CHECK_EQ(Read32(mem, 0xE0040508u), 999999937u);
    CHECK_EQ(Read32(mem, 0xE004050Cu), 0u);
}

void TestBigmacCryptoAndDma() {
    F00DMachine m;
    m.Reset(0x00800000u);
    Memory &mem = m.cpu.mem;

    const uint32_t kBase = 0xE0050000u;
    const uint32_t kMirror = 0xE04E0000u;
    const uint32_t src_addr = 0x40001000u;
    const uint32_t dst_addr = 0x40002000u;
    const uint32_t dec_addr = 0x40003000u;
    const uint32_t hash_addr = 0x40004000u;
    const uint32_t iv_addr = 0x40005000u;

    // 1. DMA memcpy (func=0, channel 0 at +0x100, commit at +0x11C) + DMAC5 mirror check
    const uint8_t aes_key[16] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
        0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    const uint8_t aes_pt[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
        0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff
    };
    const uint8_t aes_ct_expected[16] = {
        0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a
    };

    CHECK(mem.TryWrite(src_addr, 16, aes_pt, false));
    Write32(mem, kBase + 0x100u, src_addr);
    Write32(mem, kBase + 0x104u, dst_addr);
    Write32(mem, kBase + 0x108u, 16u);
    Write32(mem, kBase + 0x10Cu, 0u); // copy
    Write32(mem, kBase + 0x11Cu, 1u); // commit
    for (int i = 0; i < 16; ++i) {
        CHECK_EQ(Read8(mem, dst_addr + i), aes_pt[i]);
    }
    CHECK_EQ(Read32(mem, kMirror + 0x100u), src_addr);

    // 2. AES-128-ECB encrypt (op=0x01, key_sel=1 -> func=0x0101) & decrypt (0x0109)
    CHECK(mem.TryWrite(kBase + 0x200u, 16, aes_key, false));
    Write32(mem, kBase + 0x100u, src_addr);
    Write32(mem, kBase + 0x104u, dst_addr);
    Write32(mem, kBase + 0x108u, 16u);
    Write32(mem, kBase + 0x10Cu, 0x0101u);
    Write32(mem, kBase + 0x11Cu, 1u);
    for (int i = 0; i < 16; ++i) {
        CHECK_EQ(Read8(mem, dst_addr + i), aes_ct_expected[i]);
    }

    CHECK(mem.TryWrite(kBase + 0x200u, 16, aes_key, false));
    Write32(mem, kBase + 0x100u, dst_addr);
    Write32(mem, kBase + 0x104u, dec_addr);
    Write32(mem, kBase + 0x108u, 16u);
    Write32(mem, kBase + 0x10Cu, 0x0109u);
    Write32(mem, kBase + 0x11Cu, 1u);
    for (int i = 0; i < 16; ++i) {
        CHECK_EQ(Read8(mem, dec_addr + i), aes_pt[i]);
    }

    // 3. AES-128-CBC encrypt (0x0102) & decrypt (0x010A) via keyslot 0x10
    CHECK(m.eeprom.SetKeySlot(0x10u, aes_key, 16));
    const uint8_t iv[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    CHECK(mem.TryWrite(iv_addr, 16, iv, false));
    Write32(mem, kBase + 0x100u, src_addr);
    Write32(mem, kBase + 0x104u, dst_addr);
    Write32(mem, kBase + 0x108u, 16u);
    Write32(mem, kBase + 0x110u, 0x10u);
    Write32(mem, kBase + 0x114u, iv_addr);
    Write32(mem, kBase + 0x10Cu, 0x0502u); // bit 10 force keyslot + key_sel=1 + CBC enc
    Write32(mem, kBase + 0x11Cu, 1u);

    CHECK(mem.TryWrite(iv_addr, 16, iv, false));
    Write32(mem, kBase + 0x100u, dst_addr);
    Write32(mem, kBase + 0x104u, dec_addr);
    Write32(mem, kBase + 0x108u, 16u);
    Write32(mem, kBase + 0x110u, 0x10u);
    Write32(mem, kBase + 0x114u, iv_addr);
    Write32(mem, kBase + 0x10Cu, 0x050Au); // CBC dec
    Write32(mem, kBase + 0x11Cu, 1u);
    for (int i = 0; i < 16; ++i) {
        CHECK_EQ(Read8(mem, dec_addr + i), aes_pt[i]);
    }

    // 4. AES-128-CTR encrypt + decrypt symmetry (op=0x21 -> func=0x0521)
    CHECK(mem.TryWrite(iv_addr, 16, iv, false));
    Write32(mem, kBase + 0x100u, src_addr);
    Write32(mem, kBase + 0x104u, dst_addr);
    Write32(mem, kBase + 0x108u, 16u);
    Write32(mem, kBase + 0x10Cu, 0x0521u);
    Write32(mem, kBase + 0x11Cu, 1u);
    CHECK(mem.TryWrite(iv_addr, 16, iv, false));
    Write32(mem, kBase + 0x100u, dst_addr);
    Write32(mem, kBase + 0x104u, dec_addr);
    Write32(mem, kBase + 0x10Cu, 0x0521u);
    Write32(mem, kBase + 0x11Cu, 1u);
    for (int i = 0; i < 16; ++i) {
        CHECK_EQ(Read8(mem, dec_addr + i), aes_pt[i]);
    }

    // 5. SHA-1("abc") & SHA-256("abc")
    CHECK(mem.TryWrite(src_addr, 3, "abc", false));
    Write32(mem, kBase + 0x100u, src_addr);
    Write32(mem, kBase + 0x104u, hash_addr);
    Write32(mem, kBase + 0x108u, 3u);
    Write32(mem, kBase + 0x10Cu, 0x03u); // SHA-1
    Write32(mem, kBase + 0x11Cu, 1u);
    const uint8_t sha1_abc[20] = {
        0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
        0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d
    };
    for (int i = 0; i < 20; ++i) {
        CHECK_EQ(Read8(mem, hash_addr + i), sha1_abc[i]);
    }

    Write32(mem, kBase + 0x10Cu, 0x13u); // SHA-256
    Write32(mem, kBase + 0x11Cu, 1u);
    const uint8_t sha256_abc[32] = {
        0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
        0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
    };
    for (int i = 0; i < 32; ++i) {
        CHECK_EQ(Read8(mem, hash_addr + i), sha256_abc[i]);
    }

    // 6. HMAC-SHA1 RFC 2202 test vector 1 (key=0x0b*20, data="Hi There")
    uint8_t hmac_key[20];
    std::memset(hmac_key, 0x0b, sizeof(hmac_key));
    CHECK(mem.TryWrite(kBase + 0x200u, 20, hmac_key, false));
    CHECK(mem.TryWrite(src_addr, 8, "Hi There", false));
    Write32(mem, kBase + 0x100u, src_addr);
    Write32(mem, kBase + 0x104u, hash_addr);
    Write32(mem, kBase + 0x108u, 8u);
    Write32(mem, kBase + 0x10Cu, 0x23u); // HMAC-SHA1 (key_sel=0 -> 20 bytes)
    Write32(mem, kBase + 0x11Cu, 1u);
    const uint8_t hmac_expected[20] = {
        0xb6,0x17,0x31,0x86,0x55,0x05,0x72,0x64,0xe2,0x8b,
        0xc0,0xb6,0xfb,0x37,0x8c,0x8e,0xf1,0x46,0xbe,0x00
    };
    for (int i = 0; i < 20; ++i) {
        CHECK_EQ(Read8(mem, hash_addr + i), hmac_expected[i]);
    }

    // 7. RNG register at +0x3C produces advancing PRNG outputs
    const uint32_t rng1 = Read32(mem, kBase + 0x3Cu);
    const uint32_t rng2 = Read32(mem, kBase + 0x3Cu);
    CHECK(rng1 != rng2);
}

// -----------------------------------------------------------------------------
// 3. GDB RSP Packet Tests
// -----------------------------------------------------------------------------
void TestGdbRsp() {
    F00DMachine m;
    m.Reset(0x00800000u);
    Debugger dbg(&m.cpu, 0, &m);

    // Query & negotiation packets
    CHECK_STREQ(dbg.ProcessPacket("?"), "T05thread:01;");
    CHECK_STREQ(dbg.ProcessPacket("QStartNoAckMode"), "OK");
    CHECK(dbg.ProcessPacket("qSupported:multiprocess+").find("qXfer:features:read+") != std::string::npos);

    const std::string target_xml = dbg.ProcessPacket("qXfer:features:read:target.xml:0,fff");
    CHECK(!target_xml.empty() && (target_xml[0] == 'l' || target_xml[0] == 'm'));
    CHECK(target_xml.find("reg name=") != std::string::npos);

    const std::string mmap_xml = dbg.ProcessPacket("qXfer:memory-map:read::0,fff");
    CHECK(mmap_xml.find("0x800000") != std::string::npos || mmap_xml.find("800000") != std::string::npos);

    // Read/write all 56 registers via g & single register via P/p
    const std::string all_regs = dbg.ProcessPacket("g");
    CHECK_EQ(all_regs.size(), static_cast<size_t>(56 * 8));

    CHECK_STREQ(dbg.ProcessPacket("P3=" + EncodeLE32Hex(0x12345678u)), "OK");
    CHECK_EQ(m.cpu.r[3], 0x12345678u);
    CHECK_EQ(DecodeLE32Hex(dbg.ProcessPacket("p3")), 0x12345678u);

    // Write & read INTC register ($ivb = reg 48 = 0x30)
    CHECK_STREQ(dbg.ProcessPacket("P30=" + EncodeLE32Hex(0x00804000u)), "OK");
    CHECK_EQ(m.cpu.intc.ivb, 0x00804000u);

    // Memory read/write M / m
    CHECK_STREQ(dbg.ProcessPacket("M800100,4:" + EncodeLE32Hex(0xAABBCCDDu)), "OK");
    CHECK_STREQ(dbg.ProcessPacket("m800100,4"), EncodeLE32Hex(0xAABBCCDDu));

    // Step / Breakpoint / Continue
    WriteInsn16(m.cpu.mem, 0x00800100u, EncMovi8(1, 10));
    WriteInsn16(m.cpu.mem, 0x00800102u, EncMovi8(2, 20));
    WriteInsn16(m.cpu.mem, 0x00800104u, EncMovi8(3, 30));
    m.cpu.control.pc = 0x00800100u;

    std::string step_rep = dbg.ProcessPacket("s");
    CHECK(step_rep.rfind("T05", 0) == 0);
    CHECK_EQ(m.cpu.r[1], 10u);
    CHECK_EQ(m.cpu.control.pc, 0x00800102u);

    CHECK_STREQ(dbg.ProcessPacket("Z0,800104,2"), "OK");
    std::string cont_rep = dbg.ProcessPacket("c");
    CHECK(cont_rep.rfind("T05", 0) == 0);
    CHECK_EQ(m.cpu.r[2], 20u);
    CHECK_EQ(m.cpu.control.pc, 0x00800104u);

    CHECK_STREQ(dbg.ProcessPacket("z0,800104,2"), "OK");
    CHECK(!m.cpu.HasBreakpoint(0x00800104u));

    // Monitor qRcmd commands: status, intc, irq 4
    std::string mon_status = dbg.ProcessPacket("qRcmd," + HexStr("status"));
    CHECK(!mon_status.empty() && mon_status != "E01");

    std::string mon_irq = dbg.ProcessPacket("qRcmd," + HexStr("irq 4"));
    CHECK_EQ(mon_irq.rfind(HexStr("Raised IRQ 4"), 0), 0u);
    CHECK((m.cpu.intc.isr & (1u << 4)) != 0u);
}

// -----------------------------------------------------------------------------
// 4. Startup 0x40000 <-> 0x800000 Mirror & $cfg Cache/Remap Transition Tests
// -----------------------------------------------------------------------------
constexpr uint16_t EncJmp24Hw0(uint32_t target) {
    return static_cast<uint16_t>(0xD808u | (((target >> 1) & 0x7Fu) << 4));
}
constexpr uint16_t EncJmp24Hw1(uint32_t target) {
    return static_cast<uint16_t>((target >> 8) & 0xFFFFu);
}

void TestCfgStartupRemap() {
    F00DMachine m;
    m.Reset(0x00040200u);
    Cpu &c = m.cpu;

    // 1. Startup defaults at 0x00040000 uncached window
    CHECK_EQ(c.control.pc, 0x00040200u);
    CHECK_EQ(c.control.cfg, kCfgStartupDefault);
    CHECK_EQ(c.intc.ivb, 0x00040000u);
    CHECK(!c.IsInstructionCacheEnabled());
    CHECK(!c.IsCacheEnabled());
    CHECK(!c.IsVectorBaseRemapped());

    // 2. Shared physical SRAM mirroring between 0x00040000..0x0005FFFF and 0x00800000..0x0081FFFF
    Write32(c.mem, 0x00040500u, 0x11223344u);
    CHECK_EQ(Read32(c.mem, 0x00800500u), 0x11223344u);
    Write32(c.mem, 0x00800504u, 0x55667788u);
    CHECK_EQ(Read32(c.mem, 0x00040504u), 0x55667788u);
    Write32(c.mem, 0x00310000u, 0xA5A5A5A5u); // icache tag RAM is mapped
    CHECK_EQ(Read32(c.mem, 0x00310000u), 0xA5A5A5A5u);

    // 3. Reproduce second_loader (_reset at 0x40200) cache enable + explicit jump to 0x800360:
    //      ldc     $2, $cfg
    //      or3     $2, $2, 2        (enable ICE bit 1 -> stays in 0x40000 window)
    //      stc     $2, $cfg
    //      ... (icache tag invalidation runs in 0x40000 uncached window) ...
    //      or3     $2, $2, 0x400    (enable cache bus bit 10 -> stays in 0x40000 window)
    //      stc     $2, $cfg
    //      jmp     0x00800360       (explicit jump switches execution base to 0x800000)
    uint32_t pc = 0x00040200u;
    EmitAndCheck16(c.mem, pc, EncLdc(2, 21));               pc += 2; // 0x00040200
    EmitAndCheck32(c.mem, pc, 0xC224u, 0x0002u);            pc += 4; // 0x00040202: or3 $2, $2, 2
    EmitAndCheck16(c.mem, pc, EncStc(2, 21));               pc += 2; // 0x00040206: stc $2, $cfg
    EmitAndCheck32(c.mem, pc, 0xC224u, 0x0400u);            pc += 4; // 0x00040208: or3 $2, $2, 0x400
    EmitAndCheck16(c.mem, pc, EncStc(2, 21));               pc += 2; // 0x0004020C: stc $2, $cfg
    EmitAndCheck16(c.mem, pc, 0x0000u);                     pc += 2; // 0x0004020E: nop
    EmitAndCheck32(c.mem, pc, EncJmp24Hw0(0x00800360u), EncJmp24Hw1(0x00800360u)); // 0x00040210: jmp 0x800360

    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None)); // ldc $2, $cfg
    CHECK_EQ(c.r[2], kCfgStartupDefault);
    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None)); // or3 2
    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None)); // stc $2, $cfg
    CHECK(c.IsInstructionCacheEnabled());
    CHECK(!c.IsCacheEnabled());
    CHECK(!c.IsVectorBaseRemapped());
    CHECK_EQ(c.control.cfg, 0xF00000B2u);
    CHECK_EQ(c.intc.ivb, 0x00040000u);
    CHECK_EQ(c.control.pc, 0x00040208u); // Must NOT jump PC!

    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None)); // or3 0x400
    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None)); // stc $2, $cfg
    CHECK(c.IsCacheEnabled());
    CHECK(!c.IsVectorBaseRemapped());
    CHECK_EQ(c.control.cfg, 0xF00004B2u);
    CHECK_EQ(c.intc.ivb, 0x00040000u);
    CHECK_EQ(c.control.pc, 0x0004020Eu); // Still in uncached 0x40000 window!

    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None)); // nop
    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None)); // jmp 0x800360
    CHECK_EQ(c.control.pc, 0x00800360u); // Switched to cached 0x800000 base on explicit jmp!

    // 4. Post-jump sequence at 0x00800360 (mirrored from 0x00040360):
    //      ldc     $0, $cfg
    //      mov     $1, -0x11
    //      and     $0, $1
    //      or3     $0, $0, 8
    //      stc     $0, $cfg     (clears EVM=0, sets IVM=1 -> cfg=0xF00004AA, IVB -> 0x00800000)
    //      mov     $2, 0x42
    uint32_t cpc = 0x00040360u;
    EmitAndCheck16(c.mem, cpc, EncLdc(0, 21));              cpc += 2; // 0x00800360
    EmitAndCheck16(c.mem, cpc, EncMovi8(1, -0x11));         cpc += 2; // 0x00800362
    EmitAndCheck16(c.mem, cpc, EncAnd(0, 1));               cpc += 2; // 0x00800364
    EmitAndCheck32(c.mem, cpc, 0xC004u, 0x0008u);           cpc += 4; // 0x00800366: or3 $0, $0, 8
    EmitAndCheck16(c.mem, cpc, EncStc(0, 21));              cpc += 2; // 0x0080036A: stc $0, $cfg
    EmitAndCheck16(c.mem, cpc, EncMovi8(2, 0x42));          cpc += 2; // 0x0080036C

    for (int i = 0; i < 6; ++i) {
        CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None));
    }
    CHECK(c.IsVectorBaseRemapped());
    CHECK(c.IsCacheEnabled());
    CHECK_EQ(c.control.cfg, 0xF00004AAu);
    CHECK_EQ(c.intc.ivb, 0x00800000u);
    CHECK_EQ(c.r[2], 0x42u);
    CHECK_EQ(c.control.pc, 0x0080036Eu);

    // 5. Teardown clearing ICE + cache_bus (and $5, -0x403; stc $5, $cfg) disables cache without corrupting PC
    uint32_t td = 0x000401A4u;
    EmitAndCheck16(c.mem, td, EncLdc(5, 21));               td += 2;
    EmitAndCheck32(c.mem, td, 0xC601u, 0xFBFDu);            td += 4; // mov $6, -0x403
    EmitAndCheck16(c.mem, td, EncAnd(5, 6));                td += 2;
    EmitAndCheck16(c.mem, td, EncStc(5, 21));               td += 2;
    c.control.pc = 0x000401A4u;
    for (int i = 0; i < 4; ++i) {
        CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None));
    }
    CHECK(!c.IsInstructionCacheEnabled());
    CHECK(!c.IsCacheEnabled());
    CHECK_EQ(c.control.cfg, 0xF00000A8u);
    CHECK_EQ(c.control.pc, td);

    // 6. Control bus stcb $0, 0x2054 ($cfg) clears EVM -> updates $ivb without modifying PC
    m.Reset(0x00040200u);
    c.r[0] = 0xF00000A8u;
    EmitAndCheck32(c.mem, 0x00040200u, 0xF004u, 0x2054u); // stcb $0, 0x2054
    CHECK_EQ(static_cast<int>(c.Step().reason), static_cast<int>(StopReason::None));
    CHECK(c.IsVectorBaseRemapped());
    CHECK_EQ(c.intc.ivb, 0x00800000u);
    CHECK_EQ(c.control.pc, 0x00040204u);
}

void TestCfgRemapBreakpointsAndWatchpoints() {
    F00DMachine m;
    m.Reset(0x00040100u);
    Cpu &c = m.cpu;

    // Emit cache enable + explicit jmp to 0x00800120 (alias of 0x00040120)
    uint32_t pc = 0x00040100u;
    EmitAndCheck16(c.mem, pc, EncLdc(2, 21));               pc += 2; // 0x00040100
    EmitAndCheck32(c.mem, pc, 0xC224u, 0x0002u);            pc += 4; // 0x00040102: or3 $2, $2, 2
    EmitAndCheck16(c.mem, pc, EncStc(2, 21));               pc += 2; // 0x00040106: stc $2, $cfg
    EmitAndCheck32(c.mem, pc, 0xC224u, 0x0400u);            pc += 4; // 0x00040108: or3 $2, $2, 0x400
    EmitAndCheck16(c.mem, pc, EncStc(2, 21));               pc += 2; // 0x0004010C: stc $2, $cfg
    EmitAndCheck32(c.mem, pc, EncJmp24Hw0(0x00800120u), EncJmp24Hw1(0x00800120u)); // 0x0004010E: jmp 0x800120

    uint32_t cached_fn = 0x00040120u;
    EmitAndCheck16(c.mem, cached_fn, EncMovi8(2, 0x5Au));   cached_fn += 2; // 0x00800120 / 0x00040120
    EmitAndCheck32(c.mem, cached_fn, 0xC23Au, 0x0000u);     cached_fn += 4; // 0x00800122: sw $2, 0($3)
    EmitAndCheck16(c.mem, cached_fn, EncMovi8(4, 0x11u));   cached_fn += 2; // 0x00800126

    // Breakpoint placed in 0x00040000 window BEFORE jump must trigger at 0x00800122 after jmp 0x800120
    c.AddBreakpoint(0x00040122u);
    c.r[3] = 0x00800500u;

    StopInfo stop = m.RunSteps(16, true, nullptr);
    CHECK_EQ(static_cast<int>(stop.reason), static_cast<int>(StopReason::Breakpoint));
    CHECK_EQ(stop.pc, 0x00800122u);

    // Watchpoint placed in 0x00040000 window must trigger on write to 0x00800500
    c.mem.AddWatchpoint(0x00040500u, 4u, 1);
    stop = m.RunSteps(4, true, nullptr);
    CHECK_EQ(static_cast<int>(stop.reason), static_cast<int>(StopReason::Watchpoint));
    CHECK_EQ(stop.detail, 0x00040500u);
    CHECK_EQ(Read32(c.mem, 0x00040500u), 0x0000005Au);

    // If both direct and aliased watchpoints exist, direct window match is preferred
    c.mem.AddWatchpoint(0x00800500u, 4u, 1);
    c.control.pc = 0x00800122u;
    stop = m.RunSteps(2, true, nullptr);
    CHECK_EQ(static_cast<int>(stop.reason), static_cast<int>(StopReason::Watchpoint));
    CHECK_EQ(stop.detail, 0x00800500u);

    // Reverse direction: breakpoint in 0x00800000 window catches uncached execution in 0x00040000
    c.ClearBreakpoints();
    c.mem.ClearWatchpoints();
    m.Reset(0x00040100u);
    c.AddBreakpoint(0x00800108u);
    stop = m.RunSteps(16, true, nullptr);
    CHECK_EQ(static_cast<int>(stop.reason), static_cast<int>(StopReason::Breakpoint));
    CHECK_EQ(stop.pc, 0x00040108u);

    // GDB RSP Z0 across explicit jmp 0x800120 switch
    F00DMachine gdb_machine;
    gdb_machine.Reset(0x00040100u);
    EmitAndCheck32(gdb_machine.cpu.mem, 0x00040100u, EncJmp24Hw0(0x00800120u), EncJmp24Hw1(0x00800120u));
    EmitAndCheck16(gdb_machine.cpu.mem, 0x00040120u, EncMovi8(2, 0x33u));
    Debugger dbg(&gdb_machine.cpu);
    CHECK(dbg.ProcessPacket("Z0,40120,2") == "OK");
    const std::string reply = dbg.ProcessPacket("c");
    CHECK(reply.rfind("T05", 0) == 0);
    CHECK_EQ(gdb_machine.cpu.control.pc, 0x00800120u);
}

}  // namespace

int main() {
    set_log_callback([](const char *) {});

    TestFixedInstructionsAndControlBus();
    TestNewCoreAndDspInstructions();
    TestCpuInterruptsSwiAndRepeat();
    TestIntcAndSecGateAndEeprom();
    TestMathPowMod();
    TestBigmacCryptoAndDma();
    TestGdbRsp();
    TestCfgStartupRemap();
    TestCfgRemapBreakpointsAndWatchpoints();

    if (g_failures == 0) {
        std::printf("All mepulator tests passed!\n");
        return 0;
    }
    std::fprintf(stderr, "%d test check(s) failed.\n", g_failures);
    return 1;
}
