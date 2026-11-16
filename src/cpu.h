#pragma once

#include <cstdint>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "memory.h"

enum {
    MEP_REG_r0 = 0,
    MEP_REG_tp = 13,
    MEP_REG_gp = 14,
    MEP_REG_sp = 15,
};

inline constexpr uint32_t kSramUncachedBase = 0x00040000u;
inline constexpr uint32_t kSramUncachedSize = 0x00020000u;
inline constexpr uint32_t kSramCachedBase   = 0x00800000u;
inline constexpr uint32_t kSramRemapOffset  = kSramCachedBase - kSramUncachedBase;

inline constexpr uint32_t kCfgBitDce      = 1u << 0;   // Data Cache Enable
inline constexpr uint32_t kCfgBitIce      = 1u << 1;   // Instruction Cache Enable
inline constexpr uint32_t kCfgBitIvm      = 1u << 3;   // Interrupt Vector Mode (1 = table)
inline constexpr uint32_t kCfgBitEvm      = 1u << 4;   // Exception Vector Mode (1 = uncached startup 0x40000, 0 = 0x800000)
inline constexpr uint32_t kCfgBitCacheBus = 1u << 10;  // Cache / cached SRAM enable bit (0x400)
inline constexpr uint32_t kCfgCacheMask   = kCfgBitIce | kCfgBitCacheBus;

inline constexpr uint32_t kCfgStartupDefault = 0xF00000B0u;
inline constexpr uint32_t kCfgCachedDefault  = 0xF00004AAu;

#define GR(x) (cpu->r[(x) & 15u])
#define GRN(x) (cpu->r[MEP_REG_##x])
#define CR(x) (cpu->CRRef(x))
#define CRN(x) (cpu->control.x)

struct Control {
    uint32_t pc;    // 0:  Program Counter
    uint32_t lp;    // 1:  Link Pointer
    uint32_t sar;   // 2:  Shift Amount Register
    uint32_t r3;    // 3:  Reserved CSR 3
    uint32_t rpb;   // 4:  Repeat Begin Address
    uint32_t rpe;   // 5:  Repeat End Address
    uint32_t rpc;   // 6:  Repeat Count
    uint32_t hi;    // 7:  Multiply/Divide High
    uint32_t lo;    // 8:  Multiply/Divide Low
    uint32_t r9;    // 9:  Reserved CSR 9
    uint32_t r10;   // 10: Reserved CSR 10
    uint32_t r11;   // 11: Reserved CSR 11
    uint32_t mb0;   // 12: Modulo Begin 0
    uint32_t me0;   // 13: Modulo End 0
    uint32_t mb1;   // 14: Modulo Begin 1
    uint32_t me1;   // 15: Modulo End 1
    uint32_t psw;   // 16: Program Status Word
    uint32_t id;    // 17: Processor ID
    uint32_t tmp;   // 18: Temporary Register
    uint32_t epc;   // 19: Exception Program Counter
    uint32_t exc;   // 20: Exception Cause
    uint32_t cfg;   // 21: Configuration Register
    uint32_t vid;   // 22: Version ID (Reserved on some variants)
    uint32_t npc;   // 23: NMI Program Counter
    uint32_t dbg;   // 24: Debug Control Register
    uint32_t depc;  // 25: Debug Exception PC
    uint32_t opt;   // 26: Option Register
    uint32_t rcfg;  // 27: Instruction/Data Cache & Local RAM config
    uint32_t ccfg;  // 28: Cache Configuration Register
    uint32_t r29;   // 29: Reserved CSR 29
    uint32_t r30;   // 30: Reserved CSR 30
    uint32_t r31;   // 31: Reserved CSR 31
};

static_assert(sizeof(Control) == 32 * sizeof(uint32_t), "Control struct must have 32 uint32_t fields");

struct IntcRegs {
    uint32_t ivb = 0x00800000;  // 0: Interrupt Vector Base
    uint32_t isr = 0;           // 1: Interrupt Status
    uint32_t ier = 0;           // 2: Interrupt Enable
    uint32_t iet = 0;           // 3: Interrupt Edge/Trigger Type
    uint32_t ilr0 = 0;          // 4: Interrupt Level 0..7
    uint32_t ilr1 = 0;          // 5: Interrupt Level 8..15
    uint32_t ilr2 = 0;          // 6: Interrupt Level 16..23
    uint32_t ilr3 = 0;          // 7: Interrupt Level 24..31
};

enum class StopReason {
    None = 0,
    Breakpoint,
    Watchpoint,
    BreakInsn,
    DbreakInsn,
    Halt,
    Swi,
    UnmappedMemory,
    InvalidInsn,
};

struct StopInfo {
    StopReason reason = StopReason::None;
    uint32_t pc = 0;
    uint32_t detail = 0;  // e.g. watchpoint/fault addr, SWI number, or raw insn
    bool is_write = false;
};

class Cpu {
public:
    Cpu();

    void Reset(uint32_t entry_pc = 0);

    // Execute one instruction. If ignore_bpt_at_pc is true, skip breakpoint check on current PC (for resume-from-bpt).
    StopInfo Step(bool ignore_bpt_at_pc = false);

    // Raise or service external/software interrupts
    void RaiseIrq(uint32_t irq);
    void ClearIrq(uint32_t irq);
    void Interrupt(uint32_t irq);
    void TriggerSwi(uint32_t code, uint32_t next_pc);
    void ReturnFromException();
    void ReturnFromDebug();

    // Hardware loop helpers
    void BeginRepeat(uint32_t rpb_addr, uint32_t rpe_addr, uint32_t count);
    void BeginErepeat(uint32_t rpb_addr, uint32_t rpe_addr);
    void CancelRepeat();
    bool InActiveRepeatRange(uint32_t addr) const;

    // Modulo addressing wrap for *CPI / coprocessor or DSP helpers
    uint32_t ModuloInc(uint32_t addr, uint32_t inc, uint32_t mb, uint32_t me) const;

    // Control bus access (ldcb / stcb)
    uint32_t ReadControlBus(uint32_t addr) const;
    void WriteControlBus(uint32_t addr, uint32_t val);

    // Direct indexed access to CR[0..31]
    uint32_t GetCR(uint32_t idx) const;
    void SetCR(uint32_t idx, uint32_t val);
    uint32_t &CRRef(uint32_t idx);

    // Direct indexed access to INTC[0..7]
    uint32_t GetIntc(uint32_t idx) const;
    void SetIntc(uint32_t idx, uint32_t val);

    // Execution breakpoints
    void AddBreakpoint(uint32_t addr);
    void RemoveBreakpoint(uint32_t addr);
    bool HasBreakpoint(uint32_t addr) const;
    void ClearBreakpoints();
    std::vector<uint32_t> GetBreakpoints() const;

    void ClearStopRequest();

    static bool IsUncachedSramAddr(uint32_t addr) {
        return addr >= kSramUncachedBase && addr < (kSramUncachedBase + kSramUncachedSize);
    }
    static bool IsCachedSramAddr(uint32_t addr) {
        return addr >= kSramCachedBase && addr < (kSramCachedBase + kSramUncachedSize);
    }
    static bool MirrorSramAddr(uint32_t addr, uint32_t *mirrored_out) {
        uint32_t mirrored = 0;
        if (IsUncachedSramAddr(addr)) {
            mirrored = addr + kSramRemapOffset;
        } else if (IsCachedSramAddr(addr)) {
            mirrored = addr - kSramRemapOffset;
        } else {
            return false;
        }
        if (mirrored_out) {
            *mirrored_out = mirrored;
        }
        return true;
    }
    bool IsInstructionCacheEnabled() const { return (control.cfg & kCfgBitIce) != 0u; }
    bool IsCacheEnabled() const { return (control.cfg & kCfgCacheMask) == kCfgCacheMask; }
    bool IsVectorBaseRemapped() const { return (control.cfg & kCfgBitEvm) == 0u; }

    Memory mem;
    uint32_t r[16] = {};
    Control control = {};
    IntcRegs intc = {};
    std::unordered_map<uint32_t, uint32_t> cb_regs;

    // Step / repeat / execution state
    uint32_t cur_pc = 0;
    int32_t rpb_in = -1;
    bool erepeat_active = false;
    bool branched = false;
    bool sleeping = false;
    uint64_t step_count = 0;

    // Exception/trap behavior controls
    bool stop_on_unmapped = true;
    bool stop_on_halt = true;
    bool stop_on_break = true;
    bool swi_breaks_to_debugger = false;

    // Stop info populated by special instructions (break, dbreak, halt, swi)
    StopInfo pending_stop = {};

private:
    void ApplyCfgWrite(uint32_t new_cfg);
    bool ServicePendingInterrupt();
    std::unordered_set<uint32_t> breakpoints_;
};
