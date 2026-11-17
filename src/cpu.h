#pragma once

#include <cstdint>
#include <functional>
#include <string>
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

// RPE ($rpe, CR5) bits
inline constexpr uint32_t kRpeBitElr      = 1u << 0;   // 1 = EREPEAT, 0 = REPEAT

// PSW ($psw, CR16) bits
inline constexpr uint32_t kPswBitIec      = 1u << 0;   // Interrupt Enable Current
inline constexpr uint32_t kPswBitIep      = 1u << 1;   // Interrupt Enable Previous
inline constexpr uint32_t kPswBitUmc      = 1u << 2;   // User Mode Current
inline constexpr uint32_t kPswBitUmp      = 1u << 3;   // User Mode Previous
inline constexpr uint32_t kPswShiftSie    = 4u;        // SIE0..SIE3 bits [7:4]
inline constexpr uint32_t kPswMaskSie     = 0xFu << 4;
inline constexpr uint32_t kPswBitHie      = 1u << 8;   // Hardware Interrupt Enable
inline constexpr uint32_t kPswBitNmi      = 1u << 9;   // NMI processing flag
inline constexpr uint32_t kPswBitHalt     = 1u << 11;  // HALT / SLEEP status flag
inline constexpr uint32_t kPswBitOm       = 1u << 12;  // Operating Mode (0=core, 1=VLIW)
inline constexpr uint32_t kPswWritableMask = 0x13FFu;

// EXC ($exc, CR20) bits and codes
inline constexpr uint32_t kExcMaskCode    = 0xFu;      // Exception cause code [3:0]
inline constexpr uint32_t kExcCodeInt     = 0u;
inline constexpr uint32_t kExcCodeRi      = 2u;
inline constexpr uint32_t kExcCodeZdiv    = 3u;
inline constexpr uint32_t kExcCodeBrk     = 4u;
inline constexpr uint32_t kExcCodeSwi     = 5u;
inline constexpr uint32_t kExcShiftSip    = 4u;        // SIP0..SIP3 bits [7:4]
inline constexpr uint32_t kExcMaskSip     = 0xFu << 4;
inline constexpr uint32_t kExcBitHip      = 1u << 8;   // Hardware Interrupt Pending (RO)
inline constexpr uint32_t kExcBitBer      = 1u << 12;  // Bus Error (RW0)
inline constexpr uint32_t kExcBitDrc      = 1u << 13;  // Data Read Check (RO)

// DBG ($dbg, CR24) bits
inline constexpr uint32_t kDbgBitDss      = 1u << 0;   // Single step
inline constexpr uint32_t kDbgBitDbp      = 1u << 1;   // DBREAK instruction
inline constexpr uint32_t kDbgBitDdbl     = 1u << 2;   // Data address/value break load
inline constexpr uint32_t kDbgBitDdbs     = 1u << 3;   // Data address/value break store
inline constexpr uint32_t kDbgBitDib      = 1u << 4;   // Instruction address break
inline constexpr uint32_t kDbgBitDint     = 1u << 5;   // Debug interrupt
inline constexpr uint32_t kDbgBitJtrst    = 1u << 7;   // DSU reset
inline constexpr uint32_t kDbgBitSst      = 1u << 8;   // Single-step enable
inline constexpr uint32_t kDbgBitBsf      = 1u << 10;  // Bus stall / debug bus error (RW0)
inline constexpr uint32_t kDbgBitDm       = 1u << 15;  // Debug mode

// Timer/Counter TCR bits (0x0403 / 0x0413 / 0x0423 / 0x0433)
inline constexpr uint32_t kTimerTcrTie    = 1u << 0;   // Timer Interrupt Enable
inline constexpr uint32_t kTimerTcrTmd    = 1u << 4;   // Timer Mode (0=interval, 1=watchdog, Ch0 only)
inline constexpr uint32_t kTimerTcrTai    = 1u << 5;   // Auto Initialization on compare match

// DSU DCR bits (0x0800)
inline constexpr uint32_t kDsuDcrBitEnmi  = 1u << 3;   // Enable NMI in normal mode
inline constexpr uint32_t kDsuDcrBitEint  = 1u << 4;   // Enable HW interrupt in normal mode
inline constexpr uint32_t kDsuDcrBitSls   = 1u << 13;  // Sleep status on DINT
inline constexpr uint32_t kDsuDcrBitHls   = 1u << 14;  // Halt status on DINT

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
    uint32_t ivb = 0x00800000;  // 0: Interrupt Vector Base (MMIO 0xE3000000 / debugger alias)
    uint32_t isr = 0;           // 1: Interrupt Status
    uint32_t ier = 0;           // 2: Interrupt Enable
    uint32_t iet = 0;           // 3: Interrupt Edge/Trigger Type (0=level, 1=edge)
    uint32_t ilr0 = 0;          // 4: Interrupt Level 0..7
    uint32_t ilr1 = 0;          // 5: Interrupt Level 8..15
    uint32_t ilr2 = 0;          // 6: Interrupt Level 16..23
    uint32_t ilr3 = 0;          // 7: Interrupt Level 24..31
    uint32_t ivr = 0;           // cb 0x0000: Interrupt Vector Register ([15:12] ILV, [11:8] IML, [7:3] ICN)
};

struct TimerChannel {
    uint32_t cnt = 1;           // +0: Counter (initial 1)
    uint32_t cmp = 0;           // +1: Compare
    uint32_t ten = 0;           // +2: Timer Enable (bit 0)
    uint32_t tcr = 0;           // +3: Timer Control (TAI=5, TMD=4 ch0-only, TIE=0)
    uint32_t tis = 0;           // +4: Timer Interrupt Status (bit 0, W0C)
    uint32_t tcd = 0;           // +5: Clock Divide (bits 2:0 -> 2^tcd)
    uint32_t prescaler = 0;     // Internal clock divider counter
};

struct DsuRegs {
    uint32_t dcr = 0x18u;       // 0x0800: Debug Control (EINT=4, ENMI=3)
    uint32_t ibs = 0x01000000u; // 0x0801: Instruction Break Status (BCN=1, BS0=0)
    uint32_t dbs = 0x01000000u; // 0x0802: Data Break Status (BCN=1, BS0=0)
    uint32_t tcr = 0;           // 0x0803: Trace Control
    uint32_t iba0 = 0;          // 0x0900: Instruction Break Address 0
    uint32_t ibc0 = 0;          // 0x0901: Instruction Break Control 0
    uint32_t ibm0 = 0;          // 0x0902: Instruction Break Mask 0
    uint32_t dba0 = 0;          // 0x0A00: Data Break Address 0
    uint32_t dbc0 = 0;          // 0x0A01: Data Break Control 0
    uint32_t dbm0 = 0;          // 0x0A02: Data Break Mask 0
    uint32_t db0 = 0;           // 0x0A04: Data Value Break 0
    uint32_t dbu0 = 0;          // 0x0A05: Data Value Break Upper 0
    bool x_probe_en = false;    // Select debug vector 0x00700018 (true) vs 0x00000018 (false)
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

enum class SwiMode {
    Auto = 0, // Dispatch +0x14 when present; fall back to HLE (if swi_hle_fallback) or Trap
    Arch,     // Architectural +0x14 vector dispatch only (Trap if unmapped/uninstalled)
    Hle,      // Always invoke HLE SWI handler (skip guest +0x14 vector)
    Trap,     // Always break to debugger with StopReason::Swi
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

    // Raise or service external/software interrupts & debug events
    void RaiseIrq(uint32_t irq);
    void ClearIrq(uint32_t irq);
    void Interrupt(uint32_t irq);
    void RaiseNmi();
    void RaiseDebugInterrupt();
    void TriggerSwi(uint32_t code, uint32_t next_pc);
    void RaiseSwiSignal(uint32_t swi_num);
    void TriggerBreak(uint32_t break_pc);
    void TriggerDbreak(uint32_t dbreak_pc);
    void EnterSleep();
    void EnterHalt();
    void ReturnFromException();
    void ReturnFromDebug();

    // Prepare warm-snapshot / applet execution state (arms PSW.IEC|HIE|SIE0, IVB/IVR/ILR/CFG without wiping RAM)
    void PrepareAppletContext(uint32_t entry_pc = 0, uint32_t sp = 0,
                              uint32_t arg1 = 0, uint32_t arg2 = 0);

    using SwiHleHandler = std::function<bool(Cpu &, uint32_t swi_num)>;
    void SetSwiHleHandler(SwiHleHandler handler) { swi_hle_handler_ = std::move(handler); }
    static const char *SwiModeName(SwiMode mode);

    // Hardware loop helpers
    void BeginRepeat(uint32_t rpb_addr, uint32_t rpe_addr, uint32_t count);
    void BeginErepeat(uint32_t rpb_addr, uint32_t rpe_addr);
    void CancelRepeat();
    bool IsRepeatActive() const { return repeat_active || erepeat_active; }
    bool InActiveRepeatRange(uint32_t addr) const;

    // Modulo addressing wrap for *CPI / coprocessor or DSP helpers
    uint32_t ModuloInc(uint32_t addr, uint32_t inc, uint32_t mb, uint32_t me) const;

    // Control bus access (ldcb / stcb enforces DSU Debug Mode; *Raw bypasses for host debugger)
    uint32_t ReadControlBus(uint32_t addr) const;
    void WriteControlBus(uint32_t addr, uint32_t val);
    uint32_t ReadControlBusRaw(uint32_t addr) const;
    void WriteControlBusRaw(uint32_t addr, uint32_t val);
    static bool IsMappedControlBusAddr(uint32_t addr);

    // Timer/Counter and DSU subsystem helpers
    void TickTimers(uint32_t cycles = 1);
    uint32_t GetTimerReg(uint32_t addr) const;
    void SetTimerReg(uint32_t addr, uint32_t val);
    uint32_t GetDsuReg(uint32_t addr) const;
    void SetDsuReg(uint32_t addr, uint32_t val);
    void ResetDsu();
    void CheckDsuDataBreak(uint32_t addr, uint32_t sz, uint32_t val, bool is_write);

    // Direct indexed access to CR[0..31]
    uint32_t GetCR(uint32_t idx) const;
    void SetCR(uint32_t idx, uint32_t val, bool from_debugger = false);
    uint32_t &CRRef(uint32_t idx);

    // Direct indexed access to INTC[0..7] and IVR
    uint32_t GetIntc(uint32_t idx) const;
    void SetIntc(uint32_t idx, uint32_t val);
    uint32_t GetEffectiveIvr() const;
    bool HasActiveUnmaskedIrq() const;

    // Shared debugger/monitor formatting and inspection commands
    std::string FormatCsrState(const char *filter = nullptr) const;
    std::string FormatIntcState() const;
    std::string FormatTimersState() const;
    std::string FormatDsuState() const;
    bool TryHandleCoreCommand(const std::string &cmd, std::string *out);

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
    TimerChannel timers[4] = {};
    DsuRegs dsu = {};
    std::unordered_map<uint32_t, uint32_t> cb_regs;

    // Step / repeat / execution state
    uint32_t cur_pc = 0;
    int32_t rpb_in = -1;
    bool repeat_active = false;
    bool erepeat_active = false;
    bool repeat_will_loop = false;
    bool branched = false;
    bool sleeping = false;
    bool halted = false;
    bool pending_nmi = false;
    bool pending_dint = false;
    uint32_t pending_dsu_causes = 0;
    uint64_t step_count = 0;

    // Exception/trap behavior controls
    bool stop_on_unmapped = true;
    bool stop_on_halt = true;
    bool stop_on_break = true;
    bool swi_breaks_to_debugger = false;
    bool dsu_break_to_debugger = false;
    SwiMode swi_mode = SwiMode::Auto;
    bool swi_hle_fallback = true;
    uint32_t hle_signal_flags = 0;
    uint32_t hle_irq_handlers[12] = {};

    // Stop info populated by special instructions (break, dbreak, halt, swi)
    StopInfo pending_stop = {};

private:
    void ApplyCfgWrite(uint32_t new_cfg);
    bool FindHighestActiveIrq(uint32_t *best_irq, uint32_t *best_prio) const;
    bool IsTimerLevelActive(uint32_t ch) const;
    void UpdateTimerIrqLine(uint32_t ch);
    void RecomputeTimerIrqLines();
    bool ServiceNmi();
    bool ResolveSwiVector(uint32_t *vector_out);
    void ExecuteSwiHle(uint32_t swi_num, uint32_t exc_pc);
    bool ServiceSwi(uint32_t swi_num, uint32_t exc_pc, bool from_swi_insn);
    bool ServicePendingInterrupt();
    void EnterDebugException(uint32_t dbg_causes, uint32_t exc_pc);
    SwiHleHandler swi_hle_handler_;
    std::unordered_set<uint32_t> breakpoints_;
};
