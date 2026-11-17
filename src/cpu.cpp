#include "cpu.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>

#include "insn.h"
#include "log.h"
#include "util.h"

namespace {

bool IsTimerCbAddr(uint32_t addr) {
    return (addr >= 0x0400u && addr <= 0x0435u) && ((addr & 0xFF00u) == 0x0400u) &&
           (((addr >> 4) & 0xFu) < 4u) && ((addr & 0xFu) <= 5u);
}

bool IsDsuCbAddr(uint32_t addr) {
    if (addr >= 0x0800u && addr <= 0x0803u) return true;
    if (addr >= 0x0900u && addr <= 0x0902u) return true;
    if (addr >= 0x0A00u && addr <= 0x0A05u && addr != 0x0A03u) return true;
    return false;
}

const char *const kCsrNamesLower[32] = {
    "pc", "lp", "sar", "csr3", "rpb", "rpe", "rpc", "hi",
    "lo", "csr9", "csr10", "csr11", "mb0", "me0", "mb1", "me1",
    "psw", "id", "tmp", "epc", "exc", "cfg", "vid", "npc",
    "dbg", "depc", "opt", "rcfg", "ccfg", "csr29", "csr30", "csr31"
};

std::string TrimAscii(const std::string &s) {
    size_t start = 0;
    while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
        ++start;
    }
    size_t end = s.size();
    while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
        --end;
    }
    return s.substr(start, end - start);
}

std::string LowerAscii(std::string s) {
    for (char &ch : s) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return s;
}

} // namespace

Cpu *g_cpu = nullptr;

Cpu::Cpu() {
    Reset(0);
}

void Cpu::ResetDsu() {
    const bool keep_probe = dsu.x_probe_en;
    dsu = DsuRegs{};
    dsu.x_probe_en = keep_probe;
}

void Cpu::Reset(uint32_t entry_pc) {
    std::memset(r, 0, sizeof(r));
    std::memset(&control, 0, sizeof(control));

    const uint32_t masked_pc = entry_pc & ~1u;
    const bool startup_at_uncached = IsUncachedSramAddr(masked_pc);

    control.pc = masked_pc;
    control.cfg = startup_at_uncached ? kCfgStartupDefault : kCfgCachedDefault;
    control.ccfg = 0x5B105B08u;
    control.rcfg = 0x01000100u;
    control.opt = 0x03FD0201u;
    control.id = 0x00000100u;

    intc = IntcRegs{};
    intc.ivb = startup_at_uncached ? kSramUncachedBase : kSramCachedBase;
    for (uint32_t i = 0; i < 4; ++i) {
        timers[i] = TimerChannel{};
    }
    dsu = DsuRegs{};
    cb_regs.clear();

    cur_pc = control.pc;
    rpb_in = -1;
    repeat_active = false;
    erepeat_active = false;
    repeat_will_loop = false;
    branched = false;
    sleeping = false;
    halted = false;
    pending_nmi = false;
    pending_dint = false;
    pending_dsu_causes = 0;
    step_count = 0;
    hle_signal_flags = 0;
    std::memset(hle_irq_handlers, 0, sizeof(hle_irq_handlers));
    pending_stop = StopInfo{};

    mem.ClearFaults();
    g_cpu = this;
}

const char *Cpu::SwiModeName(SwiMode mode) {
    switch (mode) {
    case SwiMode::Auto: return "auto";
    case SwiMode::Arch: return "arch";
    case SwiMode::Hle:  return "hle";
    case SwiMode::Trap: return "trap";
    default:            return "auto";
    }
}

void Cpu::RaiseSwiSignal(uint32_t swi_num) {
    control.exc |= (1u << (kExcShiftSip + (swi_num & 3u)));
}

void Cpu::PrepareAppletContext(uint32_t entry_pc, uint32_t sp,
                               uint32_t arg1, uint32_t arg2) {
    if (entry_pc != 0u) {
        control.pc = entry_pc & ~1u;
    }
    const bool uncached = IsUncachedSramAddr(control.pc);
    control.cfg = uncached ? (kCfgStartupDefault | kCfgBitIvm) : kCfgCachedDefault;
    intc.ivb = uncached ? kSramUncachedBase : kSramCachedBase;
    intc.ivr = 0x0600u; // IML = 6 (matches Vita F00D sub_8002C0)
    if (intc.ier == 0u) {
        intc.ier = 1u << 8; // IRQ 8 mailbox enable
    }
    if (intc.ilr0 == 0u && intc.ilr1 == 0u) {
        intc.ilr0 = 0x07777777u;
        intc.ilr1 = 0x0000777Fu;
    }
    control.psw = kPswBitIec | kPswBitHie | (1u << kPswShiftSie); // IEC | HIE | SIE0
    if (sp != 0u) {
        r[MEP_REG_sp] = sp;
    } else if (r[MEP_REG_sp] == 0u) {
        r[MEP_REG_sp] = uncached ? 0x0005FF80u : 0x0081FF80u;
    }
    if (arg1 != 0u) {
        r[1] = arg1;
    }
    if (arg2 != 0u) {
        r[2] = arg2;
    }
    sleeping = false;
    halted = false;
    pending_nmi = false;
    pending_stop = StopInfo{};
    CancelRepeat();
}

uint32_t &Cpu::CRRef(uint32_t idx) {
    switch (idx & 31u) {
    case 0: return control.pc;
    case 1: return control.lp;
    case 2: return control.sar;
    case 3: return control.r3;
    case 4: return control.rpb;
    case 5: return control.rpe;
    case 6: return control.rpc;
    case 7: return control.hi;
    case 8: return control.lo;
    case 9: return control.r9;
    case 10: return control.r10;
    case 11: return control.r11;
    case 12: return control.mb0;
    case 13: return control.me0;
    case 14: return control.mb1;
    case 15: return control.me1;
    case 16: return control.psw;
    case 17: return control.id;
    case 18: return control.tmp;
    case 19: return control.epc;
    case 20: return control.exc;
    case 21: return control.cfg;
    case 22: return control.vid;
    case 23: return control.npc;
    case 24: return control.dbg;
    case 25: return control.depc;
    case 26: return control.opt;
    case 27: return control.rcfg;
    case 28: return control.ccfg;
    case 29: return control.r29;
    case 30: return control.r30;
    case 31: return control.r31;
    default: return control.pc;
    }
}

uint32_t Cpu::GetCR(uint32_t idx) const {
    const uint32_t cr_idx = idx & 31u;
    if (cr_idx == 16u) {
        return (sleeping || halted) ? (control.psw | kPswBitHalt) : control.psw;
    }
    if (cr_idx == 20u) {
        return (control.exc & ~kExcBitHip) | (HasActiveUnmaskedIrq() ? kExcBitHip : 0u);
    }
    return const_cast<Cpu *>(this)->CRRef(cr_idx);
}

void Cpu::SetCR(uint32_t idx, uint32_t val, bool from_debugger) {
    const uint32_t cr_idx = idx & 31u;
    if (cr_idx == 21u) {
        ApplyCfgWrite(val);
        return;
    }

    if (from_debugger) {
        if (cr_idx == 0u) {
            control.pc = val & ~1u;
            return;
        }
        if (cr_idx == 5u) {
            control.rpe = val;
            erepeat_active = (val & kRpeBitElr) != 0u;
            if (erepeat_active) {
                repeat_active = false;
            }
            return;
        }
        CRRef(cr_idx) = val;
        return;
    }

    switch (cr_idx) {
    case 0:  // $pc is RO for guest stc
    case 3:  // Reserved CSRs
    case 9:
    case 10:
    case 11:
    case 17: // $id RO
    case 22: // $vid RO
    case 26: // $opt RO
    case 27: // $rcfg RO
    case 28: // $ccfg RO
    case 29:
    case 30:
    case 31:
        return;
    case 2: // $sar: bits 5:0
        control.sar = val & 0x3Fu;
        return;
    case 4:  // $rpb
    case 19: // $epc
    case 23: // $npc
    case 25: // $depc
        CRRef(cr_idx) = val & ~1u;
        return;
    case 5: // $rpe
        control.rpe = val;
        erepeat_active = (val & kRpeBitElr) != 0u;
        if (erepeat_active) {
            repeat_active = false;
        }
        return;
    case 12: // $mb0
    case 13: // $me0
    case 14: // $mb1
    case 15: // $me1
        CRRef(cr_idx) = val & 0xFFFFu;
        return;
    case 16: // $psw: preserve HALT status bit 11
        control.psw = (control.psw & kPswBitHalt) | (val & kPswWritableMask);
        return;
    case 20: { // $exc: SIP3..0 R/W, BER RW0, EXC/HIP/DRC RO
        uint32_t next_exc = (control.exc & (kExcMaskCode | kExcBitDrc)) | (val & kExcMaskSip);
        if ((val & kExcBitBer) != 0u) {
            next_exc |= (control.exc & kExcBitBer);
        }
        control.exc = next_exc;
        return;
    }
    case 24: { // $dbg: DM RO, BSF & [5:0] RW0, SST & JTRST RW
        const uint32_t dm = control.dbg & kDbgBitDm;
        const uint32_t rw0_mask = kDbgBitBsf | 0x3Fu;
        const uint32_t preserved_rw0 = control.dbg & (val & rw0_mask);
        if ((val & kDbgBitJtrst) != 0u) {
            ResetDsu();
        }
        control.dbg = dm | preserved_rw0 | (val & (kDbgBitSst | kDbgBitJtrst));
        return;
    }
    default:
        CRRef(cr_idx) = val;
        return;
    }
}

void Cpu::ApplyCfgWrite(uint32_t new_cfg) {
    const uint32_t prev_cfg = control.cfg;
    control.cfg = new_cfg;

    // $cfg never rewrites PC: switching from uncached 0x00040000 to cached 0x00800000
    // happens via an explicit jump/branch (e.g. `jmp 0x800360`) after setting ICE (bit 1)
    // and bit 10 (0x400). Clearing EVM (bit 4) relocates the exception/interrupt vector base ($ivb).
    const bool evm_was_set = (prev_cfg & kCfgBitEvm) != 0u;
    const bool evm_is_set  = (new_cfg & kCfgBitEvm) != 0u;
    if (evm_was_set && !evm_is_set && (intc.ivb & ~0xFFu) == kSramUncachedBase) {
        intc.ivb += kSramRemapOffset;
        LOG("CFG vector remap: cfg 0x%08x -> 0x%08x (PC=0x%08x, IVB=0x%08x)",
            prev_cfg, new_cfg, control.pc, intc.ivb);
    } else if (!evm_was_set && evm_is_set && (intc.ivb & ~0xFFu) == kSramCachedBase) {
        intc.ivb -= kSramRemapOffset;
        LOG("CFG vector unmap: cfg 0x%08x -> 0x%08x (PC=0x%08x, IVB=0x%08x)",
            prev_cfg, new_cfg, control.pc, intc.ivb);
    }

    if ((prev_cfg & kCfgCacheMask) != (new_cfg & kCfgCacheMask)) {
        LOG("CFG cache state changed: cfg 0x%08x -> 0x%08x (ICE=%d, cache_bus=%d, PC=0x%08x)",
            prev_cfg, new_cfg,
            (new_cfg & kCfgBitIce) != 0u ? 1 : 0,
            (new_cfg & kCfgBitCacheBus) != 0u ? 1 : 0,
            control.pc);
    }
}

uint32_t Cpu::GetIntc(uint32_t idx) const {
    switch (idx) {
    case 0: return intc.ivb;
    case 1: return intc.isr;
    case 2: return intc.ier;
    case 3: return intc.iet;
    case 4: return intc.ilr0;
    case 5: return intc.ilr1;
    case 6: return intc.ilr2;
    case 7: return intc.ilr3;
    default: return 0;
    }
}

void Cpu::SetIntc(uint32_t idx, uint32_t val) {
    switch (idx) {
    case 0: intc.ivb = val; break;
    case 1: intc.isr = val; break;
    case 2: intc.ier = val; break;
    case 3: intc.iet = val; break;
    case 4: intc.ilr0 = val; break;
    case 5: intc.ilr1 = val; break;
    case 6: intc.ilr2 = val; break;
    case 7: intc.ilr3 = val; break;
    default: break;
    }
}

bool Cpu::FindHighestActiveIrq(uint32_t *best_irq, uint32_t *best_prio) const {
    const uint32_t iml = (intc.ivr >> 8) & 0xFu;
    const uint32_t pending = intc.isr & intc.ier;
    if (pending == 0u) {
        return false;
    }

    uint32_t win_irq = 0;
    uint32_t win_prio = 0;
    bool found = false;
    for (uint32_t i = 0; i < 32u; ++i) {
        if ((pending & (1u << i)) == 0u) {
            continue;
        }
        const uint32_t ilr = GetIntc(4u + (i >> 3));
        const uint32_t prio = (ilr >> ((i & 7u) * 4u)) & 0xFu;
        if (prio > iml && (!found || prio > win_prio)) {
            found = true;
            win_prio = prio;
            win_irq = i;
        }
    }
    if (!found) {
        return false;
    }
    if (best_irq) {
        *best_irq = win_irq;
    }
    if (best_prio) {
        *best_prio = win_prio;
    }
    return true;
}

bool Cpu::HasActiveUnmaskedIrq() const {
    return FindHighestActiveIrq(nullptr, nullptr);
}

uint32_t Cpu::GetEffectiveIvr() const {
    const uint32_t iml = (intc.ivr >> 8) & 0xFu;
    uint32_t irq = 0;
    uint32_t prio = 0;
    if (FindHighestActiveIrq(&irq, &prio)) {
        return ((prio & 0xFu) << 12) | (iml << 8) | ((irq & 0x1Fu) << 3);
    }
    return iml << 8;
}

bool Cpu::IsTimerLevelActive(uint32_t ch) const {
    if (ch >= 4u) {
        return false;
    }
    const TimerChannel &t = timers[ch];
    if (ch == 0u && (t.tcr & kTimerTcrTmd) != 0u) {
        return false;
    }
    return (t.tcr & kTimerTcrTie) != 0u && (t.tis & 1u) != 0u;
}

void Cpu::UpdateTimerIrqLine(uint32_t ch) {
    if (ch >= 4u) {
        return;
    }
    const uint32_t mask = 1u << ch;
    if (IsTimerLevelActive(ch)) {
        intc.isr |= mask;
        if (HasActiveUnmaskedIrq()) {
            sleeping = false;
            halted = false;
            control.psw &= ~kPswBitHalt;
        }
    } else if ((intc.iet & mask) == 0u) {
        intc.isr &= ~mask;
    }
}

void Cpu::RecomputeTimerIrqLines() {
    for (uint32_t ch = 0; ch < 4u; ++ch) {
        UpdateTimerIrqLine(ch);
    }
}

uint32_t Cpu::GetTimerReg(uint32_t addr) const {
    if (!IsTimerCbAddr(addr)) {
        return 0;
    }
    const TimerChannel &t = timers[(addr >> 4) & 3u];
    switch (addr & 0xFu) {
    case 0: return t.cnt;
    case 1: return t.cmp;
    case 2: return t.ten & 1u;
    case 3: return t.tcr;
    case 4: return t.tis & 1u;
    case 5: return t.tcd & 7u;
    default: return 0;
    }
}

void Cpu::SetTimerReg(uint32_t addr, uint32_t val) {
    if (!IsTimerCbAddr(addr)) {
        return;
    }
    const uint32_t ch = (addr >> 4) & 3u;
    TimerChannel &t = timers[ch];
    switch (addr & 0xFu) {
    case 0:
        t.cnt = val;
        break;
    case 1:
        t.cmp = val;
        break;
    case 2:
        t.ten = val & 1u;
        break;
    case 3: {
        uint32_t mask = kTimerTcrTai | kTimerTcrTie;
        if (ch == 0u) {
            mask |= kTimerTcrTmd;
        }
        t.tcr = val & mask;
        UpdateTimerIrqLine(ch);
        break;
    }
    case 4:
        // Bit 0 is W0C: writing 0 clears TIS, writing 1 is ignored.
        if ((val & 1u) == 0u) {
            t.tis &= ~1u;
        }
        UpdateTimerIrqLine(ch);
        break;
    case 5:
        t.tcd = val & 7u;
        break;
    default:
        break;
    }
}

void Cpu::TickTimers(uint32_t cycles) {
    for (uint32_t cyc = 0; cyc < cycles; ++cyc) {
        for (uint32_t ch = 0; ch < 4u; ++ch) {
            TimerChannel &t = timers[ch];
            if ((t.ten & 1u) == 0u) {
                continue;
            }
            const uint32_t div = 1u << (t.tcd & 7u);
            ++t.prescaler;
            if (t.prescaler < div) {
                continue;
            }
            t.prescaler = 0u;
            ++t.cnt;
            if (t.cnt == t.cmp) {
                const bool prev_tis = (t.tis & 1u) != 0u;
                t.tis |= 1u;
                if ((t.tcr & kTimerTcrTai) != 0u) {
                    t.cnt = 1u;
                } else {
                    t.ten &= ~1u;
                }
                if (ch == 0u && (t.tcr & kTimerTcrTmd) != 0u) {
                    if (!prev_tis && (t.tcr & kTimerTcrTie) != 0u) {
                        RaiseNmi();
                    }
                } else {
                    UpdateTimerIrqLine(ch);
                }
            }
        }
    }
}

uint32_t Cpu::GetDsuReg(uint32_t addr) const {
    switch (addr) {
    case 0x0800u: return dsu.dcr;
    case 0x0801u: return (dsu.ibs & 1u) | 0x01000000u;
    case 0x0802u: return (dsu.dbs & 1u) | 0x01000000u;
    case 0x0803u: return dsu.tcr & 1u;
    case 0x0900u: return dsu.iba0 & ~1u;
    case 0x0901u: return dsu.ibc0 & 3u;
    case 0x0902u: return dsu.ibm0 & ~1u;
    case 0x0A00u: return dsu.dba0 & ~3u;
    case 0x0A01u: return dsu.dbc0 & 0x003FFFF3u;
    case 0x0A02u: return dsu.dbm0 & ~3u;
    case 0x0A04u: return dsu.db0;
    case 0x0A05u: return dsu.dbu0;
    default: return 0;
    }
}

void Cpu::SetDsuReg(uint32_t addr, uint32_t val) {
    switch (addr) {
    case 0x0800u:
        dsu.dcr = (dsu.dcr & (kDsuDcrBitHls | kDsuDcrBitSls)) |
                  (val & (kDsuDcrBitEint | kDsuDcrBitEnmi));
        break;
    case 0x0801u:
        if ((val & 1u) == 0u) {
            dsu.ibs &= ~1u;
        }
        break;
    case 0x0802u:
        if ((val & 1u) == 0u) {
            dsu.dbs &= ~1u;
        }
        break;
    case 0x0803u:
        dsu.tcr = val & 1u;
        break;
    case 0x0900u:
        dsu.iba0 = val & ~1u;
        break;
    case 0x0901u:
        dsu.ibc0 = val & 3u;
        break;
    case 0x0902u:
        dsu.ibm0 = val & ~1u;
        break;
    case 0x0A00u:
        dsu.dba0 = val & ~3u;
        break;
    case 0x0A01u:
        dsu.dbc0 = val & 0x003FFFF3u;
        break;
    case 0x0A02u:
        dsu.dbm0 = val & ~3u;
        break;
    case 0x0A04u:
        dsu.db0 = val;
        break;
    case 0x0A05u:
        dsu.dbu0 = val;
        break;
    default:
        break;
    }
}

bool Cpu::IsMappedControlBusAddr(uint32_t addr) {
    return addr < 8u || IsTimerCbAddr(addr) || IsDsuCbAddr(addr) ||
           (addr >= 0x2000u && addr <= 0x207Cu && (addr & 3u) == 0u);
}

uint32_t Cpu::ReadControlBusRaw(uint32_t addr) const {
    if (addr == 0u) {
        return GetEffectiveIvr();
    }
    if (addr < 8u) {
        return GetIntc(addr);
    }
    if (IsTimerCbAddr(addr)) {
        return GetTimerReg(addr);
    }
    if (IsDsuCbAddr(addr)) {
        return GetDsuReg(addr);
    }
    if (addr >= 0x2000u && addr <= 0x207Cu && (addr & 3u) == 0u) {
        return GetCR((addr - 0x2000u) >> 2);
    }
    auto it = cb_regs.find(addr);
    if (it != cb_regs.end()) {
        return it->second;
    }
    LOG("ReadControlBus: unmapped reg 0x%04x (pc=0x%08x)", addr, cur_pc);
    return 0;
}

void Cpu::WriteControlBusRaw(uint32_t addr, uint32_t val) {
    if (addr == 0u) {
        intc.ivr = val & 0x0F00u;
        if (HasActiveUnmaskedIrq()) {
            sleeping = false;
            halted = false;
            control.psw &= ~kPswBitHalt;
        }
        return;
    }
    if (addr == 1u) {
        intc.isr &= val;
        RecomputeTimerIrqLines();
        return;
    }
    if (addr < 8u) {
        SetIntc(addr, val);
        if (addr == 3u) {
            RecomputeTimerIrqLines();
        }
        if (HasActiveUnmaskedIrq()) {
            sleeping = false;
            halted = false;
            control.psw &= ~kPswBitHalt;
        }
        return;
    }
    if (IsTimerCbAddr(addr)) {
        SetTimerReg(addr, val);
        return;
    }
    if (IsDsuCbAddr(addr)) {
        SetDsuReg(addr, val);
        return;
    }
    if (addr >= 0x2000u && addr <= 0x207Cu && (addr & 3u) == 0u) {
        SetCR((addr - 0x2000u) >> 2, val);
        return;
    }
    cb_regs[addr] = val;
    LOG("WriteControlBus: reg 0x%04x <= 0x%08x (pc=0x%08x)", addr, val, cur_pc);
}

uint32_t Cpu::ReadControlBus(uint32_t addr) const {
    if (IsDsuCbAddr(addr) && (control.dbg & kDbgBitDm) == 0u) {
        LOG("ReadControlBus: DSU reg 0x%04x read outside debug mode (pc=0x%08x)", addr, cur_pc);
        return 0;
    }
    return ReadControlBusRaw(addr);
}

void Cpu::WriteControlBus(uint32_t addr, uint32_t val) {
    if (IsDsuCbAddr(addr) && (control.dbg & kDbgBitDm) == 0u) {
        LOG("WriteControlBus: DSU reg 0x%04x write outside debug mode ignored (pc=0x%08x)", addr, cur_pc);
        return;
    }
    WriteControlBusRaw(addr, val);
}

void Cpu::RaiseIrq(uint32_t irq) {
    if (irq < 32u) {
        intc.isr |= (1u << irq);
        if ((intc.ier & (1u << irq)) != 0u && HasActiveUnmaskedIrq()) {
            sleeping = false;
            halted = false;
            control.psw &= ~kPswBitHalt;
        }
    }
}

void Cpu::ClearIrq(uint32_t irq) {
    if (irq < 32u) {
        intc.isr &= ~(1u << irq);
    }
}

void Cpu::Interrupt(uint32_t irq) {
    RaiseIrq(irq);
    ServicePendingInterrupt();
}

void Cpu::RaiseNmi() {
    pending_nmi = true;
    sleeping = false;
    halted = false;
    control.psw &= ~kPswBitHalt;
}

void Cpu::RaiseDebugInterrupt() {
    pending_dint = true;
}

bool Cpu::ServiceNmi() {
    if (!pending_nmi ||
        (control.psw & kPswBitNmi) != 0u ||
        (control.dbg & kDbgBitDm) != 0u ||
        (dsu.dcr & kDsuDcrBitEnmi) == 0u) {
        return false;
    }

    uint32_t vector = 0x00000004u;
    uint32_t vector_word = 0;
    if (!mem.TryRead(vector, sizeof(vector_word), &vector_word) || vector_word == 0u) {
        vector = (intc.ivb & ~0xFFu) + 0x04u;
        if (!mem.TryRead(vector, sizeof(vector_word), &vector_word) || vector_word == 0u) {
            return false;
        }
    }

    pending_nmi = false;
    sleeping = false;
    halted = false;
    control.psw &= ~(kPswBitHalt | kPswBitOm);
    control.npc = control.pc & ~1u;
    control.psw |= kPswBitNmi;

    CancelRepeat();
    control.pc = vector;
    branched = true;
    LOG("NMI dispatched -> vector 0x%08x (npc=0x%08x)", vector, control.npc);
    return true;
}

bool Cpu::ResolveSwiVector(uint32_t *vector_out) {
    uint32_t vector = (intc.ivb & ~0xFFu) + 0x14u;
    uint32_t vector_word = 0;
    if (mem.TryRead(vector, sizeof(vector_word), &vector_word) && vector_word != 0u) {
        if (vector_out) {
            *vector_out = vector;
        }
        return true;
    }
    if ((control.cfg & kCfgBitEvm) == 0u) {
        vector = 0x00000014u;
        if (mem.TryRead(vector, sizeof(vector_word), &vector_word) && vector_word != 0u) {
            if (vector_out) {
                *vector_out = vector;
            }
            return true;
        }
    }
    return false;
}

void Cpu::ExecuteSwiHle(uint32_t swi_num, uint32_t exc_pc) {
    swi_num &= 3u;
    const uint32_t sip_bit = 1u << (kExcShiftSip + swi_num);
    control.exc = (control.exc & ~(kExcMaskCode | sip_bit)) | kExcCodeSwi;

    if (swi_hle_handler_ && swi_hle_handler_(*this, swi_num)) {
        return;
    }

    if (swi_num != 0u) {
        LOG("SWI %u HLE signal ($1=0x%08x $2=0x%08x $3=0x%08x $4=0x%08x) at pc=0x%08x",
            swi_num, r[1], r[2], r[3], r[4], exc_pc);
        r[0] = 0u;
        return;
    }

    const uint32_t svc = r[4];
    LOG("SWI 0 HLE: svc=%u ($1=0x%08x $2=0x%08x $3=0x%08x) at pc=0x%08x",
        svc, r[1], r[2], r[3], exc_pc);

    switch (svc) {
    case 1: // Applet exit / cleanup (status in $1)
        r[0] = 0u;
        halted = true;
        control.psw |= kPswBitHalt;
        if (stop_on_halt) {
            pending_stop = StopInfo{StopReason::Halt, exc_pc, r[1], false};
        }
        break;
    case 2:
    case 3: { // Kernel wait/event signal flags
        const uint32_t sig_bit = 1u << (svc - 2u);
        const bool active = (hle_signal_flags & sig_bit) != 0u;
        hle_signal_flags &= ~sig_bit;
        r[0] = active ? 1u : 0u;
        break;
    }
    case 4: { // IRQ handler registration: $1 = irq (0..11), $2 = handler, $3 = opt_out_prev_ptr
        if (r[1] >= 12u) {
            r[0] = 0x800F0316u;
            break;
        }
        const uint32_t prev = hle_irq_handlers[r[1]];
        hle_irq_handlers[r[1]] = r[2];
        const uint32_t irq_mask = 1u << r[1];
        if (r[2] != 0u) {
            intc.ier |= irq_mask;
        } else {
            intc.ier &= ~irq_mask;
        }
        if (r[3] != 0u) {
            mem.TryWrite(r[3], sizeof(prev), &prev, false);
        }
        r[0] = 1u;
        break;
    }
    case 5: { // Kernel debug print: $1 = string ptr
        std::string msg;
        msg.reserve(64);
        for (uint32_t i = 0; i < 256u; ++i) {
            char ch = 0;
            if (!mem.TryRead(r[1] + i, 1u, &ch, false) || ch == '\0') {
                break;
            }
            msg.push_back(ch);
        }
        LOG("SWI 0 HLE print: %s", msg.c_str());
        r[0] = 1u;
        break;
    }
    case 6: // Keyslot/service call
    case 8: // Fuse / hardware query
        r[0] = 0u;
        break;
    case 7: // Kernel panic ($1 = code)
        LOG_ERR("SWI 0 HLE panic(code=0x%08x) at pc=0x%08x", r[1], exc_pc);
        pending_stop = StopInfo{StopReason::Swi, exc_pc, 7u, false};
        break;
    default:
        r[0] = 0u;
        break;
    }
}

bool Cpu::ServiceSwi(uint32_t swi_num, uint32_t exc_pc, bool from_swi_insn) {
    swi_num &= 3u;
    const uint32_t sip_bit = 1u << (kExcShiftSip + swi_num);
    const uint32_t sie_bit = 1u << (kPswShiftSie + swi_num);

    if (swi_breaks_to_debugger || swi_mode == SwiMode::Trap) {
        control.exc &= ~sip_bit;
        pending_stop = StopInfo{StopReason::Swi, cur_pc, swi_num, false};
        return false;
    }

    if ((control.psw & kPswBitNmi) != 0u || (control.dbg & kDbgBitDm) != 0u) {
        return false;
    }

    if (swi_mode == SwiMode::Hle) {
        ExecuteSwiHle(swi_num, from_swi_insn ? cur_pc : exc_pc);
        return true;
    }

    if ((control.psw & kPswBitIec) == 0u || (control.psw & sie_bit) == 0u) {
        if (from_swi_insn) {
            LOG("SWI %u masked/deferred at pc=0x%08x (PSW=0x%08x: IEC=%u SIE%u=%u EXC=0x%08x)",
                swi_num, cur_pc, control.psw,
                (control.psw & kPswBitIec) ? 1u : 0u,
                swi_num, (control.psw & sie_bit) ? 1u : 0u,
                control.exc);
        }
        return false;
    }

    uint32_t vector = 0u;
    if (ResolveSwiVector(&vector)) {
        // Leave EXC.SIP[swi_num] set per MeP hardware so the +0x14 handler can inspect & clear it.
        control.exc = (control.exc & ~kExcMaskCode) | kExcCodeSwi;
        control.epc = exc_pc & ~1u;
        control.psw = (control.psw & ~(0xFu | kPswBitOm)) |
                      ((control.psw & kPswBitIec) << 1) |
                      ((control.psw & kPswBitUmc) << 1);
        CancelRepeat();
        control.pc = vector;
        branched = true;
        LOG("SWI %u dispatched -> vector 0x%08x (epc=0x%08x)", swi_num, vector, control.epc);
        return true;
    }

    if (swi_mode == SwiMode::Auto && swi_hle_fallback) {
        ExecuteSwiHle(swi_num, from_swi_insn ? cur_pc : exc_pc);
        return true;
    }

    if (from_swi_insn) {
        control.exc &= ~sip_bit;
        pending_stop = StopInfo{StopReason::Swi, cur_pc, swi_num, false};
    }
    return false;
}

bool Cpu::ServicePendingInterrupt() {
    if (pending_dint && (control.dbg & kDbgBitDm) == 0u) {
        pending_dint = false;
        EnterDebugException(kDbgBitDint, control.pc & ~1u);
        return true;
    }

    if (ServiceNmi()) {
        return true;
    }

    uint32_t best_irq = 0;
    uint32_t best_prio = 0;
    if (FindHighestActiveIrq(&best_irq, &best_prio)) {
        // An active unmasked IRQ wakes HALT/SLEEP even if IEC=0 or HIE=0.
        sleeping = false;
        halted = false;
        control.psw &= ~kPswBitHalt;

        if ((control.psw & kPswBitIec) != 0u &&
            (control.psw & kPswBitHie) != 0u &&
            (control.psw & kPswBitNmi) == 0u &&
            (control.dbg & kDbgBitDm) == 0u &&
            (dsu.dcr & kDsuDcrBitEint) != 0u) {
            const uint32_t base = intc.ivb & ~0xFFu;
            const uint32_t vector = (control.cfg & kCfgBitIvm) != 0u
                                        ? (base + 0x30u + best_irq * 4u)
                                        : (base + 0x30u);
            uint32_t vector_word = 0;
            if (mem.TryRead(vector, sizeof(vector_word), &vector_word) && vector_word != 0u) {
                intc.ivr = (intc.ivr & 0x0F00u) |
                           ((best_prio & 0xFu) << 12) |
                           ((best_irq & 0x1Fu) << 3);
                // Clear latched ISR if not actively held by a level-triggered timer.
                if (!IsTimerLevelActive(best_irq) || (intc.iet & (1u << best_irq)) != 0u) {
                    intc.isr &= ~(1u << best_irq);
                }

                control.epc = control.pc & ~1u;
                control.psw = (control.psw & ~(0xFu | kPswBitOm)) |
                              ((control.psw & kPswBitIec) << 1) |
                              ((control.psw & kPswBitUmc) << 1);
                control.exc = (control.exc & ~kExcMaskCode) | kExcCodeInt;

                CancelRepeat();
                control.pc = vector;
                branched = true;
                LOG("IRQ %u (prio=%u) dispatched -> vector 0x%08x (epc=0x%08x)",
                    best_irq, best_prio, vector, control.epc);
                return true;
            }
        }
    }

    const uint32_t ready_sip = ((control.exc & kExcMaskSip) & (control.psw & kPswMaskSie)) >> kExcShiftSip;
    if (ready_sip != 0u &&
        (control.psw & kPswBitIec) != 0u &&
        (control.psw & kPswBitNmi) == 0u &&
        (control.dbg & kDbgBitDm) == 0u) {
        for (uint32_t i = 0; i < 4u; ++i) {
            if ((ready_sip & (1u << i)) != 0u) {
                if (ServiceSwi(i, control.pc & ~1u, false)) {
                    return true;
                }
            }
        }
    }

    return false;
}

void Cpu::TriggerSwi(uint32_t code, uint32_t next_pc) {
    const uint32_t swi_num = code & 3u;
    control.exc |= (1u << (kExcShiftSip + swi_num));
    ServiceSwi(swi_num, next_pc, true);
}

void Cpu::TriggerBreak(uint32_t break_pc) {
    control.exc = (control.exc & ~kExcMaskCode) | kExcCodeBrk;
    if (stop_on_break) {
        pending_stop = StopInfo{StopReason::BreakInsn, break_pc & ~1u, 0, false};
        return;
    }

    uint32_t vector = (intc.ivb & ~0xFFu) + 0x10u;
    uint32_t vector_word = 0;
    if (!mem.TryRead(vector, sizeof(vector_word), &vector_word) || vector_word == 0u) {
        vector = 0x00000010u;
        if (!mem.TryRead(vector, sizeof(vector_word), &vector_word) || vector_word == 0u) {
            pending_stop = StopInfo{StopReason::BreakInsn, break_pc & ~1u, 0, false};
            return;
        }
    }
    control.epc = break_pc & ~1u;
    control.psw = (control.psw & ~(0xFu | kPswBitOm)) |
                  ((control.psw & kPswBitIec) << 1) |
                  ((control.psw & kPswBitUmc) << 1);
    CancelRepeat();
    control.pc = vector;
    branched = true;
}

void Cpu::TriggerDbreak(uint32_t dbreak_pc) {
    EnterDebugException(kDbgBitDbp, dbreak_pc & ~1u);
}

void Cpu::EnterSleep() {
    sleeping = true;
    control.psw |= kPswBitHalt;
    if (stop_on_halt) {
        pending_stop = StopInfo{StopReason::Halt, cur_pc, 0, false};
    }
}

void Cpu::EnterHalt() {
    halted = true;
    control.psw |= kPswBitHalt;
    if (stop_on_halt) {
        pending_stop = StopInfo{StopReason::Halt, cur_pc, 0, false};
    }
}

void Cpu::EnterDebugException(uint32_t dbg_causes, uint32_t exc_pc) {
    dsu.dcr &= ~(kDsuDcrBitHls | kDsuDcrBitSls);
    if ((dbg_causes & kDbgBitDint) != 0u) {
        if (halted) dsu.dcr |= kDsuDcrBitHls;
        if (sleeping) dsu.dcr |= kDsuDcrBitSls;
    }

    sleeping = false;
    halted = false;
    control.psw &= ~(kPswBitHalt | kPswBitOm);

    control.depc = exc_pc & ~1u;
    control.dbg |= kDbgBitDm | (dbg_causes & 0x3Fu);
    CancelRepeat();

    const uint32_t dbg_vec = dsu.x_probe_en ? 0x00700018u : 0x00000018u;
    uint32_t vector_word = 0;
    if (!dsu_break_to_debugger &&
        mem.TryRead(dbg_vec, sizeof(vector_word), &vector_word) &&
        vector_word != 0u) {
        control.pc = dbg_vec;
        branched = true;
        LOG("Debug exception (causes=0x%02x) -> vector 0x%08x (depc=0x%08x)",
            dbg_causes & 0x3Fu, dbg_vec, control.depc);
        return;
    }

    pending_stop = StopInfo{StopReason::DbreakInsn, exc_pc & ~1u, dbg_causes & 0x3Fu, false};
}

void Cpu::CheckDsuDataBreak(uint32_t addr, uint32_t sz, uint32_t val, bool is_write) {
    if ((control.dbg & kDbgBitDm) != 0u || (dsu.dbc0 & 3u) == 0u || mem.unmapped_fault) {
        return;
    }
    if (is_write && (dsu.dbc0 & (1u << 13)) != 0u) { // NOSB
        return;
    }
    if (!is_write && (dsu.dbc0 & (1u << 12)) != 0u) { // NOLB
        return;
    }

    const uint32_t word_mask = ~(dsu.dbm0 & ~3u);
    if (((addr & ~3u) & word_mask) != ((dsu.dba0 & ~3u) & word_mask)) {
        return;
    }

    bool any_active_lane = false;
    for (uint32_t i = 0; i < sz; ++i) {
        const uint32_t lane = (addr + i) & 3u;
        const bool bai = ((dsu.dbc0 >> (14u + lane)) & 1u) != 0u;
        if (bai) {
            continue;
        }
        any_active_lane = true;
        const bool blm = ((dsu.dbc0 >> (4u + lane)) & 1u) != 0u;
        if (!blm) {
            const uint8_t actual_byte = static_cast<uint8_t>((val >> (i * 8u)) & 0xFFu);
            const uint8_t target_byte = static_cast<uint8_t>((dsu.db0 >> (lane * 8u)) & 0xFFu);
            if (actual_byte != target_byte) {
                return;
            }
        }
    }
    if (!any_active_lane) {
        return;
    }

    dsu.dbs |= 1u;
    if ((dsu.dbc0 & 1u) != 0u) {
        pending_dsu_causes |= is_write ? kDbgBitDdbs : kDbgBitDdbl;
    }
}

void Cpu::ReturnFromException() {
    CancelRepeat();
    if ((control.psw & kPswBitNmi) != 0u) {
        control.psw &= ~kPswBitNmi;
        control.pc = control.npc & ~1u;
        branched = true;
        return;
    }
    control.psw = (control.psw & ~5u) | ((control.psw >> 1) & 5u);
    control.pc = control.epc & ~1u;
    branched = true;
}

void Cpu::ReturnFromDebug() {
    control.dbg &= ~kDbgBitDm;
    CancelRepeat();
    control.pc = control.depc & ~1u;
    branched = true;
}

void Cpu::BeginRepeat(uint32_t rpb_addr, uint32_t rpe_addr, uint32_t count) {
    control.rpb = rpb_addr & ~1u;
    control.rpe = rpe_addr & ~1u;
    control.rpc = count;
    repeat_active = true;
    erepeat_active = false;
    repeat_will_loop = false;
    rpb_in = -1;
}

void Cpu::BeginErepeat(uint32_t rpb_addr, uint32_t rpe_addr) {
    control.rpb = rpb_addr & ~1u;
    control.rpe = (rpe_addr & ~1u) | kRpeBitElr;
    repeat_active = false;
    erepeat_active = true;
    repeat_will_loop = false;
    rpb_in = -1;
}

void Cpu::CancelRepeat() {
    rpb_in = -1;
    repeat_active = false;
    erepeat_active = false;
    repeat_will_loop = false;
}

bool Cpu::InActiveRepeatRange(uint32_t addr) const {
    if (!IsRepeatActive()) {
        return false;
    }
    const uint32_t begin = control.rpb & ~1u;
    const uint32_t end = (control.rpe & ~1u) + 4u;
    return addr >= begin && addr <= end;
}

uint32_t Cpu::ModuloInc(uint32_t addr, uint32_t inc, uint32_t mb, uint32_t me) const {
    const uint32_t mb16 = mb & 0xFFFFu;
    const uint32_t me16 = me & 0xFFFFu;
    if (me16 > mb16) {
        const uint32_t lo16 = addr & 0xFFFFu;
        const uint32_t next16 = lo16 + inc;
        if (lo16 >= mb16 && lo16 <= me16 && next16 > me16) {
            const uint32_t span = (me16 - mb16) + 1u;
            const uint32_t wrapped = mb16 + ((next16 - mb16) % span);
            return (addr & ~0xFFFFu) | (wrapped & 0xFFFFu);
        }
        return (addr & ~0xFFFFu) | (next16 & 0xFFFFu);
    }
    uint32_t next = addr + inc;
    if (me > mb && next > me) {
        next = mb + (next - me - inc);
    }
    return next;
}

void Cpu::AddBreakpoint(uint32_t addr) {
    breakpoints_.insert(addr & ~1u);
}

void Cpu::RemoveBreakpoint(uint32_t addr) {
    breakpoints_.erase(addr & ~1u);
}

bool Cpu::HasBreakpoint(uint32_t addr) const {
    const uint32_t masked = addr & ~1u;
    if (breakpoints_.find(masked) != breakpoints_.end()) {
        return true;
    }
    uint32_t mirrored = 0;
    if (MirrorSramAddr(masked, &mirrored)) {
        return breakpoints_.find(mirrored) != breakpoints_.end();
    }
    return false;
}

void Cpu::ClearBreakpoints() {
    breakpoints_.clear();
}

std::vector<uint32_t> Cpu::GetBreakpoints() const {
    std::vector<uint32_t> out(breakpoints_.begin(), breakpoints_.end());
    std::sort(out.begin(), out.end());
    return out;
}

void Cpu::ClearStopRequest() {
    pending_stop = StopInfo{};
}

StopInfo Cpu::Step(bool ignore_bpt_at_pc) {
    g_cpu = this;

    const uint32_t pc_masked = control.pc & ~1u;
    if (!ignore_bpt_at_pc && HasBreakpoint(pc_masked)) {
        cur_pc = pc_masked;
        return StopInfo{StopReason::Breakpoint, pc_masked, 0, false};
    }

    if (!ignore_bpt_at_pc &&
        (control.dbg & kDbgBitDm) == 0u &&
        (dsu.ibc0 & 3u) != 0u &&
        (dsu.iba0 & ~1u) != 0u) {
        const uint32_t mask = ~(dsu.ibm0 & ~1u);
        if ((pc_masked & mask) == ((dsu.iba0 & ~1u) & mask)) {
            dsu.ibs |= 1u;
            if ((dsu.ibc0 & 1u) != 0u) {
                pending_stop = StopInfo{};
                EnterDebugException(kDbgBitDib, pc_masked);
                if (pending_stop.reason != StopReason::None) {
                    const StopInfo stop = pending_stop;
                    pending_stop = StopInfo{};
                    return stop;
                }
            }
        }
    }

    pending_stop = StopInfo{};
    ServicePendingInterrupt();
    if (pending_stop.reason != StopReason::None) {
        const StopInfo stop = pending_stop;
        pending_stop = StopInfo{};
        return stop;
    }

    if (sleeping || halted) {
        TickTimers(1);
        ServicePendingInterrupt();
        if (pending_stop.reason != StopReason::None) {
            const StopInfo stop = pending_stop;
            pending_stop = StopInfo{};
            return stop;
        }
        if (sleeping || halted) {
            ++step_count;
            cur_pc = control.pc & ~1u;
            if (stop_on_halt) {
                return StopInfo{StopReason::Halt, cur_pc, halted ? 2u : 1u, false};
            }
            return StopInfo{StopReason::None, cur_pc, 0, false};
        }
    }

    cur_pc = control.pc & ~1u;
    uint32_t raw = 0;
    if (!mem.FetchInsn32(cur_pc, &raw)) {
        return StopInfo{StopReason::UnmappedMemory, cur_pc, cur_pc, false};
    }

    const insn_t *insn = decode_insn(raw);
    if (!insn) {
        LOG_ERR("Unknown instruction 0x%08x at pc=0x%08x", raw, cur_pc);
        return StopInfo{StopReason::InvalidInsn, cur_pc, raw, false};
    }

    pending_stop = StopInfo{};
    pending_dsu_causes = 0;
    branched = false;
    mem.ClearFaults();
    const bool sst_armed = ((control.dbg & kDbgBitDm) == 0u) && ((control.dbg & kDbgBitSst) != 0u);

    if (IsRepeatActive() && cur_pc == (control.rpe & ~1u)) {
        rpb_in = 2;
        if (erepeat_active) {
            repeat_will_loop = true;
        } else if (control.rpc > 0u) {
            --control.rpc;
            repeat_will_loop = true;
        } else {
            repeat_will_loop = false;
        }
    }

    control.pc = cur_pc + insn->sz;
    insn->execute(this, raw);
    ++step_count;
    TickTimers(1);

    if (pending_stop.reason != StopReason::None) {
        const StopInfo stop = pending_stop;
        pending_stop = StopInfo{};
        return stop;
    }

    if (branched) {
        rpb_in = -1;
        repeat_will_loop = false;
    } else if (rpb_in > 0) {
        --rpb_in;
        if (rpb_in == 0) {
            if (repeat_will_loop) {
                control.pc = control.rpb & ~1u;
            } else {
                repeat_active = false;
            }
            rpb_in = -1;
            repeat_will_loop = false;
        }
    }

    if (mem.watchpoint_hit) {
        return StopInfo{StopReason::Watchpoint, cur_pc, mem.watchpoint_addr, mem.watchpoint_is_write};
    }

    if (stop_on_unmapped && mem.unmapped_fault) {
        return StopInfo{StopReason::UnmappedMemory, cur_pc, mem.fault_addr, mem.fault_is_write};
    }

    if (pending_dsu_causes != 0u) {
        const uint32_t causes = pending_dsu_causes;
        pending_dsu_causes = 0;
        EnterDebugException(causes, cur_pc);
        if (pending_stop.reason != StopReason::None) {
            const StopInfo stop = pending_stop;
            pending_stop = StopInfo{};
            return stop;
        }
        return StopInfo{StopReason::None, cur_pc, 0, false};
    }

    if (sst_armed) {
        EnterDebugException(kDbgBitDss, control.pc & ~1u);
        if (pending_stop.reason != StopReason::None) {
            const StopInfo stop = pending_stop;
            pending_stop = StopInfo{};
            return stop;
        }
    }

    return StopInfo{StopReason::None, cur_pc, 0, false};
}

std::string Cpu::FormatCsrState(const char *filter) const {
    const std::string filt = filter ? LowerAscii(TrimAscii(filter)) : "";
    const uint32_t psw = GetCR(16);
    const uint32_t exc = GetCR(20);
    const uint32_t cfg = GetCR(21);
    const uint32_t dbg = GetCR(24);
    const uint32_t rpe = GetCR(5);

    std::ostringstream oss;
    char buf[256];
    if (!filt.empty()) {
        int found_idx = -1;
        std::string name_norm = (!filt.empty() && filt[0] == '$') ? filt.substr(1) : filt;
        for (int i = 0; i < 32; ++i) {
            if (name_norm == kCsrNamesLower[i]) {
                found_idx = i;
                break;
            }
        }
        if (found_idx < 0 && std::isdigit(static_cast<unsigned char>(name_norm[0]))) {
            char *endp = nullptr;
            const unsigned long idx = std::strtoul(name_norm.c_str(), &endp, 0);
            if (endp != name_norm.c_str() && *endp == '\0' && idx < 32ul) {
                found_idx = static_cast<int>(idx);
            }
        }
        if (found_idx < 0) {
            return "Unknown CSR '" + std::string(filter) + "'.\n";
        }
        std::snprintf(buf, sizeof(buf), "CR%-2d ($%-5s) = 0x%08X\n",
                      found_idx, kCsrNamesLower[found_idx],
                      GetCR(static_cast<uint32_t>(found_idx)));
        oss << buf;
        return oss.str();
    }

    for (uint32_t i = 0; i < 32u; i += 4u) {
        std::snprintf(buf, sizeof(buf),
                      "CR%-2u $%-5s=0x%08X  CR%-2u $%-5s=0x%08X  CR%-2u $%-5s=0x%08X  CR%-2u $%-5s=0x%08X\n",
                      i, kCsrNamesLower[i], GetCR(i),
                      i + 1u, kCsrNamesLower[i + 1u], GetCR(i + 1u),
                      i + 2u, kCsrNamesLower[i + 2u], GetCR(i + 2u),
                      i + 3u, kCsrNamesLower[i + 3u], GetCR(i + 3u));
        oss << buf;
    }
    std::snprintf(buf, sizeof(buf),
                  "PSW[IEC=%u IEP=%u UMC=%u UMP=%u SIE=0x%x HIE=%u NMI=%u HALT=%u OM=%u] "
                  "EXC[CODE=%u SIP=0x%x HIP=%u] "
                  "DBG[DM=%u SST=%u JTRST=%u BSF=%u DINT=%u DIB=%u DDBS=%u DDBL=%u DBP=%u DSS=%u] "
                  "CFG[ICE=%u DCE=%u IVM=%u EVM=%u] RPE.ELR=%u",
                  (psw & kPswBitIec) ? 1u : 0u, (psw & kPswBitIep) ? 1u : 0u,
                  (psw & kPswBitUmc) ? 1u : 0u, (psw & kPswBitUmp) ? 1u : 0u,
                  (psw >> kPswShiftSie) & 0xFu, (psw & kPswBitHie) ? 1u : 0u,
                  (psw & kPswBitNmi) ? 1u : 0u, (psw & kPswBitHalt) ? 1u : 0u,
                  (psw & kPswBitOm) ? 1u : 0u,
                  exc & kExcMaskCode, (exc >> kExcShiftSip) & 0xFu, (exc & kExcBitHip) ? 1u : 0u,
                  (dbg & kDbgBitDm) ? 1u : 0u, (dbg & kDbgBitSst) ? 1u : 0u,
                  (dbg & kDbgBitJtrst) ? 1u : 0u, (dbg & kDbgBitBsf) ? 1u : 0u,
                  (dbg & kDbgBitDint) ? 1u : 0u, (dbg & kDbgBitDib) ? 1u : 0u,
                  (dbg & kDbgBitDdbs) ? 1u : 0u, (dbg & kDbgBitDdbl) ? 1u : 0u,
                  (dbg & kDbgBitDbp) ? 1u : 0u, (dbg & kDbgBitDss) ? 1u : 0u,
                  (cfg & kCfgBitIce) ? 1u : 0u, (cfg & kCfgBitDce) ? 1u : 0u,
                  (cfg & kCfgBitIvm) ? 1u : 0u, (cfg & kCfgBitEvm) ? 1u : 0u,
                  (rpe & kRpeBitElr) ? 1u : 0u);
    oss << buf;
    return oss.str();
}

std::string Cpu::FormatIntcState() const {
    const uint32_t ivr = GetEffectiveIvr();
    const uint32_t psw = GetCR(16);
    const uint32_t exc = GetCR(20);
    char buf[384];
    std::snprintf(
        buf, sizeof(buf),
        "IVB=0x%08X IVR=0x%08X (ILV=%u IML=%u ICN=%u)\n"
        "ISR=0x%08X IER=0x%08X IET=0x%08X HIP=%u\n"
        "ILR0=0x%08X ILR1=0x%08X ILR2=0x%08X ILR3=0x%08X\n"
        "PSW=0x%08X (IEC=%u HIE=%u NMI=%u SIE=0x%x)",
        intc.ivb, ivr, (ivr >> 12) & 0xFu, (ivr >> 8) & 0xFu, (ivr >> 3) & 0x1Fu,
        intc.isr, intc.ier, intc.iet, (exc & kExcBitHip) ? 1u : 0u,
        intc.ilr0, intc.ilr1, intc.ilr2, intc.ilr3,
        psw, (psw & kPswBitIec) ? 1u : 0u, (psw & kPswBitHie) ? 1u : 0u,
        (psw & kPswBitNmi) ? 1u : 0u, (psw >> kPswShiftSie) & 0xFu);
    return std::string(buf);
}

std::string Cpu::FormatTimersState() const {
    std::ostringstream oss;
    char buf[160];
    for (uint32_t ch = 0; ch < 4u; ++ch) {
        const TimerChannel &t = timers[ch];
        std::snprintf(
            buf, sizeof(buf),
            "CH%u: CNT=0x%08X CMP=0x%08X TEN=%u TCR=0x%02X(TAI=%u TMD=%u TIE=%u) TIS=%u DIV=1/%u",
            ch, t.cnt, t.cmp, t.ten & 1u, t.tcr,
            (t.tcr & kTimerTcrTai) ? 1u : 0u,
            (t.tcr & kTimerTcrTmd) ? 1u : 0u,
            (t.tcr & kTimerTcrTie) ? 1u : 0u,
            t.tis & 1u, 1u << (t.tcd & 7u));
        oss << buf;
        if (ch < 3u) {
            oss << "\n";
        }
    }
    return oss.str();
}

std::string Cpu::FormatDsuState() const {
    char buf[384];
    std::snprintf(
        buf, sizeof(buf),
        "DBG=0x%08X (DM=%u SST=%u) DEPC=0x%08X xProbeEn=%u\n"
        "DCR=0x%08X (HLS=%u SLS=%u EINT=%u ENMI=%u) TCR=0x%08X\n"
        "IBS=0x%08X IBA0=0x%08X IBC0=0x%08X IBM0=0x%08X\n"
        "DBS=0x%08X DBA0=0x%08X DBC0=0x%08X DBM0=0x%08X DB0=0x%08X DBU0=0x%08X",
        control.dbg, (control.dbg & kDbgBitDm) ? 1u : 0u, (control.dbg & kDbgBitSst) ? 1u : 0u,
        control.depc, dsu.x_probe_en ? 1u : 0u,
        dsu.dcr, (dsu.dcr & kDsuDcrBitHls) ? 1u : 0u, (dsu.dcr & kDsuDcrBitSls) ? 1u : 0u,
        (dsu.dcr & kDsuDcrBitEint) ? 1u : 0u, (dsu.dcr & kDsuDcrBitEnmi) ? 1u : 0u,
        dsu.tcr,
        GetDsuReg(0x0801u), dsu.iba0, dsu.ibc0, dsu.ibm0,
        GetDsuReg(0x0802u), dsu.dba0, dsu.dbc0, dsu.dbm0, dsu.db0, dsu.dbu0);
    return std::string(buf);
}

bool Cpu::TryHandleCoreCommand(const std::string &cmd, std::string *out) {
    if (!out) {
        return false;
    }
    const std::string trimmed = TrimAscii(cmd);
    if (trimmed == "intc") {
        *out = FormatIntcState();
        return true;
    }
    if (trimmed == "csr" || trimmed.rfind("csr ", 0) == 0) {
        const char *filter = trimmed.size() > 4 ? trimmed.c_str() + 4 : nullptr;
        *out = FormatCsrState(filter);
        return true;
    }
    if (trimmed == "timer" || trimmed == "timers") {
        *out = FormatTimersState();
        return true;
    }
    if (trimmed == "dsu") {
        *out = FormatDsuState();
        return true;
    }
    if (trimmed.rfind("irq ", 0) == 0) {
        char *endp = nullptr;
        const unsigned long irq = std::strtoul(trimmed.c_str() + 4, &endp, 0);
        if (endp == trimmed.c_str() + 4 || irq >= 32ul) {
            *out = "Error: irq must be 0..31";
            return true;
        }
        RaiseIrq(static_cast<uint32_t>(irq));
        char buf[96];
        std::snprintf(buf, sizeof(buf), "Raised IRQ %lu (ISR=0x%08X IER=0x%08X IVR=0x%08X)",
                      irq, intc.isr, intc.ier, GetEffectiveIvr());
        *out = buf;
        return true;
    }
    if (trimmed == "nmi") {
        RaiseNmi();
        char buf[64];
        std::snprintf(buf, sizeof(buf), "Raised NMI (pending_nmi=1 PSW=0x%08X)", GetCR(16));
        *out = buf;
        return true;
    }
    if (trimmed == "dint") {
        RaiseDebugInterrupt();
        *out = "Raised DINT (pending debug interrupt)";
        return true;
    }
    if (trimmed == "swi" || trimmed.rfind("swi ", 0) == 0) {
        if (trimmed == "swi") {
            uint32_t swi_vec = 0u;
            const bool has_vec = ResolveSwiVector(&swi_vec);
            char buf[220];
            std::snprintf(buf, sizeof(buf),
                          "SWI mode=%s hle_fallback=%u trap=%u vec=%s (0x%08X)\n"
                          "PSW.IEC=%u SIE=0x%x EXC.SIP=0x%x signals=0x%08X",
                          SwiModeName(swi_mode), swi_hle_fallback ? 1u : 0u,
                          swi_breaks_to_debugger ? 1u : 0u,
                          has_vec ? "installed" : "none", swi_vec,
                          (control.psw & kPswBitIec) ? 1u : 0u,
                          (control.psw >> kPswShiftSie) & 0xFu,
                          (control.exc >> kExcShiftSip) & 0xFu,
                          hle_signal_flags);
            *out = buf;
            return true;
        }
        const std::string arg = TrimAscii(trimmed.substr(4));
        if (arg.rfind("mode ", 0) == 0) {
            const std::string m = LowerAscii(TrimAscii(arg.substr(5)));
            if (m == "auto") {
                swi_mode = SwiMode::Auto;
                swi_breaks_to_debugger = false;
            } else if (m == "arch") {
                swi_mode = SwiMode::Arch;
                swi_breaks_to_debugger = false;
            } else if (m == "hle") {
                swi_mode = SwiMode::Hle;
                swi_breaks_to_debugger = false;
            } else if (m == "trap") {
                swi_mode = SwiMode::Trap;
                swi_breaks_to_debugger = true;
            } else {
                *out = "Usage: swi mode <auto|arch|hle|trap>";
                return true;
            }
            *out = std::string("SWI mode set to ") + SwiModeName(swi_mode);
            return true;
        }
        char *endp = nullptr;
        const unsigned long swi_num = std::strtoul(arg.c_str(), &endp, 0);
        if (endp == arg.c_str() || *endp != '\0' || swi_num >= 4ul) {
            *out = "Usage: swi [0..3 | mode <auto|arch|hle|trap>]";
            return true;
        }
        RaiseSwiSignal(static_cast<uint32_t>(swi_num));
        char buf[96];
        std::snprintf(buf, sizeof(buf), "Raised SWI %lu signal (EXC=0x%08X PSW=0x%08X)",
                      swi_num, GetCR(20), GetCR(16));
        *out = buf;
        return true;
    }
    if (trimmed == "signal" || trimmed.rfind("signal ", 0) == 0) {
        if (trimmed.size() > 7) {
            char *endp = nullptr;
            const uint32_t mask = static_cast<uint32_t>(std::strtoul(trimmed.c_str() + 7, &endp, 0));
            if (endp == trimmed.c_str() + 7 || *endp != '\0') {
                *out = "Usage: signal [mask]";
                return true;
            }
            hle_signal_flags = mask;
        }
        char buf[64];
        std::snprintf(buf, sizeof(buf), "HLE signal flags = 0x%08X", hle_signal_flags);
        *out = buf;
        return true;
    }
    if (trimmed == "applet" || trimmed.rfind("applet ", 0) == 0) {
        uint32_t entry = 0u;
        uint32_t sp = 0u;
        if (trimmed.size() > 7) {
            std::istringstream iss(trimmed.substr(7));
            std::string entry_tok;
            std::string sp_tok;
            if (iss >> entry_tok) {
                char *endp = nullptr;
                entry = static_cast<uint32_t>(std::strtoul(entry_tok.c_str(), &endp, 16));
                if (endp == entry_tok.c_str() || *endp != '\0') {
                    *out = "Usage: applet [hex_entry] [hex_sp]";
                    return true;
                }
            }
            if (iss >> sp_tok) {
                char *endp = nullptr;
                sp = static_cast<uint32_t>(std::strtoul(sp_tok.c_str(), &endp, 16));
                if (endp == sp_tok.c_str() || *endp != '\0') {
                    *out = "Usage: applet [hex_entry] [hex_sp]";
                    return true;
                }
            }
        }
        PrepareAppletContext(entry, sp);
        char buf[160];
        std::snprintf(buf, sizeof(buf),
                      "Prepared applet context: PC=0x%08X SP=0x%08X PSW=0x%08X IVB=0x%08X IVR=0x%08X",
                      control.pc, r[MEP_REG_sp], control.psw, intc.ivb, intc.ivr);
        *out = buf;
        return true;
    }
    if (trimmed.rfind("cb ", 0) == 0) {
        std::istringstream iss(trimmed.substr(3));
        std::string addr_tok;
        std::string val_tok;
        if (!(iss >> addr_tok)) {
            *out = "Usage: cb <hex_addr> [hex_val]";
            return true;
        }
        char *endp = nullptr;
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(addr_tok.c_str(), &endp, 16));
        if (endp == addr_tok.c_str() || *endp != '\0') {
            *out = "Error: invalid control-bus address '" + addr_tok + "'";
            return true;
        }
        if (iss >> val_tok) {
            const uint32_t val = static_cast<uint32_t>(std::strtoul(val_tok.c_str(), &endp, 0));
            if (endp == val_tok.c_str() || *endp != '\0') {
                *out = "Error: invalid value '" + val_tok + "'";
                return true;
            }
            WriteControlBusRaw(addr, val);
            char buf[64];
            std::snprintf(buf, sizeof(buf), "cb[0x%04X] <= 0x%08X (now 0x%08X)",
                          addr, val, ReadControlBusRaw(addr));
            *out = buf;
            return true;
        }
        char buf[64];
        std::snprintf(buf, sizeof(buf), "cb[0x%04X] = 0x%08X", addr, ReadControlBusRaw(addr));
        *out = buf;
        return true;
    }
    return false;
}
