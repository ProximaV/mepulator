#include "cpu.h"

#include <algorithm>
#include <cstring>

#include "insn.h"
#include "log.h"
#include "util.h"

Cpu *g_cpu = nullptr;

Cpu::Cpu() {
    Reset(0);
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
    cb_regs.clear();

    cur_pc = control.pc;
    rpb_in = -1;
    erepeat_active = false;
    branched = false;
    sleeping = false;
    step_count = 0;
    pending_stop = StopInfo{};

    mem.ClearFaults();
    g_cpu = this;
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
    return const_cast<Cpu *>(this)->CRRef(idx);
}

void Cpu::SetCR(uint32_t idx, uint32_t val) {
    const uint32_t cr_idx = idx & 31u;
    if (cr_idx == 21u) {
        ApplyCfgWrite(val);
        return;
    }
    CRRef(cr_idx) = val;
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

uint32_t Cpu::ReadControlBus(uint32_t addr) const {
    if (addr < 8) {
        return GetIntc(addr);
    }
    if (addr >= 0x2000 && addr <= 0x207C && (addr & 3u) == 0) {
        return GetCR((addr - 0x2000u) >> 2);
    }
    auto it = cb_regs.find(addr);
    if (it != cb_regs.end()) {
        return it->second;
    }
    LOG("ReadControlBus: unmapped reg 0x%04x (pc=0x%08x)", addr, cur_pc);
    return 0;
}

void Cpu::WriteControlBus(uint32_t addr, uint32_t val) {
    if (addr < 8) {
        SetIntc(addr, val);
        return;
    }
    if (addr >= 0x2000 && addr <= 0x207C && (addr & 3u) == 0) {
        SetCR((addr - 0x2000u) >> 2, val);
        return;
    }
    cb_regs[addr] = val;
    LOG("WriteControlBus: reg 0x%04x <= 0x%08x (pc=0x%08x)", addr, val, cur_pc);
}

void Cpu::RaiseIrq(uint32_t irq) {
    if (irq < 32) {
        intc.isr |= (1u << irq);
        if ((intc.ier & (1u << irq)) != 0) {
            sleeping = false;
        }
    }
}

void Cpu::ClearIrq(uint32_t irq) {
    if (irq < 32) {
        intc.isr &= ~(1u << irq);
    }
}

void Cpu::Interrupt(uint32_t irq) {
    RaiseIrq(irq);
    ServicePendingInterrupt();
}

bool Cpu::ServicePendingInterrupt() {
    uint32_t pending = intc.isr & intc.ier;
    if (pending == 0 || (control.psw & 1u) == 0) {
        return false;
    }

    uint32_t best_irq = 0;
    int best_prio = -1;
    for (uint32_t i = 0; i < 32; ++i) {
        if ((pending & (1u << i)) == 0) {
            continue;
        }
        uint32_t ilr = GetIntc(4 + (i >> 3));
        int prio = static_cast<int>((ilr >> ((i & 7u) * 4u)) & 0xFu);
        if (prio > best_prio) {
            best_prio = prio;
            best_irq = i;
        }
    }

    const uint32_t vector = (intc.ivb & ~0xFFu) + 0x80u + best_irq * 4u;
    uint32_t vector_word = 0;
    if (!mem.TryRead(vector, sizeof(vector_word), &vector_word) || vector_word == 0) {
        // No handler installed at this vector slot in RAM.
        return false;
    }

    // Acknowledge pending bit cleanly after reading a valid handler.
    intc.isr &= ~(1u << best_irq);
    sleeping = false;

    // Save EPC BEFORE overwriting PC!
    control.epc = control.pc & ~1u;
    control.psw = (control.psw & ~0xFu) | ((control.psw & 1u) << 1) | ((control.psw & 4u) << 1);
    control.exc = (control.exc & ~0xFFu) | (0x20u + (best_irq & 0x1Fu));

    CancelRepeat();
    control.pc = vector;
    branched = true;
    LOG("IRQ %u dispatched -> vector 0x%08x (epc=0x%08x)", best_irq, vector, control.epc);
    return true;
}

void Cpu::TriggerSwi(uint32_t code, uint32_t next_pc) {
    const uint32_t swi_num = code & 3u;
    const uint32_t vector = (intc.ivb & ~0xFFu) + 0x40u + swi_num * 4u;
    uint32_t vector_word = 0;

    if (!swi_breaks_to_debugger &&
        mem.TryRead(vector, sizeof(vector_word), &vector_word) &&
        vector_word != 0) {
        control.epc = next_pc & ~1u;
        control.psw = (control.psw & ~0xFu) | ((control.psw & 1u) << 1) | ((control.psw & 4u) << 1);
        control.exc = (control.exc & ~0xFFu) | (0x10u + swi_num);
        CancelRepeat();
        control.pc = vector;
        branched = true;
        return;
    }

    pending_stop = StopInfo{StopReason::Swi, cur_pc, swi_num, false};
}

void Cpu::ReturnFromException() {
    control.psw = (control.psw & ~5u) | ((control.psw >> 1) & 5u);
    CancelRepeat();
    control.pc = control.epc & ~1u;
    branched = true;
}

void Cpu::ReturnFromDebug() {
    control.dbg &= ~1u;
    CancelRepeat();
    control.pc = control.depc & ~1u;
    branched = true;
}

void Cpu::BeginRepeat(uint32_t rpb_addr, uint32_t rpe_addr, uint32_t count) {
    control.rpb = rpb_addr & ~1u;
    control.rpe = rpe_addr & ~1u;
    control.rpc = count;
    erepeat_active = false;
    rpb_in = -1;
}

void Cpu::BeginErepeat(uint32_t rpb_addr, uint32_t rpe_addr) {
    control.rpb = rpb_addr & ~1u;
    control.rpe = rpe_addr & ~1u;
    erepeat_active = true;
    rpb_in = -1;
}

void Cpu::CancelRepeat() {
    rpb_in = -1;
    erepeat_active = false;
}

bool Cpu::InActiveRepeatRange(uint32_t addr) const {
    if (control.rpc == 0 && !erepeat_active) {
        return false;
    }
    const uint32_t begin = control.rpb & ~1u;
    const uint32_t end = (control.rpe & ~1u) + 4u;
    return addr >= begin && addr <= end;
}

uint32_t Cpu::ModuloInc(uint32_t addr, uint32_t inc, uint32_t mb, uint32_t me) const {
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

    ServicePendingInterrupt();
    if (sleeping) {
        cur_pc = control.pc & ~1u;
        if (stop_on_halt) {
            return StopInfo{StopReason::Halt, cur_pc, 1, false};
        }
        return StopInfo{StopReason::None, cur_pc, 0, false};
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
    branched = false;
    mem.ClearFaults();

    if ((control.rpc > 0 || erepeat_active) && cur_pc == (control.rpe & ~1u)) {
        rpb_in = 2;
    }

    control.pc = cur_pc + insn->sz;
    insn->execute(this, raw);
    ++step_count;

    if (pending_stop.reason != StopReason::None) {
        return pending_stop;
    }

    if (branched) {
        rpb_in = -1;
    } else if (rpb_in > 0) {
        --rpb_in;
        if (rpb_in == 0) {
            if (erepeat_active) {
                control.pc = control.rpb & ~1u;
            } else if (control.rpc > 1) {
                --control.rpc;
                control.pc = control.rpb & ~1u;
            } else {
                control.rpc = 0;
            }
            rpb_in = -1;
        }
    }

    if (mem.watchpoint_hit) {
        return StopInfo{StopReason::Watchpoint, cur_pc, mem.watchpoint_addr, mem.watchpoint_is_write};
    }

    if (stop_on_unmapped && mem.unmapped_fault) {
        return StopInfo{StopReason::UnmappedMemory, cur_pc, mem.fault_addr, mem.fault_is_write};
    }

    return StopInfo{StopReason::None, cur_pc, 0, false};
}
