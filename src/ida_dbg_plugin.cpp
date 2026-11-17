#include <ida.hpp>
#include <idp.hpp>
#include <idd.hpp>
#include <dbg.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <segment.hpp>
#include <entry.hpp>
#include <name.hpp>
#include <ua.hpp>
#include <expr.hpp>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <string>
#include <thread>
#include <unordered_set>
#include <vector>

#include "f00d_machine.h"
#include "log.h"

namespace {

constexpr pid_t kPid = 1;
constexpr thid_t kTid = 1;

constexpr register_class_t RC_GENERAL = 0x01;
constexpr register_class_t RC_CONTROL = 0x02;
constexpr size_t kRegIdxPc = 16;
constexpr size_t kRegIdxCfg = 16 + 21;
constexpr size_t kRegIdxIvb = 48;
constexpr register_class_t RC_INTC    = 0x04;
constexpr register_class_t RC_TIMER   = 0x08;
constexpr register_class_t RC_DSU     = 0x10;

const char *const kRegClasses[] = {
    "General registers",
    "Control registers",
    "INTC registers",
    "Timer/Counter",
    "DSU registers",
    nullptr
};

const register_info_t kRegisters[] = {
    // 0..15: GPRs
    { "$0",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$1",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$2",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$3",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$4",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$5",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$6",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$7",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$8",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$9",   REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$10",  REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$11",  REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$12",  REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$tp",  REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$gp",  REGISTER_ADDRESS,                           RC_GENERAL, dt_dword, nullptr, 0 },
    { "$sp",  REGISTER_ADDRESS | REGISTER_SP,             RC_GENERAL, dt_dword, nullptr, 0 },

    // 16: $pc
    { "$pc",  REGISTER_ADDRESS | REGISTER_IP,             RC_GENERAL, dt_dword, nullptr, 0 },

    // 17..47: CSRs (CR[1..31])
    { "$lp",   REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$sar",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$r3",   0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$rpb",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$rpe",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$rpc",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$hi",   0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$lo",   0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$r9",   0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$r10",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$r11",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$mb0",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$me0",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$mb1",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$me1",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$psw",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$id",   REGISTER_READONLY,                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$tmp",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$epc",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$exc",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$cfg",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$vid",  REGISTER_READONLY,                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$npc",  REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$dbg",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$depc", REGISTER_ADDRESS,                          RC_CONTROL, dt_dword, nullptr, 0 },
    { "$opt",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$rcfg", 0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$ccfg", 0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$r29",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$r30",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },
    { "$r31",  0,                                         RC_CONTROL, dt_dword, nullptr, 0 },

    // 48..55: INTC registers
    { "$ivb",  REGISTER_ADDRESS,                          RC_INTC,    dt_dword, nullptr, 0 },
    { "$isr",  0,                                         RC_INTC,    dt_dword, nullptr, 0 },
    { "$ier",  0,                                         RC_INTC,    dt_dword, nullptr, 0 },
    { "$iet",  0,                                         RC_INTC,    dt_dword, nullptr, 0 },
    { "$ilr0", 0,                                         RC_INTC,    dt_dword, nullptr, 0 },
    { "$ilr1", 0,                                         RC_INTC,    dt_dword, nullptr, 0 },
    { "$ilr2", 0,                                         RC_INTC,    dt_dword, nullptr, 0 },
    { "$ilr3", 0,                                         RC_INTC,    dt_dword, nullptr, 0 },

    // 56: Control-bus INTC IVR
    { "$ivr",  0,                                         RC_INTC,    dt_dword, nullptr, 0 },

    // 57..80: Control-bus Timer/Counter channels 0..3 (0x0400..0x0435)
    { "$cnt0", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$cmp0", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$ten0", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcr0", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tis0", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcd0", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$cnt1", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$cmp1", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$ten1", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcr1", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tis1", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcd1", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$cnt2", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$cmp2", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$ten2", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcr2", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tis2", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcd2", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$cnt3", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$cmp3", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$ten3", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcr3", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tis3", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },
    { "$tcd3", 0,                                         RC_TIMER,   dt_dword, nullptr, 0 },

    // 81..92: Control-bus Debug Support Unit (DSU, 0x0800..0x0A05)
    { "$dcr",  0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$ibs",  0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$dbs",  0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$tcr",  0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$iba0", REGISTER_ADDRESS,                          RC_DSU,     dt_dword, nullptr, 0 },
    { "$ibc0", 0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$ibm0", 0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$dba0", REGISTER_ADDRESS,                          RC_DSU,     dt_dword, nullptr, 0 },
    { "$dbc0", 0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$dbm0", 0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$db0",  0,                                         RC_DSU,     dt_dword, nullptr, 0 },
    { "$dbu0", 0,                                         RC_DSU,     dt_dword, nullptr, 0 },
};

constexpr uint32_t kExtraCbAddrs[] = {
    0x0000u,
    0x0400u, 0x0401u, 0x0402u, 0x0403u, 0x0404u, 0x0405u,
    0x0410u, 0x0411u, 0x0412u, 0x0413u, 0x0414u, 0x0415u,
    0x0420u, 0x0421u, 0x0422u, 0x0423u, 0x0424u, 0x0425u,
    0x0430u, 0x0431u, 0x0432u, 0x0433u, 0x0434u, 0x0435u,
    0x0800u, 0x0801u, 0x0802u, 0x0803u,
    0x0900u, 0x0901u, 0x0902u,
    0x0A00u, 0x0A01u, 0x0A02u, 0x0A04u, 0x0A05u,
};
static_assert(qnumber(kRegisters) == 56 + qnumber(kExtraCbAddrs), "kRegisters / kExtraCbAddrs size mismatch");

const uchar kBreakInsnBytes[2] = { 0x32, 0x70 };

void IdaLogCallback(const char *text) {
    if (text && *text) {
        msg("[mepdbg] %s", text);
        const size_t n = std::strlen(text);
        if (text[n - 1] != '\n') {
            msg("\n");
        }
    }
}

uint8_t ToIdaSegPerm(uint8_t mem_perm) {
    uint8_t perm = 0;
    if (mem_perm & MEM_PERM_READ)  perm |= SEGPERM_READ;
    if (mem_perm & MEM_PERM_WRITE) perm |= SEGPERM_WRITE;
    if (mem_perm & MEM_PERM_EXEC)  perm |= SEGPERM_EXEC;
    return perm;
}

int WatchTypeFromBpt(bpttype_t type) {
    switch (type) {
    case BPT_WRITE: return 1;
    case BPT_READ:  return 2;
    case BPT_RDWR:  return 3;
    default:        return 0;
    }
}

struct mepdbg_plugmod_t;
static mepdbg_plugmod_t *g_active_plugmod = nullptr;

struct idd_listener_t : public event_listener_t {
    mepdbg_plugmod_t *pm = nullptr;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct idp_fallback_listener_t : public event_listener_t {
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct ui_listener_t : public event_listener_t {
    mepdbg_plugmod_t *pm = nullptr;
    bool debugger_selected = false;
    ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

struct mepdbg_plugmod_t : public plugmod_t {
    F00DMachine machine;
    std::deque<debug_event_t> event_queue;
    std::atomic<bool> pause_requested{false};
    bool is_running = false;
    bool attached = false;
    bool ignore_bpt_once = false;
    resume_mode_t resmod = RESMOD_NONE;
    uint32_t entry_pc = 0x00800000u;
    std::unordered_set<uint32_t> ida_exec_bpts;

    idd_listener_t idd_listener;
    idp_fallback_listener_t idp_listener;
    ui_listener_t ui_listener;
    bool hooks_installed = false;
    bool idc_registered = false;

    mepdbg_plugmod_t();
    ~mepdbg_plugmod_t() override;

    bool idaapi run(size_t arg) override;

    void InstallHooks();
    void UninstallHooks();
    void RegisterIdcFunctions();
    void UnregisterIdcFunctions();
    void ResetSessionState();
    void LoadSegmentsFromIdb();
    uint32_t DetermineEntryPc() const;
    void QueueEvent(const debug_event_t &ev);
    void QueueStopEvent(const StopInfo &stop, bool from_single_step);
    ea_t ResolveBptKea(uint32_t stop_pc) const;
    uint32_t ReadRegByIdx(size_t idx) const;
    void WriteRegByIdx(size_t idx, uint32_t val);
    void WriteRegAndInvalidate(size_t idx, uint32_t val);
    ssize_t HandleIddEvent(ssize_t code, va_list va);
    bool ExecuteCommand(const char *cmdline, std::string &out);
    ssize_t HandleRexec(const char *cmdline);
};

int FindRegIdxByName(const char *name) {
    if (!name || !*name) {
        return -1;
    }
    for (size_t i = 0; i < qnumber(kRegisters); ++i) {
        if (strieq(kRegisters[i].name, name)) {
            return static_cast<int>(i);
        }
    }
    struct reg_alias_entry_t {
        const char *alias;
        size_t idx;
    };
    static const reg_alias_entry_t kAliases[] = {
        { "h-pc",      16 },
        { "r0",         0 }, { "$r0",  0 },
        { "r1",         1 }, { "$r1",  1 },
        { "r2",         2 }, { "$r2",  2 },
        { "r3",         3 },
        { "r4",         4 }, { "$r4",  4 },
        { "r5",         5 }, { "$r5",  5 },
        { "r6",         6 }, { "$r6",  6 },
        { "r7",         7 }, { "$r7",  7 },
        { "r8",         8 }, { "$r8",  8 }, { "fp", 8 }, { "$fp", 8 },
        { "r9",         9 },
        { "r10",       10 },
        { "r11",       11 },
        { "r12",       12 }, { "$r12", 12 },
        { "r13",       13 }, { "$r13", 13 },
        { "r14",       14 }, { "$r14", 14 },
        { "r15",       15 }, { "$r15", 15 },
        { "$h-csr-3",  19 },
        { "$h-csr-9",  25 },
        { "$h-csr-10", 26 },
        { "$h-csr-11", 27 },
        { "$h-csr-29", 45 },
        { "$h-csr-30", 46 },
        { "$h-csr-31", 47 },
    };
    for (const auto &entry : kAliases) {
        if (strieq(entry.alias, name)) {
            return static_cast<int>(entry.idx);
        }
    }
    for (size_t i = 0; i < qnumber(kRegisters); ++i) {
        const char *rn = kRegisters[i].name;
        if (rn[0] == '$' && strieq(rn + 1, name)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

debugger_t g_debugger = {
    IDD_INTERFACE_VERSION,
    "mepulator",
    DEBUGGER_ID_6811_EMULATOR,
    "MeP",
    DBG_FLAG_CAN_CONT_BPT
    | DBG_FLAG_SAFE
    | DBG_FLAG_FAKE_ATTACH
    | DBG_FLAG_NOHOST
    | DBG_FLAG_NOPARAMETERS
    | DBG_FLAG_NOPASSWORD
    | DBG_FLAG_NOSTARTDIR
    | DBG_FLAG_ANYSIZE_HWBPT
    | DBG_FLAG_FAST_STEP
    | DBG_HAS_GET_PROCESSES
    | DBG_HAS_ATTACH_PROCESS
    | DBG_HAS_DETACH_PROCESS
    | DBG_HAS_REQUEST_PAUSE
    | DBG_HAS_THREAD_SUSPEND
    | DBG_HAS_THREAD_CONTINUE
    | DBG_HAS_SET_RESUME_MODE
    | DBG_HAS_CHECK_BPT
    | DBG_HAS_REXEC,
    const_cast<const char **>(kRegClasses),
    RC_GENERAL,
    const_cast<register_info_t *>(kRegisters),
    static_cast<int>(qnumber(kRegisters)),
    0x1000,
    kBreakInsnBytes,
    static_cast<uchar>(sizeof(kBreakInsnBytes)),
    0,
    DBG_RESMOD_STEP_INTO,
};

mepdbg_plugmod_t::mepdbg_plugmod_t() {
    g_active_plugmod = this;
    idd_listener.pm = this;
    ui_listener.pm = this;
    InstallHooks();
    RegisterIdcFunctions();
}

mepdbg_plugmod_t::~mepdbg_plugmod_t() {
    UnregisterIdcFunctions();
    UninstallHooks();
    set_log_callback(nullptr);
    if (g_active_plugmod == this) {
        g_active_plugmod = nullptr;
    }
    if (dbg == &g_debugger) {
        dbg = nullptr;
    }
}

void mepdbg_plugmod_t::InstallHooks() {
    if (!hooks_installed) {
        ::hook_event_listener(HT_IDD, &idd_listener, this);
        ::hook_event_listener(HT_IDP, &idp_listener, this);
        ::hook_event_listener(HT_UI, &ui_listener, this);
        hooks_installed = true;
    }
}

void mepdbg_plugmod_t::UninstallHooks() {
    if (hooks_installed) {
        unhook_event_listener(HT_UI, &ui_listener);
        unhook_event_listener(HT_IDD, &idd_listener);
        unhook_event_listener(HT_IDP, &idp_listener);
        hooks_installed = false;
    }
}

void mepdbg_plugmod_t::ResetSessionState() {
    entry_pc = DetermineEntryPc();
    machine.Reset(entry_pc, true, false);
    LoadSegmentsFromIdb();
    machine.cpu.control.pc = entry_pc;
    machine.cpu.r[MEP_REG_sp] = 0x00040000u;
}

bool idaapi mepdbg_plugmod_t::run(size_t) {
    info("F00D MePulator integrated debugger is active.\n"
         "Use Debugger -> Select debugger -> 'mepulator' (or F9) to debug this F00D binary in-process.\n"
         "In the debugger CLI bar you can run: status, intc, irq <n>, reset, eeprom <path>, step [n], help.");
    return true;
}

uint32_t mepdbg_plugmod_t::DetermineEntryPc() const {
    ea_t ea = inf_get_start_ip();
    if (ea != BADADDR) {
        return static_cast<uint32_t>(ea) & ~1u;
    }
    ea = inf_get_main();
    if (ea != BADADDR) {
        return static_cast<uint32_t>(ea) & ~1u;
    }
    segment_t *sram_seg = getseg(0x00800000u);
    if (sram_seg != nullptr) {
        return 0x00800000u;
    }
    segment_t *startup_seg = getseg(0x00040000u);
    if (startup_seg != nullptr) {
        return 0x00040000u;
    }
    const int qty = get_segm_qty();
    ea_t best = BADADDR;
    for (int i = 0; i < qty; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg || seg->is_header_segm()) {
            continue;
        }
        if (seg->perm & SEGPERM_EXEC) {
            return static_cast<uint32_t>(seg->start_ea) & ~1u;
        }
        if (best == BADADDR || seg->start_ea < best) {
            best = seg->start_ea;
        }
    }
    return best != BADADDR ? (static_cast<uint32_t>(best) & ~1u) : 0x00800000u;
}

void mepdbg_plugmod_t::LoadSegmentsFromIdb() {
    const int qty = get_segm_qty();
    std::vector<uint8_t> buf;
    for (int i = 0; i < qty; ++i) {
        segment_t *seg = getnseg(i);
        if (!seg || seg->start_ea >= seg->end_ea) {
            continue;
        }
        qstring sname;
        get_segm_name(&sname, seg);
        if (sname == "ABS" || seg->type == SEG_XTRN) {
            continue;
        }
        const ea_t seg_size = seg->end_ea - seg->start_ea;
        if (seg_size == 0 || seg_size > 0x08000000ULL) {
            continue;
        }
        const uint32_t start = static_cast<uint32_t>(seg->start_ea);
        const uint32_t sz = static_cast<uint32_t>(seg_size);
        machine.cpu.mem.EnsureRamRange(start, sz, sname.c_str(), MEM_PERM_RWX);

        buf.resize(sz);
        const ssize_t got = get_bytes(buf.data(), sz, seg->start_ea, GMB_READALL);
        if (got > 0) {
            // Copy initialized bytes cleanly while keeping uninitialized BSS zero-filled
            for (ea_t off = 0; off < sz; ) {
                if (!is_loaded(seg->start_ea + off)) {
                    ++off;
                    continue;
                }
                ea_t run_end = off + 1;
                while (run_end < sz && is_loaded(seg->start_ea + run_end)) {
                    ++run_end;
                }
                machine.cpu.mem.TryWrite(
                    start + static_cast<uint32_t>(off),
                    static_cast<uint32_t>(run_end - off),
                    buf.data() + off,
                    false);
                off = run_end;
            }
        }
    }
}

void mepdbg_plugmod_t::QueueEvent(const debug_event_t &ev) {
    event_queue.push_back(ev);
}

ea_t mepdbg_plugmod_t::ResolveBptKea(uint32_t stop_pc) const {
    const uint32_t masked = stop_pc & ~1u;
    if (ida_exec_bpts.find(masked) != ida_exec_bpts.end()) {
        return masked;
    }
    uint32_t mirrored = 0;
    if (Cpu::MirrorSramAddr(masked, &mirrored) && ida_exec_bpts.find(mirrored) != ida_exec_bpts.end()) {
        return mirrored;
    }
    return masked;
}

void mepdbg_plugmod_t::QueueStopEvent(const StopInfo &stop, bool from_single_step) {
    debug_event_t ev;
    ev.pid = kPid;
    ev.tid = kTid;
    ev.ea = stop.pc;
    ev.handled = true;

    switch (stop.reason) {
    case StopReason::None:
        if (from_single_step) {
            ev.set_eid(STEP);
            ev.ea = machine.cpu.control.pc & ~1u;
        } else {
            ev.set_eid(PROCESS_SUSPENDED);
        }
        break;
    case StopReason::Breakpoint:
        {
            const ea_t bpt_ea = ResolveBptKea(stop.pc);
            ev.ea = bpt_ea;
            bptaddr_t &bpt = ev.set_bpt();
            bpt.hea = BADADDR;
            bpt.kea = (bpt_ea == stop.pc) ? BADADDR : bpt_ea;
        }
        break;
    case StopReason::Watchpoint:
        {
            bptaddr_t &bpt = ev.set_bpt();
            bpt.hea = stop.detail;
            bpt.kea = BADADDR;
        }
        break;
    case StopReason::BreakInsn:
    case StopReason::DbreakInsn:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info.sprnt("Debug exception (DBG=0x%08X DEPC=0x%08X)",
                           machine.cpu.control.dbg, machine.cpu.control.depc);
        }
        break;
    case StopReason::Halt:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info = "CPU halt instruction";
        }
        break;
    case StopReason::Swi:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 5;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info.sprnt("SWI %u ($4=%u, $1=0x%08X)",
                           stop.detail, machine.cpu.r[4], machine.cpu.r[1]);
        }
        break;
    case StopReason::UnmappedMemory:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 11;
            exc.can_cont = true;
            exc.ea = stop.detail;
            exc.info.sprnt("Unmapped memory %s at 0x%08X", stop.is_write ? "write" : "read", stop.detail);
        }
        break;
    case StopReason::InvalidInsn:
        {
            excinfo_t &exc = ev.set_exception();
            exc.code = 4;
            exc.can_cont = true;
            exc.ea = stop.pc;
            exc.info.sprnt("Invalid instruction 0x%08X", stop.detail);
        }
        break;
    default:
        break;
    }

    invalidate_dbgmem_contents(0, BADADDR);
    QueueEvent(ev);
}

uint32_t mepdbg_plugmod_t::ReadRegByIdx(size_t idx) const {
    if (idx < 16) {
        return machine.cpu.r[idx];
    }
    if (idx < 48) {
        return machine.cpu.GetCR(static_cast<uint32_t>(idx - 16));
    }
    if (idx < 56) {
        return machine.cpu.GetIntc(static_cast<uint32_t>(idx - 48));
    }
    if (idx < qnumber(kRegisters)) {
        return machine.cpu.ReadControlBusRaw(kExtraCbAddrs[idx - 56]);
    }
    return 0;
}

void mepdbg_plugmod_t::WriteRegByIdx(size_t idx, uint32_t val) {
    if (idx < 16) {
        machine.cpu.r[idx] = val;
        return;
    }
    if (idx < 48) {
        machine.cpu.SetCR(static_cast<uint32_t>(idx - 16), val, true);
        return;
    }
    if (idx < 56) {
        machine.cpu.SetIntc(static_cast<uint32_t>(idx - 48), val);
        return;
    }
    if (idx < qnumber(kRegisters)) {
        machine.cpu.WriteControlBusRaw(kExtraCbAddrs[idx - 56], val);
    }
}

void mepdbg_plugmod_t::WriteRegAndInvalidate(size_t idx, uint32_t val) {
    const uint32_t prev_pc = machine.cpu.control.pc;
    const uint32_t prev_ivb = machine.cpu.intc.ivb;
    WriteRegByIdx(idx, val);
    // Writing $cfg, $ivr, or indirect CSR/control mutation can update $ivb / cache / interrupt state.
    if (idx == kRegIdxCfg
        || idx >= 56
        || (idx != kRegIdxPc && machine.cpu.control.pc != prev_pc)
        || (idx != kRegIdxIvb && machine.cpu.intc.ivb != prev_ivb)) {
        invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
    }
}

bool mepdbg_plugmod_t::ExecuteCommand(const char *cmdline, std::string &out) {
    out.clear();
    if (!cmdline || !*cmdline) {
        return true;
    }
    std::string cmd(cmdline);
    while (!cmd.empty() && std::isspace(static_cast<unsigned char>(cmd.back()))) {
        cmd.pop_back();
    }
    size_t start = 0;
    while (start < cmd.size() && std::isspace(static_cast<unsigned char>(cmd[start]))) {
        ++start;
    }
    cmd = cmd.substr(start);
    if (cmd.empty()) {
        return true;
    }

    char buf[512];
    if (cmd == "help" || cmd == "?") {
        out =
            "[mepdbg] Commands:\n"
            "  status         - Print CPU/INTC/DBG/Timer status\n"
            "  intc           - Print INTC (IVB/IVR/ISR/IER/IET/ILR0..3) and PSW\n"
            "  csr [name|n]   - Print CSRs and decoded PSW/EXC/DBG/CFG/RPE flags\n"
            "  timer          - Print Timer/Counter Ch0..Ch3 state\n"
            "  dsu            - Print DSU break/trace state and $dbg/$depc\n"
            "  cb <hex> [v]   - Read/write control bus address (bypasses DM check)\n"
            "  irq <n>        - Raise hardware IRQ n (0..31)\n"
            "  swi [0..3|mode]- Inspect SWI state, raise SIP0..3, or set mode <auto|arch|hle|trap>\n"
            "  signal [mask]  - Inspect/set HLE signaling flags (used by SWI $4=2,3)\n"
            "  applet [pc][sp]- Arm PSW.IEC|HIE|SIE0, IVB/IVR/ILR for direct applet execution\n"
            "  nmi            - Assert NMI input\n"
            "  dint           - Assert DSU debug interrupt (DINT)\n"
            "  reset          - Reset machine and reload IDB segments\n"
            "  eeprom <path>  - Load EEPROM keyring file\n"
            "  step [n]       - Execute n instructions (default 1)\n";
        return true;
    }
    if (cmd == "status") {
        out = machine.FormatStatus();
        return true;
    }
    if (machine.cpu.TryHandleCoreCommand(cmd, &out)) {
        if (cmd.rfind("irq ", 0) == 0 || cmd == "nmi" || cmd == "dint" ||
            cmd.rfind("cb ", 0) == 0 || cmd.rfind("swi ", 0) == 0 ||
            cmd == "applet" || cmd.rfind("applet ", 0) == 0) {
            invalidate_dbg_state(DBGINV_REGS);
        }
        return true;
    }
    if (cmd == "reset") {
        ResetSessionState();
        for (uint32_t ea : ida_exec_bpts) {
            machine.cpu.AddBreakpoint(ea);
        }
        invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY);
        qsnprintf(buf, sizeof(buf), "[mepdbg] Machine reset to PC=0x%08X", entry_pc);
        out = buf;
        return true;
    }
    if (cmd.rfind("eeprom ", 0) == 0) {
        const std::string path = cmd.substr(7);
        if (machine.LoadEepromFile(path.c_str())) {
            qsnprintf(buf, sizeof(buf), "[mepdbg] Loaded EEPROM from '%s'", path.c_str());
        } else {
            qsnprintf(buf, sizeof(buf), "[mepdbg] Failed to load EEPROM from '%s'", path.c_str());
        }
        out = buf;
        return true;
    }
    if (cmd == "step" || cmd.rfind("step ", 0) == 0) {
        uint64_t count = 1;
        if (cmd.size() > 5) {
            count = strtoull(cmd.c_str() + 5, nullptr, 0);
            if (count == 0) count = 1;
        }
        const StopInfo stop = machine.RunSteps(count, true, &pause_requested);
        qsnprintf(buf, sizeof(buf),
            "[mepdbg] Executed up to %llu steps -> PC=0x%08X (reason=%d)",
            static_cast<unsigned long long>(count), stop.pc, static_cast<int>(stop.reason));
        invalidate_dbgmem_contents(0, BADADDR);
        out = buf;
        return true;
    }

    qsnprintf(buf, sizeof(buf),
        "[mepdbg] Unknown command '%s'. Type 'help' for commands.", cmd.c_str());
    out = buf;
    return false;
}

ssize_t mepdbg_plugmod_t::HandleRexec(const char *cmdline) {
    std::string out;
    ExecuteCommand(cmdline, out);
    if (!out.empty()) {
        msg("%s\n", out.c_str());
    }
    return 0;
}

ssize_t mepdbg_plugmod_t::HandleIddEvent(ssize_t code, va_list va) {
    switch (code) {
    case debugger_t::ev_init_debugger:
        {
            va_arg(va, const char *);
            va_arg(va, int);
            va_arg(va, const char *);
            va_arg(va, qstring *);
            set_log_callback(IdaLogCallback);
            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = false;
            return DRC_OK;
        }

    case debugger_t::ev_term_debugger:
        {
            set_log_callback(nullptr);
            event_queue.clear();
            ida_exec_bpts.clear();
            is_running = false;
            attached = false;
            return DRC_OK;
        }

    case debugger_t::ev_get_processes:
        {
            procinfo_vec_t *procs = va_arg(va, procinfo_vec_t *);
            va_arg(va, qstring *);
            if (procs) {
                process_info_t &pi = procs->push_back();
                pi.pid = kPid;
                pi.name = "F00D Emulator";
            }
            return DRC_OK;
        }

    case debugger_t::ev_start_process:
        {
            const char *path = va_arg(va, const char *);
            va_arg(va, const char *);       // args
            va_arg(va, const char *);       // startdir
            va_arg(va, uint32);             // dbg_proc_flags
            const char *input_path = va_arg(va, const char *);
            va_arg(va, uint32);             // input_file_crc32
            va_arg(va, qstring *);          // errbuf
            va_arg(va, launch_env_t *);     // envs

            ResetSessionState();

            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = true;
            resmod = RESMOD_NONE;
            ignore_bpt_once = false;

            debug_event_t ev;
            ev.set_eid(PROCESS_STARTED);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = entry_pc;
            ev.handled = true;
            ev.modinfo().name = (input_path && *input_path) ? input_path : (path && *path ? path : "f00d.bin");
            ev.modinfo().base = entry_pc;
            ev.modinfo().size = 0;
            ev.modinfo().rebase_to = BADADDR;
            QueueEvent(ev);

            debug_event_t susp;
            susp.set_eid(PROCESS_SUSPENDED);
            susp.pid = kPid;
            susp.tid = kTid;
            susp.ea = entry_pc;
            susp.handled = true;
            QueueEvent(susp);
            return DRC_OK;
        }

    case debugger_t::ev_attach_process:
        {
            va_arg(va, pid_t);
            va_arg(va, int);
            va_arg(va, uint32);
            va_arg(va, qstring *);

            ResetSessionState();

            event_queue.clear();
            ida_exec_bpts.clear();
            pause_requested.store(false);
            is_running = false;
            attached = true;
            resmod = RESMOD_NONE;
            ignore_bpt_once = false;

            debug_event_t ev;
            ev.set_eid(PROCESS_STARTED);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = entry_pc;
            ev.handled = true;
            ev.modinfo().name = "f00d.bin";
            ev.modinfo().base = entry_pc;
            ev.modinfo().size = 0;
            ev.modinfo().rebase_to = BADADDR;
            QueueEvent(ev);
            return DRC_OK;
        }

    case debugger_t::ev_detach_process:
    case debugger_t::ev_exit_process:
        {
            va_arg(va, qstring *);
            is_running = false;
            attached = false;
            debug_event_t ev;
            ev.set_exit_code(PROCESS_EXITED, 0);
            ev.pid = kPid;
            ev.tid = kTid;
            ev.ea = machine.cpu.control.pc & ~1u;
            ev.handled = true;
            QueueEvent(ev);
            return DRC_OK;
        }

    case debugger_t::ev_get_debapp_attrs:
        {
            debapp_attrs_t *out_pattrs = va_arg(va, debapp_attrs_t *);
            if (out_pattrs) {
                out_pattrs->addrsize = 4;
                // Use IDA's built-in .gdb platform key in exceptions.cfg so codes 4/5/11 map cleanly without user config edits.
                out_pattrs->platform = "gdb";
                out_pattrs->is_be = false;
            }
            return DRC_OK;
        }

    case debugger_t::ev_rebase_if_required_to:
        {
            va_arg(va, ea_t);
            return DRC_OK;
        }

    case debugger_t::ev_request_pause:
        {
            va_arg(va, qstring *);
            pause_requested.store(true);
            return DRC_OK;
        }

    case debugger_t::ev_set_resume_mode:
        {
            va_arg(va, thid_t);
            resmod = static_cast<resume_mode_t>(va_arg(va, int));
            va_arg(va, qstring *);
            return DRC_OK;
        }

    case debugger_t::ev_resume:
        {
            const debug_event_t *ev = va_arg(va, const debug_event_t *);
            if (attached) {
                pause_requested.store(false);
                if (ev && ev->eid() == PROCESS_STARTED && !event_queue.empty()) {
                    is_running = false;
                } else {
                    is_running = true;
                    ignore_bpt_once = true;
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_get_debug_event:
        {
            gdecode_t *out_code = va_arg(va, gdecode_t *);
            debug_event_t *event = va_arg(va, debug_event_t *);
            const int timeout_ms = va_arg(va, int);

            if (!out_code || !event) {
                return DRC_FAILED;
            }

            if (event_queue.empty() && is_running) {
                if (resmod == RESMOD_INTO) {
                    const StopInfo stop = machine.Step(ignore_bpt_once);
                    ignore_bpt_once = false;
                    is_running = false;
                    resmod = RESMOD_NONE;
                    QueueStopEvent(stop, true);
                } else {
                    const StopInfo stop = machine.RunSteps(100000, ignore_bpt_once, &pause_requested);
                    ignore_bpt_once = false;
                    if (pause_requested.exchange(false)) {
                        is_running = false;
                        QueueStopEvent(StopInfo{StopReason::None, machine.cpu.control.pc & ~1u, 0, false}, false);
                    } else if (stop.reason != StopReason::None) {
                        is_running = false;
                        QueueStopEvent(stop, false);
                    } else if ((machine.cpu.sleeping || machine.cpu.halted) && timeout_ms > 0) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 25)));
                    }
                }
            }

            if (event_queue.empty()) {
                if (!is_running && timeout_ms > 0) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(std::min(timeout_ms, 10)));
                }
                *out_code = GDE_NO_EVENT;
                return DRC_OK;
            }

            *event = event_queue.front();
            event_queue.pop_front();
            if (event->eid() == PROCESS_SUSPENDED) {
                is_running = false;
            }
            *out_code = event_queue.empty() ? GDE_ONE_EVENT : GDE_MANY_EVENTS;
            return DRC_OK;
        }

    case debugger_t::ev_thread_suspend:
    case debugger_t::ev_thread_continue:
        {
            va_arg(va, thid_t);
            va_arg(va, qstring *);
            return DRC_OK;
        }

    case debugger_t::ev_read_registers:
        {
            va_arg(va, thid_t);
            const int clsmask = va_arg(va, int);
            regval_t *values = va_arg(va, regval_t *);
            va_arg(va, qstring *);
            if (!values) {
                return DRC_FAILED;
            }
            for (size_t i = 0; i < qnumber(kRegisters); ++i) {
                if (clsmask == 0 || (kRegisters[i].register_class_mask & clsmask) != 0) {
                    values[i].set_int(ReadRegByIdx(i));
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_write_register:
        {
            va_arg(va, thid_t);
            const int regidx = va_arg(va, int);
            const regval_t *value = va_arg(va, const regval_t *);
            va_arg(va, qstring *);
            if (!value || regidx < 0 || static_cast<size_t>(regidx) >= qnumber(kRegisters)) {
                return DRC_FAILED;
            }
            WriteRegAndInvalidate(static_cast<size_t>(regidx), static_cast<uint32_t>(value->ival));
            return DRC_OK;
        }

    case debugger_t::ev_get_memory_info:
        {
            meminfo_vec_t *ranges = va_arg(va, meminfo_vec_t *);
            va_arg(va, qstring *);
            if (!ranges) {
                return DRC_FAILED;
            }
            ranges->qclear();
            const auto regions = machine.cpu.mem.GetRegions();
            for (const auto &reg : regions) {
                memory_info_t &mi = ranges->push_back();
                mi.start_ea = reg.start;
                mi.end_ea = static_cast<ea_t>(reg.start) + static_cast<ea_t>(reg.size);
                mi.name = reg.name.c_str();
                mi.sclass = reg.is_device ? "DATA" : "CODE";
                mi.sbase = 0;
                mi.bitness = 1;
                mi.perm = ToIdaSegPerm(reg.perm);
            }
            return DRC_OK;
        }

    case debugger_t::ev_read_memory:
        {
            size_t *nbytes = va_arg(va, size_t *);
            const ea_t ea = va_arg(va, ea_t);
            void *buffer = va_arg(va, void *);
            const size_t size = va_arg(va, size_t);
            va_arg(va, qstring *);
            if (!nbytes || !buffer) {
                return DRC_FAILED;
            }
            if (size == 0) {
                *nbytes = 0;
                return DRC_OK;
            }
            if (machine.cpu.mem.TryRead(static_cast<uint32_t>(ea), static_cast<uint32_t>(size), buffer, false)) {
                *nbytes = size;
                return DRC_OK;
            }
            // Fallback byte-by-byte read across boundary regions
            uint8_t *dst = static_cast<uint8_t *>(buffer);
            size_t count = 0;
            while (count < size && machine.cpu.mem.TryRead(static_cast<uint32_t>(ea + count), 1, dst + count, false)) {
                ++count;
            }
            machine.cpu.mem.ClearFaults();
            *nbytes = count;
            return count > 0 ? DRC_OK : DRC_FAILED;
        }

    case debugger_t::ev_write_memory:
        {
            size_t *nbytes = va_arg(va, size_t *);
            const ea_t ea = va_arg(va, ea_t);
            const void *buffer = va_arg(va, const void *);
            const size_t size = va_arg(va, size_t);
            va_arg(va, qstring *);
            if (!nbytes || !buffer) {
                return DRC_FAILED;
            }
            if (size == 0) {
                *nbytes = 0;
                return DRC_OK;
            }
            const uint32_t addr = static_cast<uint32_t>(ea);
            const uint32_t sz = static_cast<uint32_t>(size);
            if (!machine.cpu.mem.TryWrite(addr, sz, buffer, false)) {
                machine.cpu.mem.ClearFaults();
                *nbytes = 0;
                return DRC_FAILED;
            }
            uint32_t mirrored = 0;
            if (Cpu::MirrorSramAddr(addr, &mirrored)) {
                invalidate_dbgmem_contents(mirrored, sz);
            }
            *nbytes = size;
            return DRC_OK;
        }

    case debugger_t::ev_check_bpt:
        {
            int *bptvc = va_arg(va, int *);
            const bpttype_t type = va_arg(va, bpttype_t);
            va_arg(va, ea_t);
            va_arg(va, int);
            if (bptvc) {
                switch (type) {
                case BPT_SOFT:
                case BPT_EXEC:
                case BPT_DEFAULT:
                case BPT_WRITE:
                case BPT_READ:
                case BPT_RDWR:
                    *bptvc = BPT_OK;
                    break;
                default:
                    *bptvc = BPT_BAD_TYPE;
                    break;
                }
            }
            return DRC_OK;
        }

    case debugger_t::ev_update_bpts:
        {
            int *nbpts = va_arg(va, int *);
            update_bpt_info_t *bpts = va_arg(va, update_bpt_info_t *);
            const int nadd = va_arg(va, int);
            const int ndel = va_arg(va, int);
            va_arg(va, qstring *);
            int count = 0;
            for (int i = 0; i < nadd + ndel; ++i) {
                update_bpt_info_t &b = bpts[i];
                if (b.code == BPT_SKIP) {
                    continue;
                }
                const bool is_add = i < nadd;
                const uint32_t ea = static_cast<uint32_t>(b.ea) & ~1u;
                if (b.type == BPT_SOFT || b.type == BPT_EXEC || b.type == BPT_DEFAULT) {
                    if (is_add) {
                        if (b.type == BPT_SOFT || b.type == BPT_DEFAULT) {
                            b.orgbytes.resize(2);
                            if (!machine.cpu.mem.TryRead(ea, 2, b.orgbytes.begin(), false)) {
                                b.orgbytes[0] = 0;
                                b.orgbytes[1] = 0;
                                machine.cpu.mem.ClearFaults();
                            }
                        }
                        machine.cpu.AddBreakpoint(ea);
                        ida_exec_bpts.insert(ea);
                    } else {
                        machine.cpu.RemoveBreakpoint(ea);
                        ida_exec_bpts.erase(ea);
                    }
                    b.code = BPT_OK;
                    ++count;
                } else {
                    const int wt = WatchTypeFromBpt(b.type);
                    const uint32_t wsize = b.size > 0 ? static_cast<uint32_t>(b.size) : 4u;
                    if (wt != 0) {
                        if (is_add) {
                            machine.cpu.mem.AddWatchpoint(static_cast<uint32_t>(b.ea), wsize, wt);
                        } else {
                            machine.cpu.mem.RemoveWatchpoint(static_cast<uint32_t>(b.ea), wsize, wt);
                        }
                        b.code = BPT_OK;
                        ++count;
                    } else {
                        b.code = BPT_BAD_TYPE;
                    }
                }
            }
            if (nbpts) {
                *nbpts = count;
            }
            return DRC_OK;
        }

    case debugger_t::ev_rexec:
        {
            const char *cmdline = va_arg(va, const char *);
            return HandleRexec(cmdline);
        }

    default:
        break;
    }

    return DRC_NONE;
}

ssize_t idaapi idd_listener_t::on_event(ssize_t code, va_list va) {
    return pm ? pm->HandleIddEvent(code, va) : DRC_NONE;
}

// Fallback IDP listener when Python mepf00d (rather than toshiba-mep-ida MeP) is loaded.
ssize_t idaapi idp_fallback_listener_t::on_event(ssize_t code, va_list va) {
    if (PH.psnames != nullptr && PH.psnames[0] != nullptr && streq(PH.psnames[0], "MeP")) {
        return 0;  // Native toshiba-mep-ida handles all IDP debugger callbacks directly.
    }

    switch (code) {
    case processor_t::ev_get_reg_info:
        {
            const char **main_regname = va_arg(va, const char **);
            bitrange_t *bitrange = va_arg(va, bitrange_t *);
            const char *regname = va_arg(va, const char *);
            const int idx = FindRegIdxByName(regname);
            if (idx >= 0) {
                if (main_regname) *main_regname = kRegisters[idx].name;
                if (bitrange) *bitrange = bitrange_t(0, 32);
                return 1;
            }
            return 0;
        }

    case processor_t::ev_calc_step_over:
        {
            ea_t *target = va_arg(va, ea_t *);
            const ea_t ip = va_arg(va, ea_t);
            if (!target || ip == BADADDR) {
                return 0;
            }
            insn_t ins;
            if (decode_insn(&ins, ip) <= 0) {
                return 0;
            }
            qstring mnem;
            print_insn_mnem(&mnem, ip);
            if (mnem == "bsr" || mnem == "jsr" || mnem == "bsrv" || mnem == "jsrv" || mnem == "swi") {
                *target = ip + ins.size;
                return 1;
            }
            *target = BADADDR;
            return 1;
        }

    default:
        break;
    }

    return 0;
}

ssize_t idaapi ui_listener_t::on_event(ssize_t code, va_list) {
    if ((code == ui_database_inited || code == ui_ready_to_run) && !debugger_selected) {
        if (load_debugger("mepdbg.dll", false) || load_debugger("mepulator", false)) {
            debugger_selected = true;
        }
    }
    return 0;
}

error_t idaapi idc_mepdbg_start(idc_value_t *, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    pm->ResetSessionState();
    pm->event_queue.clear();
    pm->ida_exec_bpts.clear();
    pm->pause_requested.store(false);
    pm->is_running = false;
    pm->attached = true;
    pm->resmod = RESMOD_NONE;
    pm->ignore_bpt_once = false;
    r->set_long(static_cast<sval_t>(static_cast<uint64_t>(pm->entry_pc)));
    return eOk;
}

error_t idaapi idc_mepdbg_step(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const uint64_t count = argv[0].num > 0 ? static_cast<uint64_t>(argv[0].num) : 1ULL;
    if (count == 1) {
        pm->machine.Step(true);
    } else {
        pm->machine.RunSteps(count, true, &pm->pause_requested);
    }
    invalidate_dbgmem_contents(0, BADADDR);
    r->set_long(static_cast<sval_t>(static_cast<uint64_t>(pm->machine.cpu.control.pc & ~1u)));
    return eOk;
}

error_t idaapi idc_mepdbg_run_to(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const uint32_t target = static_cast<uint32_t>(argv[0].num) & ~1u;
    uint32_t target_alias = 0;
    const bool has_alias = Cpu::MirrorSramAddr(target, &target_alias);
    const uint64_t max_steps = argv[1].num > 0 ? static_cast<uint64_t>(argv[1].num) : 1000000ULL;
    for (uint64_t i = 0; i < max_steps; ++i) {
        const StopInfo stop = pm->machine.Step(i == 0);
        const uint32_t cur_pc = pm->machine.cpu.control.pc & ~1u;
        if (cur_pc == target || (has_alias && cur_pc == target_alias)) {
            break;
        }
        if (stop.reason != StopReason::None || pm->machine.cpu.sleeping || pm->machine.cpu.halted) {
            break;
        }
    }
    invalidate_dbgmem_contents(0, BADADDR);
    r->set_long(static_cast<sval_t>(static_cast<uint64_t>(pm->machine.cpu.control.pc & ~1u)));
    return eOk;
}

error_t idaapi idc_mepdbg_get_reg(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) {
        r->set_long(-1);
        return eOk;
    }
    const uint32_t val = pm->ReadRegByIdx(static_cast<size_t>(idx));
    r->set_long(static_cast<sval_t>(static_cast<uint64_t>(val)));
    return eOk;
}

error_t idaapi idc_mepdbg_set_reg(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    const int idx = FindRegIdxByName(argv[0].c_str());
    if (idx < 0) {
        r->set_long(0);
        return eOk;
    }
    pm->WriteRegAndInvalidate(static_cast<size_t>(idx), static_cast<uint32_t>(argv[1].num));
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_mepdbg_read_u32(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(-1);
        return eOk;
    }
    uint32_t val = 0;
    const uint32_t addr = static_cast<uint32_t>(argv[0].num);
    if (!pm->machine.cpu.mem.TryRead(addr, sizeof(val), &val, false)) {
        pm->machine.cpu.mem.ClearFaults();
        r->set_long(-1);
        return eOk;
    }
    r->set_long(static_cast<sval_t>(static_cast<uint64_t>(val)));
    return eOk;
}

error_t idaapi idc_mepdbg_write_u32(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    const uint32_t addr = static_cast<uint32_t>(argv[0].num);
    const uint32_t val = static_cast<uint32_t>(argv[1].num);
    if (!pm->machine.cpu.mem.TryWrite(addr, sizeof(val), &val, false)) {
        pm->machine.cpu.mem.ClearFaults();
        r->set_long(0);
        return eOk;
    }
    invalidate_dbgmem_contents(addr, addr + 4);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_mepdbg_add_bpt(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    pm->machine.cpu.AddBreakpoint(static_cast<uint32_t>(argv[0].num) & ~1u);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_mepdbg_del_bpt(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    pm->machine.cpu.RemoveBreakpoint(static_cast<uint32_t>(argv[0].num) & ~1u);
    r->set_long(1);
    return eOk;
}

error_t idaapi idc_mepdbg_exec(idc_value_t *argv, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_string("ERROR: mepdbg plugmod not active");
        return eOk;
    }
    std::string out;
    pm->ExecuteCommand(argv[0].c_str(), out);
    r->set_string(out.c_str());
    return eOk;
}

error_t idaapi idc_mepdbg_stop(idc_value_t *, idc_value_t *r) {
    mepdbg_plugmod_t *pm = g_active_plugmod;
    if (!pm) {
        r->set_long(0);
        return eOk;
    }
    pm->is_running = false;
    pm->attached = false;
    pm->event_queue.clear();
    r->set_long(1);
    return eOk;
}

const char kArgsNone[] = { 0 };
const char kArgsLong[] = { VT_LONG, 0 };
const char kArgsStr[] = { VT_STR, 0 };
const char kArgsStrLong[] = { VT_STR, VT_LONG, 0 };
const char kArgsLongLong[] = { VT_LONG, VT_LONG, 0 };

const ext_idcfunc_t kIdcFuncs[] = {
    { "mepdbg_start",     idc_mepdbg_start,     kArgsNone,     nullptr, 0, EXTFUN_BASE },
    { "mepdbg_step",      idc_mepdbg_step,      kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "mepdbg_run_to",    idc_mepdbg_run_to,    kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "mepdbg_get_reg",   idc_mepdbg_get_reg,   kArgsStr,      nullptr, 0, EXTFUN_BASE },
    { "mepdbg_set_reg",   idc_mepdbg_set_reg,   kArgsStrLong,  nullptr, 0, EXTFUN_BASE },
    { "mepdbg_read_u32",  idc_mepdbg_read_u32,  kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "mepdbg_write_u32", idc_mepdbg_write_u32, kArgsLongLong, nullptr, 0, EXTFUN_BASE },
    { "mepdbg_add_bpt",   idc_mepdbg_add_bpt,   kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "mepdbg_del_bpt",   idc_mepdbg_del_bpt,   kArgsLong,     nullptr, 0, EXTFUN_BASE },
    { "mepdbg_exec",      idc_mepdbg_exec,      kArgsStr,      nullptr, 0, EXTFUN_BASE },
    { "mepdbg_stop",      idc_mepdbg_stop,      kArgsNone,     nullptr, 0, EXTFUN_BASE },
};

void mepdbg_plugmod_t::RegisterIdcFunctions() {
    if (!idc_registered) {
        for (const auto &fn : kIdcFuncs) {
            add_idc_func(fn);
        }
        idc_registered = true;
    }
}

void mepdbg_plugmod_t::UnregisterIdcFunctions() {
    if (idc_registered) {
        for (const auto &fn : kIdcFuncs) {
            del_idc_func(fn.name);
        }
        idc_registered = false;
    }
}

plugmod_t *idaapi init(void) {
    const char *proc0 = (PH.psnames != nullptr && PH.psnames[0] != nullptr) ? PH.psnames[0] : nullptr;
    const bool is_mep = (PH.id == 0xF00D) || (proc0 != nullptr && strnieq(proc0, "mep", 3));
    if (!is_mep) {
        return PLUGIN_SKIP;
    }

    if (proc0 != nullptr) {
        g_debugger.processor = proc0;
    }
    dbg = &g_debugger;
    return new mepdbg_plugmod_t();
}

}  // namespace

plugin_t PLUGIN = {
    IDP_INTERFACE_VERSION,
    PLUGIN_DBG | PLUGIN_PROC | PLUGIN_MULTI,
    init,
    nullptr,
    nullptr,
    "Integrated PS Vita F00D / Toshiba MeP Emulator Debugger",
    "In-process Toshiba MeP / F00D emulator debugger powered by mepulator.",
    "F00D MePulator",
    ""
};
