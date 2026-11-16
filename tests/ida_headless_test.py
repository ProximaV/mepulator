import ctypes
import json
import os
import traceback

import ida_auto
import ida_bytes
import ida_dbg
import ida_expr
import ida_ida
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_pro
import ida_segment
import ida_ua
import idc

REPORT_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "build",
    "ida_headless_report.txt",
)


def eval_idc(expr_str):
    rv = ida_expr.idc_value_t()
    err = ida_expr.eval_idc_expr(rv, ida_idaapi.BADADDR, expr_str)
    if err:
        raise RuntimeError(f"eval_idc_expr({expr_str!r}) failed: {err}")
    if rv.vtype == ida_expr.VT_STR:
        return rv.c_str()
    if rv.vtype == ida_expr.VT_INT64:
        return int(rv.i64)
    return int(rv.num)


def disasm_at(ea):
    text = ida_lines.generate_disasm_line(ea, 0)
    if text:
        return ida_lines.tag_remove(text).strip()
    return idc.GetDisasm(ea).strip()


def run_tests():
    ida_auto.auto_wait()
    report = {
        "ok": False,
        "checks": {},
        "segments": [],
        "reg_info": {},
        "ida_dbg": {},
        "step_trace": [],
        "rexec": {},
        "errors": [],
    }

    try:
        # 1. Verify processor & segments
        proc_name = ida_ida.inf_get_procname()
        proc_id = ida_idp.ph_get_id()
        start_ip = ida_ida.inf_get_start_ip()
        report["checks"]["proc_name"] = proc_name
        report["checks"]["proc_id"] = hex(proc_id)
        report["checks"]["start_ip"] = hex(start_ip)
        assert proc_name == "MeP", f"Expected proc_name 'MeP', got {proc_name!r}"
        assert proc_id == 0xF00D, f"Expected proc_id 0xF00D, got {hex(proc_id)}"

        seg_qty = ida_segment.get_segm_qty()
        has_800000 = False
        for i in range(seg_qty):
            seg = ida_segment.getnseg(i)
            if seg is None:
                continue
            sname = ida_segment.get_segm_name(seg)
            report["segments"].append({
                "name": sname,
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "perm": seg.perm,
            })
            if seg.start_ea <= 0x00800000 < seg.end_ea:
                has_800000 = True
        assert has_800000, f"No segment covering 0x00800000 found: {report['segments']}"

        # Verify decoding at 0x00800000
        insn = ida_ua.insn_t()
        insn_len = ida_ua.decode_insn(insn, 0x00800000)
        assert insn_len > 0, "Failed to decode instruction at 0x00800000"
        report["checks"]["entry_disasm"] = disasm_at(0x00800000)
        report["checks"]["entry_dword"] = hex(ida_bytes.get_dword(0x00800000))

        # 2. Verify ev_str2reg & ev_get_reg_info via ida_idp.parse_reg_name
        reg_names_to_check = [
            "$0", "$sp", "$tp", "$gp", "r0", "r15",
            "$pc", "pc", "$lp", "$psw", "$cfg", "$r3", "$h-csr-3",
            "$ivb", "$isr", "$ier", "$iet", "$ilr0", "$ilr1", "$ilr2", "$ilr3",
        ]
        for rname in reg_names_to_check:
            ri = ida_idp.reg_info_t()
            ok = ida_idp.parse_reg_name(ri, rname)
            assert ok, f"parse_reg_name failed for {rname!r}"
            report["reg_info"][rname] = {
                "reg": ri.reg,
                "size": ri.size,
            }

        is_ida_gui = bool(ctypes.windll.kernel32.GetModuleHandleW("ida.exe"))
        report["checks"]["host_exe"] = "ida.exe" if is_ida_gui else "idat.exe"

        # 3. Verify mepdbg.dll auto-selection / load_debugger("mepdbg.dll", False)
        was_dbg_on = bool(ida_dbg.is_debugger_on())
        loaded_dbg = ida_dbg.load_debugger("mepdbg.dll", False)
        report["ida_dbg"]["was_debugger_on_before_load"] = was_dbg_on
        report["ida_dbg"]["load_debugger_first"] = bool(loaded_dbg)
        if not loaded_dbg:
            lp_ok = ida_loader.load_plugin("mepdbg")
            report["ida_dbg"]["explicit_load_plugin"] = bool(lp_ok)
            loaded_dbg = ida_dbg.load_debugger("mepdbg.dll", False)
        report["ida_dbg"]["load_debugger"] = bool(loaded_dbg)
        report["ida_dbg"]["is_debugger_on"] = bool(ida_dbg.is_debugger_on())
        report["ida_dbg"]["process_state"] = int(ida_dbg.get_process_state())

        # 4. Test standard ida_dbg APIs
        idb_word0 = ida_bytes.get_dword(0x00800000)
        dbg_started = ida_dbg.start_process("", "", "")
        report["ida_dbg"]["start_process"] = int(dbg_started)
        assert loaded_dbg, "load_debugger('mepdbg.dll', False) returned False"
        assert dbg_started == 1, f"start_process returned {dbg_started}"
        if dbg_started == 1:
            ev1 = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
            report["ida_dbg"]["start_wait_event"] = int(ev1)
            report["ida_dbg"]["state_after_start"] = int(ida_dbg.get_process_state())
            pc_rv = ida_dbg.get_reg_val("$pc")
            sp_rv = ida_dbg.get_reg_val("$sp")
            cfg_rv = ida_dbg.get_reg_val("$cfg")
            ivb_rv = ida_dbg.get_reg_val("$ivb")
            dbg_word0_bytes = idc.get_bytes(0x00800000, 4, True)
            dbg_word0_idc = idc.read_dbg_dword(0x00800000)
            report["ida_dbg"]["entry_regs"] = {
                "$pc": hex(pc_rv),
                "$sp": hex(sp_rv),
                "$cfg": hex(cfg_rv),
                "$ivb": hex(ivb_rv),
                "dbg_word0_idc": hex(dbg_word0_idc) if dbg_word0_idc is not None else None,
            }
            assert dbg_word0_bytes and len(dbg_word0_bytes) == 4, "idc.get_bytes(0x00800000, 4, True) failed"
            dbg_word0 = int.from_bytes(dbg_word0_bytes, "little")
            assert dbg_word0 == idb_word0, f"RAM mismatch via ida_dbg: {hex(dbg_word0)} != {hex(idb_word0)}"
            assert dbg_word0_idc == idb_word0, f"read_dbg_dword mismatch: {dbg_word0_idc} != {hex(idb_word0)}"
            assert pc_rv == 0x00800000, f"Expected PC=0x00800000 via ida_dbg, got {hex(pc_rv)}"
            assert sp_rv == 0x00040000, f"Expected SP=0x00040000 via ida_dbg, got {hex(sp_rv)}"
            assert cfg_rv == 0xF00004AA, f"Expected CFG=0xF00004AA via ida_dbg, got {hex(cfg_rv)}"
            assert ivb_rv == 0x00800000, f"Expected IVB=0x00800000 via ida_dbg, got {hex(ivb_rv)}"

            step_ok = ida_dbg.step_into()
            ev_step = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
            pc_after_step = ida_dbg.get_reg_val("$pc")
            report["ida_dbg"]["step_into_ok"] = bool(step_ok)
            report["ida_dbg"]["step_wait_event"] = int(ev_step)
            report["ida_dbg"]["pc_after_step_into"] = hex(pc_after_step)
            assert step_ok and pc_after_step != 0x00800000, (
                f"ida_dbg.step_into failed: step_ok={step_ok}, pc={hex(pc_after_step)}"
            )

            add_bpt_ok = ida_dbg.add_bpt(0x00800266)
            cont_ok = ida_dbg.continue_process()
            ev_bpt = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
            pc_at_bpt = ida_dbg.get_reg_val("$pc")
            del_bpt_ok = ida_dbg.del_bpt(0x00800266)
            report["ida_dbg"]["add_bpt_ok"] = bool(add_bpt_ok)
            report["ida_dbg"]["continue_ok"] = bool(cont_ok)
            report["ida_dbg"]["bpt_wait_event"] = int(ev_bpt)
            report["ida_dbg"]["bpt_pc"] = hex(pc_at_bpt)
            report["ida_dbg"]["del_bpt_ok"] = bool(del_bpt_ok)
            assert add_bpt_ok and cont_ok, f"Breakpoint setup/continue failed: add={add_bpt_ok}, cont={cont_ok}"
            assert pc_at_bpt == 0x00800266, f"Expected bpt PC=0x00800266 via ida_dbg, got {hex(pc_at_bpt)}"
            assert del_bpt_ok, "ida_dbg.del_bpt(0x00800266) failed"

            # Verify SRAM alias breakpoint/run_to in uncached 0x00040000 window hits cached 0x00800000 execution
            ida_dbg.exit_process()
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
            assert ida_dbg.start_process("", "", "") == 1
            ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
            assert ida_dbg.run_to(0x00040266), "ida_dbg.run_to(0x00040266) failed"
            ev_alias_rt = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
            pc_alias_rt = ida_dbg.get_reg_val("$pc")
            report["ida_dbg"]["alias_run_to_ev"] = int(ev_alias_rt)
            report["ida_dbg"]["alias_run_to_pc"] = hex(pc_alias_rt)
            assert ev_alias_rt == 5 and pc_alias_rt == 0x00800266, (
                f"Expected alias run_to(0x00040266) stop at 0x00800266, got ev={ev_alias_rt}, pc={hex(pc_alias_rt)}"
            )

            ida_dbg.exit_process()
            ev_exit = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, 5)
            report["ida_dbg"]["exit_wait_event"] = int(ev_exit)
            report["ida_dbg"]["mode"] = "full_ida_dbg_passed"

        # 5. Exercise deterministic mepdbg_* IDC interface on real 105_f00d.i64 instructions
        entry_pc = eval_idc("mepdbg_start()")
        assert entry_pc == 0x00800000, f"Expected entry_pc=0x00800000, got {hex(entry_pc)}"

        ram_word0 = eval_idc("mepdbg_read_u32(0x00800000)")
        assert ram_word0 == idb_word0, (
            f"F00DMachine RAM at 0x00800000 ({hex(ram_word0)}) != IDB ({hex(idb_word0)})"
        )
        mirror_word0 = eval_idc("mepdbg_read_u32(0x00040000)")
        assert mirror_word0 == idb_word0, (
            f"F00DMachine uncached mirror at 0x00040000 ({hex(mirror_word0)}) != IDB ({hex(idb_word0)})"
        )
        report["checks"]["ram_match_word0"] = hex(ram_word0)
        report["checks"]["mirror_match_word0"] = hex(mirror_word0)

        init_pc = eval_idc('mepdbg_get_reg("$pc")')
        init_sp = eval_idc('mepdbg_get_reg("$sp")')
        init_cfg = eval_idc('mepdbg_get_reg("$cfg")')
        init_ivb = eval_idc('mepdbg_get_reg("$ivb")')
        report["checks"]["initial_regs"] = {
            "$pc": hex(init_pc),
            "$sp": hex(init_sp),
            "$cfg": hex(init_cfg),
            "$ivb": hex(init_ivb),
        }
        assert init_pc == 0x00800000
        assert init_sp == 0x00040000
        assert init_cfg == 0xF00004AA, f"Expected $cfg=0xF00004AA, got {hex(init_cfg)}"
        assert init_ivb == 0x00800000

        # Single-step 8 entry instructions of 105_f00d.i64 and trace PC/registers
        for step_idx in range(8):
            cur_pc = eval_idc('mepdbg_get_reg("$pc")')
            insn_text = disasm_at(cur_pc)
            before = {r: eval_idc(f'mepdbg_get_reg("{r}")') for r in ("$0", "$1", "$2", "$3", "$4", "$sp", "$lp", "$psw")}
            next_pc = eval_idc("mepdbg_step(1)")
            after = {r: eval_idc(f'mepdbg_get_reg("{r}")') for r in ("$0", "$1", "$2", "$3", "$4", "$sp", "$lp", "$psw")}
            changed = {r: f"{hex(before[r])} -> {hex(after[r])}" for r in before if before[r] != after[r]}
            report["step_trace"].append({
                "step": step_idx,
                "pc": hex(cur_pc),
                "disasm": insn_text,
                "next_pc": hex(next_pc),
                "changed": changed,
            })

        # 6. Register read/write verification
        reg_rw_cases = [
            ("$0", 0x12345678),
            ("$sp", 0x0081FF00),
            ("$ivb", 0x00800100),
            ("$ier", 0x00000005),
        ]
        for rname, val in reg_rw_cases:
            prev = eval_idc(f'mepdbg_get_reg("{rname}")')
            ok = eval_idc(f'mepdbg_set_reg("{rname}", 0x{val:08X})')
            got = eval_idc(f'mepdbg_get_reg("{rname}")')
            assert ok == 1 and got == val, f"Reg R/W failed for {rname}: ok={ok}, got={hex(got)}, expected={hex(val)}"
            eval_idc(f'mepdbg_set_reg("{rname}", 0x{prev:08X})')
        report["checks"]["reg_rw"] = "passed"

        # 7. Memory read/write verification at 0x0081F000
        orig_mem = eval_idc("mepdbg_read_u32(0x0081F000)")
        assert orig_mem >= 0, f"mepdbg_read_u32(0x0081F000) failed: {orig_mem}"
        w_ok = eval_idc("mepdbg_write_u32(0x0081F000, 0xCAFEBABE)")
        r_val = eval_idc("mepdbg_read_u32(0x0081F000)")
        assert w_ok == 1 and r_val == 0xCAFEBABE, f"Memory R/W failed: ok={w_ok}, got={hex(r_val)}"
        eval_idc(f"mepdbg_write_u32(0x0081F000, 0x{orig_mem:08X})")
        report["checks"]["mem_rw"] = "passed"

        # 8. Breakpoint + run_to verification:
        # Reset session and place breakpoint at observed PC of step 3 in step_trace
        eval_idc("mepdbg_start()")
        bpt_target = int(report["step_trace"][3]["pc"], 16)
        assert eval_idc(f"mepdbg_add_bpt(0x{bpt_target:08X})") == 1
        # Ask run_to for an unreachable sentinel address so it must stop ONLY because the breakpoint hit
        stopped_pc = eval_idc("mepdbg_run_to(0xDEADBEEF, 10000)")
        assert stopped_pc == bpt_target, (
            f"Breakpoint stop mismatch: stopped_pc={hex(stopped_pc)}, expected bpt={hex(bpt_target)}"
        )
        assert eval_idc(f"mepdbg_del_bpt(0x{bpt_target:08X})") == 1
        report["checks"]["breakpoint_stop_pc"] = hex(stopped_pc)

        # 9. rexec / mepdbg_exec verification
        status_out = eval_idc('mepdbg_exec("status")')
        intc_out = eval_idc('mepdbg_exec("intc")')
        irq_out = eval_idc('mepdbg_exec("irq 0")')
        report["rexec"]["status"] = status_out
        report["rexec"]["intc"] = intc_out
        report["rexec"]["irq 0"] = irq_out
        assert "PC=" in status_out, f"Unexpected status output: {status_out!r}"
        assert "IVB=" in intc_out and "IER=" in intc_out, f"Unexpected intc output: {intc_out!r}"
        assert "Raised IRQ 0" in irq_out, f"Unexpected irq output: {irq_out!r}"

        assert eval_idc("mepdbg_stop()") == 1
        report["ok"] = True
    except Exception as exc:
        report["errors"].append(f"{exc}\n{traceback.format_exc()}")
    finally:
        with open(REPORT_PATH, "w", encoding="utf-8") as fp:
            json.dump(report, fp, indent=2)
        ida_pro.qexit(0 if report["ok"] else 1)


class _ReadyHooks(ida_kernwin.UI_Hooks):
    def ready_to_run(self):
        self.unhook()
        run_tests()


_READY_HOOKS = None


if __name__ == "__main__":
    if ctypes.windll.kernel32.GetModuleHandleW("ida.exe") != 0:
        _READY_HOOKS = _ReadyHooks()
        _READY_HOOKS.hook()
    else:
        run_tests()
