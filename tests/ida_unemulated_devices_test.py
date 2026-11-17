"""Headless IDA / IDA-MCP test to discover hardware devices not yet emulated by mepulator.

Usage:
  1. Via IDA headless MCP (`open_database` with `gui=False` on `second-dec150.bin.i64`,
     then `execute_python` calling `run(db)` or executing this script).
  2. Via IDA CLI headless:
     `idat.exe -A -S".\\tests\\ida_unemulated_devices_test.py" .\\second-dec150.bin.i64`
  3. Via standalone Python (launches `idat.exe -A` against a temporary copy of the IDB):
     `python .\\tests\\ida_unemulated_devices_test.py`
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback


def _resolve_repo_root():
    env_root = os.environ.get("MEPULATOR_ROOT")
    if env_root and os.path.isfile(os.path.join(env_root, "src", "f00d_machine.cpp")):
        return os.path.abspath(env_root)

    if "__file__" in globals():
        candidate = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if os.path.isfile(os.path.join(candidate, "src", "f00d_machine.cpp")):
            return candidate

    try:
        import ida_loader
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if idb_path:
            candidate = os.path.dirname(os.path.abspath(idb_path))
            if os.path.isfile(os.path.join(candidate, "src", "f00d_machine.cpp")):
                return candidate
    except ImportError:
        pass

    cwd = os.getcwd()
    if os.path.isfile(os.path.join(cwd, "src", "f00d_machine.cpp")):
        return cwd
    return None


def _parse_int_literal(expr, constants):
    expr = expr.strip()
    if expr in constants:
        return constants[expr]
    expr_clean = re.sub(r"[uUlL]+$", "", expr)
    return int(expr_clean, 0)


def parse_emulated_devices(repo_root):
    """Parse MapDevice() registrations and member types from src/f00d_machine.{h,cpp}."""
    constants = {}
    eeprom_h = os.path.join(repo_root, "src", "devices", "eeprom.h")
    if os.path.isfile(eeprom_h):
        with open(eeprom_h, "r", encoding="utf-8") as fp:
            m = re.search(r"kSize\s*=\s*(0x[0-9a-fA-F]+|\d+)", fp.read())
            if m:
                constants["EEPROM::kSize"] = int(m.group(1), 0)

    member_types = {}
    machine_h = os.path.join(repo_root, "src", "f00d_machine.h")
    if os.path.isfile(machine_h):
        with open(machine_h, "r", encoding="utf-8") as fp:
            for line in fp:
                m = re.match(r"^\s*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;\s*$", line)
                if m:
                    member_types[m.group(2)] = m.group(1)

    devices = []
    machine_cpp = os.path.join(repo_root, "src", "f00d_machine.cpp")
    with open(machine_cpp, "r", encoding="utf-8") as fp:
        src = fp.read()

    pattern = re.compile(
        r'MapDevice\(\s*([^,]+?)\s*,\s*([^,]+?)\s*,\s*&([A-Za-z_]\w*)\s*,\s*"([^"]+)"'
    )
    for start_s, size_s, member, name in pattern.findall(src):
        start = _parse_int_literal(start_s, constants)
        size = _parse_int_literal(size_s, constants)
        cls_name = member_types.get(member, "Device")
        devices.append({
            "name": name,
            "member": member,
            "class": cls_name,
            "start": start,
            "end": start + size,
            "size": size,
            "is_stub": cls_name == "UnknownDevice",
        })
    return devices


def _s16(v):
    return v - 0x10000 if (v & 0x8000) else v


def _u16(buf, off):
    return int.from_bytes(buf[off:off + 2], "little")


def _u32(buf, off):
    return int.from_bytes(buf[off:off + 4], "little")


def _reg_idx_from_op(op):
    import ida_idp
    import ida_ua

    if op.type != ida_ua.o_reg:
        return None
    name = ida_idp.get_reg_name(op.reg, 4)
    if not name:
        return None
    if name == "$tp":
        return 13
    if name == "$gp":
        return 14
    if name == "$sp":
        return 15
    if name.startswith("$") and name[1:].isdigit():
        return int(name[1:])
    return None


def _is_valid_code_run(data, base_ea, target_ea):
    import ida_ua

    off = target_ea - base_ea
    ascii_run = 0
    for b in data[max(0, off - 4):min(len(data), off + 8)]:
        if 0x20 <= b < 0x7F:
            ascii_run += 1
        else:
            ascii_run = 0
        if ascii_run >= 6:
            return False

    ea = target_ea
    end_ea = base_ea + len(data)
    for _ in range(6):
        if ea >= end_ea:
            return False
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz <= 0:
            return False
        ea += sz
    return True


def scan_segment_devices(base_ea, data):
    """Scan a loaded MeP segment for MMIO (0xE0000000..0xEFFFFFFF) and control-bus accesses."""
    import ida_ua

    mmio_refs = {}  # target_addr -> set(instruction_or_table_ea)
    cb_refs = {}    # cb_addr -> set(instruction_ea)

    ea = base_ea
    end_ea = base_ea + len(data)
    regs = {}

    while ea < end_ea:
        off = ea - base_ea
        insn = ida_ua.insn_t()
        sz = ida_ua.decode_insn(insn, ea)
        if sz <= 0 or off + sz > len(data):
            regs.clear()
            ea += 2
            continue

        hw0 = _u16(data, off)
        hw1 = _u16(data, off + 2) if sz == 4 else 0
        mnem = insn.get_canon_mnem()

        # ldcb / stcb immediate: 1111_nnnn_000x_0100 abs16
        if sz == 4 and (hw0 & 0xF0FF) in (0xF004, 0xF014) and _is_valid_code_run(data, base_ea, ea):
            cb_refs.setdefault(hw1, set()).add(ea)

        if sz == 4 and (hw0 & 0xF0FF) == 0xC021:  # movh $rn, imm16
            rn = (hw0 >> 8) & 0xF
            val = hw1 << 16
            if 0xE0000000 <= val < 0xF0000000 and _is_valid_code_run(data, base_ea, ea):
                regs[rn] = val
            else:
                regs.pop(rn, None)
        elif sz == 4 and (hw0 & 0xF00F) == 0xC004:  # or3 $rn, $rm, imm16
            rn = (hw0 >> 8) & 0xF
            rm = (hw0 >> 4) & 0xF
            if rm in regs:
                val = regs[rm] | hw1
                regs[rn] = val
                mmio_refs.setdefault(val, set()).add(ea)
            else:
                regs.pop(rn, None)
        elif sz == 4 and (hw0 & 0xF00F) == 0xC000:  # add3 $rn, $rm, imm16
            rn = (hw0 >> 8) & 0xF
            rm = (hw0 >> 4) & 0xF
            if rm in regs:
                val = (regs[rm] + _s16(hw1)) & 0xFFFFFFFF
                regs[rn] = val
                mmio_refs.setdefault(val, set()).add(ea)
            else:
                regs.pop(rn, None)
        elif sz == 2 and (hw0 & 0xF000) == 0x9000:  # add3 $rl, $rn, $rm
            rn = (hw0 >> 8) & 0xF
            rm = (hw0 >> 4) & 0xF
            rl = hw0 & 0xF
            if rn in regs:
                mmio_refs.setdefault(regs[rn], set()).add(ea)
            if rm in regs:
                mmio_refs.setdefault(regs[rm], set()).add(ea)
            regs.pop(rl, None)
        elif sz == 4 and (hw0 & 0xF000) == 0xC000 and (hw0 & 0x000F) in range(8, 16):
            rn = (hw0 >> 8) & 0xF
            rm = (hw0 >> 4) & 0xF
            op_low = hw0 & 0x000F
            if rm in regs:
                mmio_refs.setdefault((regs[rm] + _s16(hw1)) & 0xFFFFFFFF, set()).add(ea)
            if op_low in (8, 9, 10) and rn in regs:
                mmio_refs.setdefault(regs[rn], set()).add(ea)
            if op_low in (11, 12, 13, 14, 15):
                regs.pop(rn, None)
        elif sz == 4 and (hw0 & 0xF003) == 0xE002:  # sw_abs24 $rn, (abs24)
            rn = (hw0 >> 8) & 0xF
            if rn in regs:
                mmio_refs.setdefault(regs[rn], set()).add(ea)
        elif sz == 2 and (hw0 & 0xF000) == 0x0000 and (hw0 & 0x000F) in range(8, 16):
            rn = (hw0 >> 8) & 0xF
            rm = (hw0 >> 4) & 0xF
            op_low = hw0 & 0x000F
            if rm in regs:
                mmio_refs.setdefault(regs[rm], set()).add(ea)
            if op_low in (8, 9, 10) and rn in regs:
                mmio_refs.setdefault(regs[rn], set()).add(ea)
            if op_low in (11, 12, 13, 14, 15):
                regs.pop(rn, None)
        elif sz == 2 and (hw0 & 0xF00F) == 0x0000:  # mov $rn, $rm
            rn = (hw0 >> 8) & 0xF
            rm = (hw0 >> 4) & 0xF
            if rm in regs:
                regs[rn] = regs[rm]
            else:
                regs.pop(rn, None)
        elif mnem in ("bra", "jmp", "ret", "reti", "dret", "bsr", "jsr", "bsrv", "jsrv"):
            regs.clear()
        else:
            if mnem not in ("sw", "sh", "sb", "stc", "stcb", "beq", "bne", "beqi", "bnei", "beqz", "bnez", "bgei", "blti"):
                dst = _reg_idx_from_op(insn.ops[0])
                if dst is not None:
                    regs.pop(dst, None)

        ea += sz

    # Detect stride-8 (mmio_reg, value) initialization tables in data
    for off in range(0, len(data) - 32, 4):
        w0 = _u32(data, off)
        if 0xE0000000 <= w0 < 0xF0000000 and (w0 & 3) == 0:
            w1 = _u32(data, off + 8)
            w2 = _u32(data, off + 16)
            w3 = _u32(data, off + 24)
            if all((w & 0xFF000000) == (w0 & 0xFF000000) and (w & 3) == 0 for w in (w1, w2, w3)):
                mmio_refs.setdefault(w0, set()).add(base_ea + off)

    return mmio_refs, cb_refs


# Hardware metadata verified from https://wiki.henkaku.xyz/vita/* pages.
WIKI_DEVICE_INFO = {
    0xE0020000: {
        "wiki_name": "Unknown / Cmep 0xE0020000 (DMA & Security Gate)",
        "wiki_range": "0xE0020000-0xE0020FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Cmep_registers",
        "description": "DMA/crypto enable, cryAio async state, ReadAs DMA (+0x40..+0x48), and per-console keyring 0x602 window (+0x100..+0x11F).",
        "known_regs": {
            0x00: "Enable bits (arm2cry0..3, sc2cry01, ARM reset R/W; second_loader sets 0x30003)",
            0x04: "cryAio (write-once bits 0x8000003F; second_loader checks 0x8000001F clear)",
            0x20: "RAZ/WI working state / timer checked for 0 by second_loader",
            0x100: "256-bit key window populated from keyring 0x602",
        },
    },
    0xE0070000: {
        "wiki_name": "SceEmmcController (EmmcCrypto)",
        "wiki_range": "0xE0070000-0xE0070FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Cmep_registers",
        "description": "Hardware eMMC encryption controller configured by first_loader and second_loader.",
        "known_regs": {
            0x00: "EmmcCrypto Toggle (1=enable, 0=disable)",
            0x04: "EmmcCrypto availability status (bit 0 = boot device status; abort if set)",
            0x08: "EmmcCrypto keyrings indexes (two 16-bit write-only indexes, e.g. 0x020E020F)",
            0x0C: "Unknown status/config register",
            0x14: "Control register (set to 6 under condition in second_loader)",
        },
    },
    0xE0100000: {
        "wiki_name": "SceGpio1Reg (GPIO Bus 1)",
        "wiki_range": "0xE0100000-0xE0100FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/GPIO_Registers",
        "description": "GPIO Bus 1 (e.g. Port 7 LCD backlight); shares the standard SceGpio register layout (+0x00..+0x48).",
        "known_regs": {
            0x00: "Port mode (1=output, 0=input; 1 bit/port)",
            0x04: "Port read (0=low, 1=high)",
            0x08: "Port set",
            0x0C: "Port clear",
            0x10: "Port enable?",
            0x14: "Interrupt mode (ports 0..15, 2 bits/port)",
            0x18: "Interrupt mode (ports 16..31, 2 bits/port)",
            0x1C: "Gate 0 interrupt mask",
            0x20: "Gate 1 interrupt mask",
            0x24: "Gate 2 interrupt mask",
            0x28: "Gate 3 interrupt mask",
            0x2C: "Gate 4 interrupt mask",
            0x34: "Port read latched (output mode)",
            0x38: "Gate 0 interrupt status/clear",
            0x3C: "Gate 1 interrupt status/clear",
            0x40: "Gate 2 interrupt status/clear",
            0x44: "Gate 3 interrupt status/clear",
            0x48: "Gate 4 interrupt status/clear",
        },
    },
    0xE0A00000: {
        "wiki_name": "SceSpi0Reg",
        "wiki_range": "0xE0A00000-0xE0A00FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/SPI_Registers",
        "description": "SPI controller 0 (connected to SceSyscon).",
        "known_regs": {
            0x00: "SPI_RXFIFO (Read FIFO)",
            0x04: "SPI_TXFIFO (Write FIFO)",
            0x08: "SPI_CTL (Configuration)",
            0x0C: "SPI_INTCTL (Interrupt control)",
            0x10: "SPI_STATUS (Start/cancel transfer, busy)",
            0x14: "SPI_DMACTL",
            0x20: "Undocumented SPI register (listed as ?? on wiki)",
            0x24: "SPI_INT_STATUS (Bit 9 = RX FIFO not empty)",
            0x28: "SPI_RXFIFO_STATUS",
            0x2C: "SPI_TXFIFO_STATUS",
        },
    },
    0xE0B00000: {
        "wiki_name": "SceSdif0 (MMC)",
        "wiki_range": "0xE0B00000-0xE0B00FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/SDIF_Registers",
        "description": "SD/MMC Host Controller 0 (SD Host Controller Simplified Spec, mirrored every 0x100 bytes; +0x24 Present State, +0x29 Power Control, +0x2C Clock Control).",
        "known_regs": {
            0x24: "Present State",
            0x29: "Power Control (1 byte)",
            0x2C: "Clock Control (2 bytes)",
        },
    },
    0xE0BF0000: {
        "wiki_name": "Dynamic SceSdif1..3 base (0xE0BF0000 + (id << 16))",
        "wiki_range": "0xE0C00000-0xE0C2FFFF (SceSdif1..3 when id=1..3)",
        "wiki_url": "https://wiki.henkaku.xyz/vita/SDIF_Registers",
        "description": "Not a separate MMIO bank on the wiki; firmware computes 0xE0BF0000 + (port_id << 16) for port_id >= 1 to address SceSdif1 (0xE0C00000, SD/GC), SceSdif2 (0xE0C10000, Wlan/Bt), and SceSdif3 (0xE0C20000).",
        "known_regs": {},
    },
    0xE2030000: {
        "wiki_name": "SceUartReg (UART0..6)",
        "wiki_range": "0xE2030000-0xE209FFFF (port i at 0xE2030000 + i*0x10000)",
        "wiki_url": "https://wiki.henkaku.xyz/vita/UART_Registers",
        "description": "7 UART ports (0x80-byte interface per 0x10000 port window).",
        "known_regs": {
            0x04: "Enable port (1=enable, 0=disable)",
            0x28: "Port status (bit 8=Write FIFO not full, bit 9=Port ready)",
            0x40: "Unknown (0 written)",
            0x64: "Unknown (0x10001 written)",
            0x68: "Read FIFO data available (bits 0..5)",
            0x70: "Write FIFO",
            0x78: "Read FIFO",
        },
    },
    0xE20A0000: {
        "wiki_name": "SceGpio0Reg (GPIO Bus 0)",
        "wiki_range": "0xE20A0000-0xE20A0FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/GPIO_Registers",
        "description": "GPIO Bus 0 (OLED/LCD, Syscon I/O, UDCD, LEDs, Camera, HDMI, Motion, SDIF, 3G Modem); shares standard SceGpio layout (+0x00..+0x48).",
        "known_regs": {
            0x00: "Port mode (1=output, 0=input; 1 bit/port)",
            0x04: "Port read (0=low, 1=high)",
            0x08: "Port set",
            0x0C: "Port clear",
            0x10: "Port enable?",
            0x14: "Interrupt mode (ports 0..15)",
            0x18: "Interrupt mode (ports 16..31)",
            0x1C: "Gate 0 interrupt mask",
            0x20: "Gate 1 interrupt mask",
            0x24: "Gate 2 interrupt mask",
            0x28: "Gate 3 interrupt mask",
            0x2C: "Gate 4 interrupt mask",
            0x34: "Port read latched (output mode)",
            0x38: "Gate 0 interrupt status/clear",
            0x3C: "Gate 1 interrupt status/clear",
            0x40: "Gate 2 interrupt status/clear",
            0x44: "Gate 3 interrupt status/clear",
            0x48: "Gate 4 interrupt status/clear",
        },
    },
    0xE3100000: {
        "wiki_name": "ScePervasiveMisc",
        "wiki_range": "0xE3100000-0xE3100FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Pervasive",
        "description": "Pervasive miscellaneous status/control registers (+0x000..+0x194).",
        "known_regs": {
            0x000: "revision0 (RO, e.g. 0x80000115)",
            0x004: "Unknown RO (bit 2 indicates defective L2 cache)",
            0x030: "Unknown (bit 0 R/W; writing 1 hangs system)",
            0x180: "Unknown R/W",
            0x18C: "UART5 pull-down enable (bit 1=CTS, bit 0=TX)",
            0x194: "Game Card related (bit 0 R/W)",
        },
    },
    0xE3101000: {
        "wiki_name": "ScePervasiveReset",
        "wiki_range": "0xE3101000-0xE3101FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Pervasive",
        "description": "Per-peripheral reset control registers.",
        "known_regs": {
            0x004: "ARM Debugger? reset (mask 1)",
            0x010: "GPU reset (mask 1)",
            0x020: "PSP Allegrex reset (mask 1)",
            0x024: "SceSonyRegbus reset (mask 1)",
            0x178: "SPM32/SPM128 reset",
            0x17C: "Venezia? reset",
            0x180: "VIP? reset",
            0x190: "Bigmac or eMMC cryptor reset (cleared by SK cmd 0xD01)",
        },
    },
    0xE3102000: {
        "wiki_name": "ScePervasiveGate",
        "wiki_range": "0xE3102000-0xE3102FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Pervasive",
        "description": "Per-peripheral clock gating registers.",
        "known_regs": {
            0x000: "ARM? clock gate (mask 0x00F10000)",
            0x004: "ARM Debugger? clock gate (mask 1)",
            0x180: "Clock gate (mask 0xFF)",
            0x184: "Clock gate (mask 0x3)",
        },
    },
    0xE3103000: {
        "wiki_name": "ScePervasiveBaseClk",
        "wiki_range": "0xE3103000-0xE3103FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Pervasive",
        "description": "Base clock configuration registers.",
        "known_regs": {
            0x000: "ARM Clock (Non-Secure)",
            0x004: "ARM Clock (Secure)",
            0x030: "VIP Clock (Non-Secure)",
            0x040: "CMeP Clock (Secure)",
            0x050: "Center Xbar/Bus Clock (Secure, set to 1 by First Loader)",
            0x090: "DRAM Main Clock (Secure)",
        },
    },
    0xE3104000: {
        "wiki_name": "ScePervasiveVid",
        "wiki_range": "0xE3104000-0xE3104FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Pervasive",
        "description": "Voltage ID registers (used by sceSysconCtrlVoltageForDriver).",
        "known_regs": {
            0x000: "VDDA VID 0",
            0x004: "VDDA VID 1",
            0x008: "VDDA VID 2",
            0x00C: "VDDA VID 3",
            0x010: "VDDA VID 4",
            0x014: "VDDA VID 5",
            0x0A4: "Bus VID (0x1E)",
        },
    },
    0xE3105000: {
        "wiki_name": "SceUartClkgenReg",
        "wiki_range": "0xE3105000-0xE3105FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/UART_Registers",
        "description": "UART 0..6 clock generator registers (+port*4: bits 17:16 input clock select, bits 15:0 integer prescaler).",
        "known_regs": {
            0x00: "UART0 clock generator",
        },
    },
    0xE3110000: {
        "wiki_name": "ScePervasive2",
        "wiki_range": "0xE3110000-0xE3110FFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Pervasive",
        "description": "Secondary pervasive controller (ARM 0x0 alias selector, bus error registers, USB/Memory Card PHY states).",
        "known_regs": {
            0xC00: "0x0 alias for ARM (0 / 1) = (0x1F000000 / 0x40000000)",
        },
    },
    0xE6000000: {
        "wiki_name": "LPDDR2 I/F CH0 (Control Registers)",
        "wiki_range": "0xE6000000-0xE600FFFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Physical_Memory",
        "description": "LPDDR2 SDRAM Interface Channel 0 (individual register offsets not documented on the wiki).",
        "known_regs": {},
    },
    0xE6008000: {
        "wiki_name": "LPDDR2 I/F CH0 (PHY / Extended Registers)",
        "wiki_range": "0xE6000000-0xE600FFFF",
        "wiki_url": "https://wiki.henkaku.xyz/vita/Physical_Memory",
        "description": "LPDDR2 SDRAM Interface Channel 0 upper/PHY region (individual register offsets not documented on the wiki).",
        "known_regs": {},
    },
}


def _build_mepac_cb_info():
    """Control-bus register metadata from MeP-Arch-DSAE0020861.pdf."""
    info = {}
    timer_ref = "MeP-Arch-DSAE0020861.pdf Sec.6.2 (pp.251-258)"
    timer_specs = (
        (0, "CNT", "Counter {ch} (32-bit RW, initial 0x00000001; increments every TCD clock)."),
        (1, "CMP", "Compare Register {ch} (32-bit RW, initial 0; period = CMP * TCD * clock_period; 0 = 32-bit free-running)."),
        (2, "TEN", "Timer Enable {ch} (TEN enable control: 1 = run, 0 = stop; bit 0 in Fig. 137 & firmware, prose says bit 1)."),
        (3, "TCR", "Timer Control Register {ch} (bit 5 TAI auto-init to 1 on match{extra}, bit 0 TIE IRQ/NMI enable)."),
        (4, "TIS", "Timer Interrupt Status Register {ch} (bit 0 TIS R/W0C compare-match status)."),
        (5, "TCD", "Timer Clock Divide Register {ch} (bits 2:0 TCD, divisor 2^n for n=0..7, 1..128)."),
    )
    for ch in range(4):
        base = 0x0400 + ch * 0x10
        unit = f"MeP Timer/Counter Ch{ch}"
        extra = ", bit 4 TMD mode 0=interval/1=watchdog" if ch == 0 else ""
        for off, prefix, desc_tmpl in timer_specs:
            info[base + off] = {
                "reg_name": f"{prefix}{ch}",
                "unit": unit,
                "manual_ref": timer_ref,
                "description": desc_tmpl.format(ch=ch, extra=extra),
            }

    dsu_ref = "MeP-Arch-DSAE0020861.pdf Sec.3.11.12 (pp.152-164)"
    dsu_regs = (
        (0x0800, "DCR", "Debug Control Register (debug-mode only)."),
        (0x0801, "IBS", "Instruction Breakpoint Status Register (debug-mode only)."),
        (0x0802, "DBS", "Data Breakpoint Status Register (debug-mode only; Fig.36 lists 0x0802)."),
        (0x0803, "TCR", "Trace Control Register (debug-mode only)."),
        (0x0900, "IBA0", "Instruction Breakpoint Address 0 Register (debug-mode only)."),
        (0x0901, "IBC0", "Instruction Breakpoint Control 0 Register (debug-mode only)."),
        (0x0902, "IBM0", "Instruction Breakpoint Mask 0 Register (debug-mode only)."),
        (0x0A00, "DBA0", "Data Breakpoint Address 0 Register (debug-mode only)."),
        (0x0A01, "DBC0", "Data Breakpoint Control 0 Register (debug-mode only)."),
        (0x0A02, "DBM0", "Data Address Break Mask 0 Register (debug-mode only)."),
        (0x0A04, "DB0", "Data Value Break 0 Register (debug-mode only)."),
        (0x0A05, "DBU0", "Data Value Break Upper 0 Register (debug-mode only, 64-bit coprocessor datapath)."),
    )
    for addr, name, desc in dsu_regs:
        info[addr] = {
            "reg_name": name,
            "unit": "MeP Debug Support Unit (DSU)",
            "manual_ref": dsu_ref,
            "description": desc,
        }
    return info


MEPAC_CB_INFO = _build_mepac_cb_info()


def _annotate_cb_record(cb_addr, record):
    meta = MEPAC_CB_INFO.get(cb_addr)
    if meta:
        record["reg_name"] = meta["reg_name"]
        record["unit"] = meta["unit"]
        record["manual_ref"] = meta["manual_ref"]
        record["description"] = meta["description"]
    return record


def _annotate_device_record(page, addrs, record):
    meta = WIKI_DEVICE_INFO.get(page)
    if not meta:
        return record
    record["wiki_name"] = meta["wiki_name"]
    record["wiki_range"] = meta["wiki_range"]
    record["wiki_url"] = meta["wiki_url"]
    record["description"] = meta["description"]
    known = meta.get("known_regs", {})
    if known:
        reg_notes = {}
        for addr in addrs:
            off = addr - page
            if off in known:
                reg_notes[f"0x{addr:08X}"] = known[off]
        if reg_notes:
            record["documented_offsets"] = reg_notes
    return record


def _match_device(addr, devices):
    for dev in devices:
        if dev["start"] <= addr < dev["end"]:
            return dev
    return None


def _is_emulated_cb_reg(cb_addr):
    # Matches Cpu::IsMappedControlBusAddr / ReadControlBus / WriteControlBus in src/cpu.cpp
    if cb_addr < 8:
        return True
    if 0x0400 <= cb_addr <= 0x0435 and (cb_addr & 0xFF00) == 0x0400 and ((cb_addr >> 4) & 0xF) < 4 and (cb_addr & 0xF) <= 5:
        return True
    if (0x0800 <= cb_addr <= 0x0803) or (0x0900 <= cb_addr <= 0x0902) or (0x0A00 <= cb_addr <= 0x0A05 and cb_addr != 0x0A03):
        return True
    if 0x2000 <= cb_addr <= 0x207C and (cb_addr & 3) == 0:
        return True
    return False


def run(db=None):
    """Entrypoint compatible with IDA MCP `execute_python` and headless `idat.exe`."""
    import ida_auto
    import ida_bytes
    import ida_ida
    import ida_idp
    import ida_segment

    ida_auto.auto_wait()

    repo_root = _resolve_repo_root()
    if not repo_root:
        raise RuntimeError("Could not locate mepulator repository root (set MEPULATOR_ROOT).")

    proc_name = ida_ida.inf_get_procname()
    proc_id = ida_idp.ph_get_id()
    assert proc_name == "MeP", f"Expected processor 'MeP', got {proc_name!r}"
    assert proc_id == 0xF00D, f"Expected processor id 0xF00D, got {hex(proc_id)}"

    mapped_devices = parse_emulated_devices(repo_root)
    assert len(mapped_devices) >= 10, f"Unexpectedly few devices parsed: {mapped_devices}"

    segments = []
    all_mmio_refs = {}
    all_cb_refs = {}

    if db is not None:
        seg_iter = list(db.segments.get_all())
    else:
        seg_iter = [ida_segment.getnseg(i) for i in range(ida_segment.get_segm_qty())]

    for seg in seg_iter:
        if seg is None or seg.end_ea <= seg.start_ea:
            continue
        size = int(seg.end_ea - seg.start_ea)
        segments.append({
            "name": ida_segment.get_segm_name(seg),
            "start": hex(seg.start_ea),
            "end": hex(seg.end_ea),
            "size": hex(size),
        })
        raw = ida_bytes.get_bytes(seg.start_ea, size)
        if not raw:
            continue
        mmio_refs, cb_refs = scan_segment_devices(int(seg.start_ea), raw)
        for addr, eas in mmio_refs.items():
            all_mmio_refs.setdefault(addr, set()).update(eas)
        for cb_addr, eas in cb_refs.items():
            all_cb_refs.setdefault(cb_addr, set()).update(eas)

    assert len(segments) >= 1, "Database contains no segments"

    pages = {}
    for addr, eas in sorted(all_mmio_refs.items()):
        if not (0xE0000000 <= addr < 0xF0000000):
            continue
        page = addr & 0xFFFFF000
        entry = pages.setdefault(page, {"addrs": set(), "eas": set()})
        entry["addrs"].add(addr)
        entry["eas"].update(eas)

    emulated = []
    stubbed = []
    unemulated = []

    for page, info in sorted(pages.items()):
        dev = _match_device(page, mapped_devices)
        record = {
            "page": f"0x{page:08X}",
            "addresses": [f"0x{a:08X}" for a in sorted(info["addrs"])],
            "sample_sites": [f"0x{e:05X}" for e in sorted(info["eas"])[:8]],
            "reference_count": len(info["eas"]),
        }
        if dev is None:
            _annotate_device_record(page, sorted(info["addrs"]), record)
            unemulated.append(record)
        elif dev["is_stub"]:
            record["mapped_as"] = f'{dev["name"]} ({dev["class"]})'
            _annotate_device_record(page, sorted(info["addrs"]), record)
            stubbed.append(record)
        else:
            record["mapped_as"] = f'{dev["name"]} ({dev["class"]})'
            emulated.append(record)

    emulated_cb = []
    unemulated_cb = []
    for cb_addr, eas in sorted(all_cb_refs.items()):
        rec = {
            "cb_addr": f"0x{cb_addr:04X}",
            "sites": [f"0x{e:05X}" for e in sorted(eas)],
        }
        _annotate_cb_record(cb_addr, rec)
        if _is_emulated_cb_reg(cb_addr):
            emulated_cb.append(rec)
        else:
            unemulated_cb.append(rec)

    discovered_pages = {p for p in pages.keys()}
    expected_emulated_pages = {0xE0000000, 0xE0030000, 0xE0040000, 0xE0050000, 0xE0058000}
    missing_core = sorted(f"0x{p:08X}" for p in (expected_emulated_pages - discovered_pages))
    assert not missing_core, f"Scanner missed expected emulated devices: {missing_core}"

    expected_peripheral_pages = {
        0xE0100000,
        0xE0A00000,
        0xE0B00000,
        0xE0BF0000,
        0xE2030000,
        0xE20A0000,
        0xE3100000,
        0xE3110000,
        0xE6000000,
        0xE6008000,
    }
    missing_periph = sorted(f"0x{p:08X}" for p in (expected_peripheral_pages - discovered_pages))
    assert not missing_periph, f"Scanner missed expected firmware peripheral pages: {missing_periph}"

    for rec in unemulated:
        page_val = int(rec["page"], 16)
        assert _match_device(page_val, mapped_devices) is None, (
            f"Page {rec['page']} matched a mapped device unexpectedly"
        )

    assert len(unemulated_cb) == 0, f"Unexpected unemulated control-bus registers: {unemulated_cb}"
    cb_by_addr = {int(r["cb_addr"], 16): r for r in emulated_cb}
    for reg_addr in range(0x0400, 0x0406):
        assert reg_addr in cb_by_addr and "reg_name" in cb_by_addr[reg_addr], (
            f"Expected annotated Timer0 register 0x{reg_addr:04X} in emulated_control_bus_regs"
        )

    return {
        "ok": True,
        "repo_root": repo_root,
        "proc_name": proc_name,
        "proc_id": hex(proc_id),
        "segments": segments,
        "mapped_device_count": len(mapped_devices),
        "discovered_mmio_page_count": len(pages),
        "emulated_devices_in_binary": emulated,
        "stubbed_devices_in_binary": stubbed,
        "unemulated_devices": unemulated,
        "emulated_control_bus_regs": emulated_cb,
        "unemulated_control_bus_regs": unemulated_cb,
    }


def _find_idat_executable():
    env_idat = os.environ.get("IDAT_PATH")
    if env_idat and os.path.isfile(env_idat):
        return env_idat
    in_path = shutil.which("idat.exe") or shutil.which("idat")
    if in_path:
        return in_path
    for ver in ("9.5", "9.4", "9.3", "9.2", "9.1", "9.0"):
        candidate = rf"C:\Program Files\IDA Professional {ver}\idat.exe"
        if os.path.isfile(candidate):
            return candidate
    return None


def _run_standalone_cli():
    repo_root = _resolve_repo_root()
    if not repo_root:
        raise SystemExit("Run from mepulator repository or set MEPULATOR_ROOT.")

    idb_path = sys.argv[1] if len(sys.argv) > 1 else os.path.join(repo_root, "second-dec150.bin.i64")
    if not os.path.isfile(idb_path):
        raise SystemExit(f"Database not found: {idb_path}")

    idat = _find_idat_executable()
    if not idat:
        raise SystemExit("idat.exe not found on PATH or standard install directories; set IDAT_PATH.")

    report_path = os.path.join(repo_root, "build", "ida_unemulated_devices_report.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="mep_ida_test_") as tmpdir:
        tmp_i64 = os.path.join(tmpdir, os.path.basename(idb_path))
        shutil.copy2(idb_path, tmp_i64)
        env = os.environ.copy()
        env["MEPULATOR_ROOT"] = repo_root
        env["MEPULATOR_REPORT_PATH"] = report_path
        script_path = os.path.abspath(__file__)
        proc = subprocess.run(
            [idat, "-A", f'-S{script_path}', tmp_i64],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if proc.returncode != 0:
            print(proc.stdout)
            print(proc.stderr, file=sys.stderr)
            raise SystemExit(f"idat exited with code {proc.returncode}")

    with open(report_path, "r", encoding="utf-8") as fp:
        report = json.load(fp)
    print(json.dumps(report, indent=2))
    if not report.get("ok"):
        raise SystemExit(1)


if __name__ == "__main__":
    try:
        import ida_pro  # noqa: F401
        _IN_IDA = True
    except ImportError:
        _IN_IDA = False

    if _IN_IDA:
        repo_root = _resolve_repo_root() or os.getcwd()
        report_path = os.environ.get(
            "MEPULATOR_REPORT_PATH",
            os.path.join(repo_root, "build", "ida_unemulated_devices_report.json"),
        )
        os.makedirs(os.path.dirname(report_path), exist_ok=True)
        try:
            res = run(None)
        except Exception as exc:
            res = {"ok": False, "error": f"{exc}\n{traceback.format_exc()}"}
        with open(report_path, "w", encoding="utf-8") as fp:
            json.dump(res, fp, indent=2)
        import ida_pro
        ida_pro.qexit(0 if res.get("ok") else 1)
    else:
        _run_standalone_cli()
