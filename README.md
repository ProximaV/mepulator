# mepulator

PS Vita F00D / Toshiba MeP C5 emulator, standalone GDB RSP server, and integrated IDA Pro 9.x debugger plugin (`mepdbg.dll`).

## Build Targets
Defined in `CMakeLists.txt` (C++17 / C11, requires Python 3 for instruction table generation):
- **`mepulator_core`** (`STATIC`): Core MeP C5 CPU, memory subsystem, F00D machine & MMIO devices, GDB RSP debugger, logging/utilities, and vendored mbedTLS crypto/bignum primitives (`aes`, `aesni`, `bignum`, `platform`, `sha1`, `sha256`).
- **`mepulator`** (`EXECUTABLE`, `src/main.cpp`): Standalone headless emulator and TCP GDB RSP server.
- **`mepulator_tests`** (`EXECUTABLE`, `tests/mepulator_tests.cpp`): C++ unit and integration test suite registered with CTest.
- **`mepdbg`** (`SHARED` / `mepdbg.dll`, `src/ida_dbg_plugin.cpp`): Native in-process IDA Pro debugger plugin, built automatically when `${IDA_SDK_DIR}/include/idd.hpp` and `${IDA_SDK_DIR}/lib/x64_win_vc_64/ida.lib` are present.

## Feature Set

### 1. Toshiba MeP C5 CPU Core & Instruction Decoder (`src/cpu.*`, `src/insn.*`, `src/insn.in`, `src/generate_insn.py`)
- **Table-driven 16/32-bit instruction decoder**: `src/generate_insn.py` compiles 140 instruction encodings (86 16-bit, 54 32-bit) from `src/insn.in` into `insn_gen.cpp`, validates against duplicate opcode patterns, and sorts patterns by mask specificity (most fixed bits first, then 32-bit before 16-bit).
- **Implemented instruction families**:
  - **Arithmetic & logic**: `add`, `add3` (`$sp`, register, 16-bit immediate), `sub`, `neg`, `advck3`, `sbvck3`, `sl1ad3`, `sl2ad3`, `and`, `and3`, `or`, `or3`, `xor`, `xor3`, `nor`, `slt3` (`r0`/imm5/imm16), `sltu3` (`r0`/imm5/imm16).
  - **Shifts & extensions**: `sll` (reg/imm5), `sll3`, `srl` (reg/imm5), `sra` (reg/imm5), `ssarb`, `fsft`, `extb`, `exth`, `extub`, `extuh`.
  - **Moves & loads/stores**: `mov` (reg/imm8/imm16), `movu` (imm16/imm24), `movh`, `lb`/`lbu`/`lh`/`lhu`/`lw` (register-indirect, `$tp`/`$sp` disp7, disp16, abs24), `sb`/`sh`/`sw` (register-indirect, `$tp`/`$sp` disp7, disp16, abs24), `bsetm`, `bclrm`, `bnotm`, `btstm`, `tas`.
  - **Multiply, divide, DSP & atomics**: `mul`, `mulu`, `mulr`, `mulru`, `madd`, `maddu`, `maddr`, `maddru`, `div`, `divu` (with safe divide-by-zero and `INT32_MIN / -1` handling), `ldz`, `ave`, `abs`, `min`, `max`, `minu`, `maxu`, `sadd`, `saddu`, `ssub`, `ssubu`, `clip`, `clipu`, `casb3`, `cash3`, `casw3`.
  - **Control flow & hardware loops**: `beq`, `beqi`, `beqz`, `bgei`, `blti`, `bne`, `bnei`, `bnez`, `bra`, `bsr` (disp12/disp24), `bsrv`, `jmp` (reg/target24), `jsr`, `jsrv`, `ret`, `reti`, `dret`, `repeat`, and `erepeat` (including 2-instruction `rpe` pipeline tail handling and branch-out-of-range cancellation).
  - **Control/system/debug**: `ldc`, `stc`, `ldcb`, `ldcb_r`, `stcb`, `stcb_r`, `di`, `ei`, `sleep`, `halt`, `break`, `dbreak`, `swi`, `syncm`, `synccp`, plus no-op stubs for `cache`, `pref`, and `prefd`.
- **Full 56-register state & control bus**:
  - **16 GPRs**: `$r0..$r12`, `$tp` (`r13`), `$gp` (`r14`), `$sp` (`r15`).
  - **32 CSRs (`Control`, CR0..CR31)**: `$pc`, `$lp`, `$sar`, `$r3`, `$rpb`, `$rpe`, `$rpc`, `$hi`, `$lo`, `$r9..$r11`, `$mb0`, `$me0`, `$mb1`, `$me1`, `$psw`, `$id`, `$tmp`, `$epc`, `$exc`, `$cfg`, `$vid`, `$npc`, `$dbg`, `$depc`, `$opt`, `$rcfg`, `$ccfg`, `$r29..$r31`.
  - **8 INTC registers (`IntcRegs`)**: `$ivb`, `$isr`, `$ier`, `$iet`, `$ilr0..$ilr3`.
  - **Control bus (`ldcb`/`stcb`)**: maps `0x0000..0x0007` to `INTC[0..7]`, word-aligned `0x2000..0x207C` to `CR[0..31]`, and additional dynamic addresses to `cb_regs`.
- **Reset defaults & `$cfg` cache/vector transitions**:
  - Hardware defaults: `$ccfg = 0x5B105B08`, `$rcfg = 0x01000100`, `$opt = 0x03FD0201`, `$id = 0x00000100`.
  - Entry in uncached SRAM (`0x00040000..0x0005FFFF`) resets `$cfg = 0xF00000B0` (`EVM=1`, `IVM=0`) and `$ivb = 0x00040000`.
  - Entry elsewhere (e.g. cached SRAM `0x00800000+`) resets `$cfg = 0xF00004AA` (`EVM=0`, `IVM=1`, `ICE=1`, `0x400=1`) and `$ivb = 0x00800000`.
  - Writing `$cfg` (via `stc` or `stcb 0x2054`) tracks `DCE` (bit 0), `ICE` (bit 1), `IVM` (bit 3), `EVM` (bit 4), and `CacheBus` (bit 10 / `0x400`), and relocates `$ivb` between `0x00040000` and `0x00800000` when `EVM` toggles without modifying `$pc`. Switching execution between uncached and cached SRAM occurs via explicit control-flow instructions (such as `jmp 0x800360`).
- **Interrupts, exceptions & stop controls**:
  - Priority-arbitrated IRQ dispatch (`RaiseIrq`/`ClearIrq`/`ServicePendingInterrupt`) using `$ier`, `$isr`, `$ilr0..3`, and `$psw.IEC`, dispatching to `(ivb & ~0xFF) + 0x80 + irq * 4` when a non-zero handler word is installed and waking from `sleep`.
  - `swi` dispatches through `(ivb & ~0xFF) + 0x40 + (code & 3) * 4` when `swi_breaks_to_debugger` is false and a handler is present, or stops with `StopReason::Swi`.
  - Configurable stop flags (`stop_on_unmapped`, `stop_on_halt`, `stop_on_break`, `swi_breaks_to_debugger`) and stop reasons (`Breakpoint`, `Watchpoint`, `BreakInsn`, `DbreakInsn`, `Halt`, `Swi`, `UnmappedMemory`, `InvalidInsn`).

### 2. Memory Subsystem & F00D Memory Map (`src/memory.*`, `src/f00d_machine.*`)
- **Banked physical memory**: supports owned RAM/ROM banks, non-owning aliased banks (`MapAlias`), `EnsureRamRange` (fills only uncovered gaps without disturbing existing RAM/MMIO), cross-bank contiguous reads/writes, arbitrary-size MMIO reads/writes, and 4-byte instruction fetches with 2-byte end-of-segment fallback (`FetchInsn32`).
- **Standard F00D RAM & cache regions**:

| Start | Size | Name | Permissions | Notes |
| --- | --- | --- | --- | --- |
| `0x00000000` | `0x00040000` | `BOOTROM_LOW` | `RWX` | Low BootROM / vector region |
| `0x00040000` | `0x00020000` | `CMEP_SRAM_UNCACHED` | `RWX` | Non-owning alias of `0x00800000..0x0081FFFF` |
| `0x00300000` | `0x00010000` | `CMEP_ICACHE` | `RW` | Instruction cache RAM |
| `0x00310000` | `0x00010000` | `CMEP_ICACHE_TAG` | `RW` | Instruction cache tag RAM |
| `0x00320000` | `0x00010000` | `CMEP_DCACHE` | `RW` | Data cache RAM |
| `0x00330000` | `0x00010000` | `CMEP_DCACHE_TAG` | `RW` | Data cache tag RAM |
| `0x00800000` | `0x00200000` | `CMEP_SRAM` | `RWX` | Cached MeP SRAM |
| `0x40000000` | `0x00200000` | `SECURE_RAM` | `RWX` | Secure RAM |
| `0x50000000` | `0x02000000` | `NONSEC_DRAM` | `RWX` | Optional (`map_large_dram = true`) |

- **SRAM-mirrored breakpoints & watchpoints**: execution breakpoints and read/write/access watchpoints match across both the uncached (`0x00040000..0x0005FFFF`) and cached (`0x00800000..0x0081FFFF`) SRAM views, prioritizing direct window matches before alias matches.

### 3. F00D MMIO Peripherals & ARM Responder (`src/device.*`, `src/devices/*`, `src/arm.*`)
All MMIO banks are mapped `RW` with generic 8/16-bit RMW shims in `Device`:
- **`0xE0000000` (`0x1000`) — `ARMComm` (`MAILBOX`)**: thread-safe (`std::mutex`) 128-byte mailbox (`regs[32]`); ignores `0xFFFFFFFF` early boot probes on `+0x10`, clears `+0x00` status on `+0x10` writes, raises IRQ 8 on non-zero commands, and exposes `ArmSendCommand()`/`ArmReadReply()`.
- **`0xE0010000` (`0x1000`) — `e001device` (`SYS_E001`)**: 16-dword register block initialized with `regs[0] = 0x80000005`.
- **`0xE0020000` (`0x1000`) — `UnknownDevice` (`SEC_GATE`)**: RAZ/WI gate at `+0x20`, direct R/W mapping to EEPROM keyslot `0x602` at `+0x100..+0x11F`, and general backed register storage.
- **`0xE0030000` (`0x1000`) — `EEPROMProgrammer` (`KEYRING_CTRL`)**: writes 32-byte keys (`+0x00..+0x1C`) to target EEPROM slot (`+0x20`), manages per-line protection bits (`+0x28`/`+0x24`/`+0x2C`, defaulting `0x501 -> 0x10000007`, `0x502..0x515 -> 0x18000003`, others `0xDEAD`), and reports ready/idle (`0`) on status offsets `+0x04`/`+0x20`/`+0x24`.
- **`0xE0040000` (`0x1000`) — `Math` (`BIGNUM`)**: 2 KB operand RAM (`+0x108` base, `+0x300` multi-word exponent, `+0x400` modulus, `+0x508` result), 1-word exponent (`+0x808`), command (`+0x800`), and flags (`+0x804`); executes modular exponentiation (`PowMod`, `cmd >> 27 == 0x12`) for 1..64 words via `mbedtls_mpi_exp_mod` and raises IRQ 9.
- **`0xE0050000` & `0xE04E0000` (`0x1000` each) — `Bigmac` (`DMAC5_BIGMAC` & `DMAC5_MIRROR`)**: dual-channel DMAC5 engine (`+0x100`, `+0x180`), external key/IV registers (`+0x200..+0x2FF`), channel 0 busy status (`+0x24`), and `std::mt19937` PRNG (`+0x3C`, seeded `0xF00DC7A5`). Supports:
  - DMA `memcpy` (`op=0x00` / `0x2080`) and `memset` (`op=0x0C`)
  - AES-128/192/256 ECB (`op=0x01`/`0x09`), CBC (`op=0x02`/`0x0A`/`0x218a`/`0x238a`), and CTR (`op=0x21`/`0x21a1`) using external keys or EEPROM keyslots (`func & 0x400` or non-zero `keyslot` when no external key is staged)
  - SHA-1 (`op=0x03`), SHA-256 (`op=0x13`/`0x2093`), HMAC-SHA1 (`op=0x23`), and HMAC-SHA256 (`op=0x33`/`0x20b3`)
- **`0xE0058000` (`0x10000`) — `EEPROM` (`KEYRING_EEPROM`)**: 64 KB keyring (`0x400` slots × 32 bytes) supporting 8/16/32-bit reads, direct 32-bit writes, binary file loading (`EEPROM::Load`), and `SetKeySlot`/`GetKeySlot`.
- **`0xE0070000` (`0x1000`) & `0xE00C0000` (`0x1000`) — `UnknownDevice` (`EMMC_MISC` & `XBAR_CLK`)**: backed MMIO register stubs with read/write logging.
- **`0xE3000000` (`0x1000`) — `IntcMmioDevice` (`INTC_MMIO`)**: live MMIO mirror of `$ivb`..`$ilr3` (`+0x00..+0x1C`) plus 16 extra 32-bit scratch registers.
- **Simulated `ARM` responder (`src/arm.*`, `--with-arm-test`)**: background thread simulating ARM-side mailbox handshake (`StartUp`, `SetSharedBuffer`, `SetRvk` from `prog_rvk.srvk`, `SetTracebuf`, and `LoadSm` from `kprx_auth_sm.self`).

### 4. Integrated IDA Pro Debugger (`src/ida_dbg_plugin.cpp`, `mepdbg.dll`)
- **`PLUGIN_DBG | PLUGIN_PROC | PLUGIN_MULTI` plugin**: auto-activates when `PH.id == 0xF00D` or `PH.psnames[0]` starts with `mep`, and auto-selects `"mepdbg.dll"` / `"mepulator"` on `ui_database_inited` / `ui_ready_to_run`.
- **Fallback `HT_IDP` support**: when Python `mepf00d` is used instead of native `toshiba-mep-ida` (`MeP`), provides `ev_get_reg_info` (including aliases such as `h-pc`, `r0..r15`, `fp`, `$h-csr-*`) and `ev_calc_step_over` (`bsr`, `jsr`, `bsrv`, `jsrv`, `swi`).
- **Registers, memory & exceptions**: exposes all 56 registers across 3 register classes (`General registers`, `Control registers`, `INTC registers`, marking `$id` and `$vid` read-only), resolves entry PC (`start_ip` -> `main` -> `0x00800000` -> `0x00040000` -> first exec segment -> lowest segment), initializes `$sp = 0x00040000`, loads initialized IDB segment byte runs via `EnsureRamRange` while preserving zero-filled BSS, and maps stop reasons onto IDA's `.gdb` exception platform (`4`/`5`/`11`).
- **Cross-window SRAM synchronization**:
  - Matches breakpoints and watchpoints across `0x00040000..0x0005FFFF <-> 0x00800000..0x0081FFFF`, resolving `kea` back to the IDB's breakpoint address on stop.
  - Writing debugger memory invalidates IDA's cached memory in the mirrored SRAM range; modifying `$cfg` (or any register changing `$pc`/`$ivb`) triggers `invalidate_dbg_state(DBGINV_REGS | DBGINV_MEMORY)`.
- **Built-in Debugger CLI (`ev_rexec`)**: `status`, `intc`, `irq <n>`, `reset`, `eeprom <path>`, `step [n]`, `help` (`?`).
- **Registered IDC helpers**: `mepdbg_start()`, `mepdbg_stop()`, `mepdbg_step(n)`, `mepdbg_run_to(addr, max_steps)`, `mepdbg_get_reg(name)`, `mepdbg_set_reg(name, val)`, `mepdbg_read_u32(addr)`, `mepdbg_write_u32(addr, val)`, `mepdbg_add_bpt(addr)`, `mepdbg_del_bpt(addr)`, `mepdbg_exec(cmd)`.

### 5. Standalone CLI & GDB RSP Server (`src/main.cpp`, `src/debugger.*`)
- **Cross-platform TCP GDB RSP stub** (Winsock2 on Windows, POSIX sockets elsewhere; `Debugger::ProcessPacket` also callable directly without sockets):
  - `qSupported`: `PacketSize=4096;qXfer:features:read+;qXfer:memory-map:read+;QStartNoAckMode+;hwbreak+;swbreak+`.
  - Full 56-register `target.xml` (`org.gnu.gdb.mep.core`, `org.gnu.gdb.mep.csr`, `org.vita.f00d.intc`), dynamic `memory-map` XML from `Memory::GetRegions()`, register/memory R/W (`g`/`G`/`p`/`P`/`m`/`M`/`X`), SRAM-mirrored breakpoints & watchpoints (`Z0..Z4`/`z0..z4`), `s`/`c`/`vCont`, `D`/`k`, and async `0x03` (Ctrl-C) interrupt polling every 1024 instructions.
  - Monitor commands (`qRcmd`): `status`, `intc`, `irq <0..31>`, `reset`, `keyring` (dumps keyslot `0x602`).
- **CLI options (`mepulator`)**:
  - `--rom <path>` (default: `1692_f00d.bin`)
  - `--base <addr>` (default: `0x00800000`; also sets initial PC unless `--pc` is given)
  - `--pc <addr>` (default: `0x00800000`)
  - `--sp <addr>` (default: `0x00040000`)
  - `--eeprom <path>` (default: `1692_eeprom.bin`)
  - `--gdb` / `-g`, `--gdb-port <port>` (default: `1234`, implies `--gdb`)
  - `--headless` (default mode; overrides `--gdb`)
  - `--max-steps <n>` (`0` = unlimited)
  - `--with-arm-test`

## Building (Windows / Visual Studio 2022)

1. Build the `toshiba-mep-ida` processor module (`mep.dll`) from `..\..\module\toshiba-mep-ida\mep.vcxproj` (or your IDA SDK `src\module\toshiba-mep-ida`) and copy `Release64\mep.dll` into IDA's `procs\` directory (for example `%APPDATA%\Hex-Rays\IDA Pro\procs\mep.dll`).

2. Build `mepulator`, `mepulator_tests`, and `mepdbg.dll` from this directory:
   ```powershell
   cmake -S . -B build -G "Visual Studio 17 2022" -A x64 -DIDA_SDK_DIR=<ida-sdk>\src
   cmake --build build --config Release
   ```
   (`IDA_SDK_DIR` defaults to `$ENV{IDA_SDK_DIR}` or `..\..\..\ida-sdk-main\src`.)

   Run the unit tests:
   ```powershell
   .\build\Release\mepulator_tests.exe
   # or: ctest --test-dir build -C Release --output-on-failure
   ```
   Copy `.\build\Release\mepdbg.dll` into IDA's `plugins\` directory (for example `%APPDATA%\Hex-Rays\IDA Pro\plugins\mepdbg.dll`).

## Usage in IDA Pro
1. Open a PS Vita F00D binary or database (`BootROM`, `second_loader`, `secure_kernel`, etc.) in IDA Pro with the `MeP` processor selected.
2. Select **Debugger -> Select debugger -> mepulator** (or press `F9` / Start Process).
3. IDA maps all IDB segments alongside the F00D memory map, breaks at the entry point, and exposes all 56 GPR/CSR/INTC registers. Breakpoints and watchpoints operate across both the uncached (`0x00040000`) and cached (`0x00800000`) SRAM views.

## Headless IDA Verification
```powershell
idat.exe -A -S".\tests\ida_headless_test.py" .\105_f00d.i64
```

## CLI & Standalone GDB Server Examples
```powershell
# Run cached-base F00D payload headless:
mepulator.exe --rom f00d.bin --base 0x00800000 --pc 0x00800100 --headless --max-steps 10000

# Run uncached startup image (BootROM / loader) headless:
mepulator.exe --rom retail.bin --base 0x00040000 --pc 0x00040000 --headless --max-steps 50000

# Run GDB RSP server on port 1234:
mepulator.exe --rom f00d.bin --gdb --gdb-port 1234
```

## Repository Layout
- `src/cpu.*`, `src/insn.*`, `src/insn.in`, `src/generate_insn.py`, `src/util.*`, `src/log.*`: MeP C5 CPU core, instruction generator/decoder, and helpers.
- `src/memory.*`, `src/f00d_machine.*`: Banked memory manager, F00D address map, and `INTC_MMIO` bridge.
- `src/device.*`, `src/devices/*`, `src/arm.*`: MMIO devices (`armcomm`, `bigmac`, `e001device`, `eeprom`, `mathdev`, `unknowndevice`) and optional ARM mailbox responder.
- `src/debugger.*`, `src/main.cpp`: GDB RSP server and standalone CLI entrypoint.
- `src/ida_dbg_plugin.cpp`: Integrated IDA Pro 9.x debugger plugin (`mepdbg.dll`), debugger CLI, and IDC helpers.
- `tests/mepulator_tests.cpp`, `tests/ida_headless_test.py`: C++ unit/integration tests and headless IDA verification script.
