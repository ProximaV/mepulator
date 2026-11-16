# mepulator

PS Vita F00D / Toshiba MeP C5 emulator, standalone GDB RSP server, and integrated IDA Pro 9.x debugger plugin (`mepdbg.dll`).

## Features
- **Toshiba MeP C5 core & instruction decoder**: Full 16/32-bit MeP instruction decoding sorted by mask specificity, `Control` registers (`$pc`..`$r31`), `INTC` registers (`$ivb`, `$isr`, `$ier`, `$iet`, `$ilr0..3`), `ldcb`/`stcb` control-bus transfers, hardware `repeat`/`erepeat` loops, `sleep`/`halt`/`break`/`dbreak`/`swi`/`reti`/`dret`, and PS Vita F00D reset defaults (`$ccfg = 0x5B105B08`, `$rcfg = 0x01000100`, `$opt = 0x03FD0201`).
- **Memory map, uncached/cached SRAM alias, & `$cfg` behavior**:
  - Maps `BOOTROM_LOW` (`0x00000000..0x0003FFFF`), `CMEP_ICACHE` / `CMEP_ICACHE_TAG` / `CMEP_DCACHE` / `CMEP_DCACHE_TAG` (`0x00300000..0x0033FFFF`), `CMEP_SRAM` (`0x00800000..0x009FFFFF`), `CMEP_SRAM_UNCACHED` (`0x00040000..0x0005FFFF` mirrored to `0x00800000..0x0081FFFF`), `SECURE_RAM` (`0x40000000..0x401FFFFF`), and `NONSEC_DRAM` (`0x50000000..0x51FFFFFF`).
  - Entry in the uncached window (`0x00040000..0x0005FFFF`, e.g. BootROM or `second_loader`) initializes `$cfg = 0xF00000B0` (`EVM=1`, `IVM=0`) and `$ivb = 0x00040000`; entry in cached SRAM (`0x00800000+`) initializes `$cfg = 0xF00004AA` (`EVM=0`, `IVM=1`, `ICE=1`, `0x400=1`) and `$ivb = 0x00800000`.
  - Writing `$cfg` updates cache enable state (`ICE` bit 1, bus/cache enable bit 10 / `0x400`, `DCE` bit 0) and relocates `$ivb` between `0x00040000` and `0x00800000` when `EVM` (bit 4) toggles, without mutating `$pc`. Switching execution from uncached `0x00040000` to cached `0x00800000` occurs via explicit control-flow instructions (such as `jmp 0x800360`).
- **F00D MMIO peripherals**:
  - `0xE0000000`: `ARMComm` mailbox
  - `0xE0010000`: `e001device`
  - `0xE0020000`: Security gate / fuse slot `0x602` (`0x100..0x11F`)
  - `0xE0030000` & `0xE0058000`: `EEPROMProgrammer` & EEPROM keyring (`0x400` slots)
  - `0xE0040000`: `Math` bignum modular exponentiation (`PowMod`, 1..64 words)
  - `0xE0050000` / `0xE04E0000`: `Bigmac` DMAC5 crypto/DMA engine (memcpy, memset, AES-ECB/CBC/CTR encrypt+decrypt, SHA-1, SHA-256, HMAC-SHA1/SHA256, RNG)
  - `0xE0070000`: `EMMC_MISC` (`UnknownDevice`)
  - `0xE00C0000`: `XBAR_CLK` (`UnknownDevice`)
  - `0xE3000000`: `IntcMmio` mirror of `$ivb`/`$isr`/`$ier`/`$iet`/`$ilr0..3`
- **Integrated IDA Pro Debugger (`mepdbg.dll`)**:
  - `PLUGIN_DBG | PLUGIN_PROC | PLUGIN_MULTI` native plugin embedding `F00DMachine` directly inside IDA Pro — no external `gdbserver` process needed.
  - Auto-activates whenever the loaded database uses `toshiba-mep-ida` (`MeP`, `PH.id == 0xF00D`) or Python `mepf00d`.
  - Loads all IDB segments into emulator RAM, resolves the entry PC (`start_ip`, `main`, `0x00800000`, `0x00040000`, or first executable/lowest segment), and exposes all 56 GPR/CSR/INTC registers.
  - Supports execution breakpoints (`F2`), `Run to cursor` (`F4`), read/write/access data watchpoints, Step Into (`F7`), Step Over (`F8`), Continue (`F9`), Pause, Stop, debugger CLI commands (`status`, `intc`, `irq <n>`, `reset`, `eeprom <path>`, `step [n]`, `help`), and IDC helpers (`mepdbg_start`, `mepdbg_stop`, `mepdbg_step`, `mepdbg_run_to`, `mepdbg_get_reg`, `mepdbg_set_reg`, `mepdbg_read_u32`, `mepdbg_write_u32`, `mepdbg_add_bpt`, `mepdbg_del_bpt`, `mepdbg_exec`).
  - Handles `0x00040000`-based and `0x00800000`-based debugging seamlessly: breakpoints, watchpoints, and `run_to` match across the `0x00040000..0x0005FFFF <-> 0x00800000..0x0081FFFF` SRAM mirror, and editing `$cfg` while paused invalidates IDA's cached registers and memory (`DBGINV_REGS | DBGINV_MEMORY`).
- **Standalone CLI & GDB RSP Server (`mepulator.exe`)**:
  - Exposes 56-register XML target description, memory map XML, SRAM-mirrored `Z0..Z4` breakpoints/watchpoints, and `monitor` (`qRcmd`) commands.

## Building (Windows / Visual Studio 2022)

1. Build `toshiba-mep-ida` processor module (`mep.dll`):
   ```powershell
   & "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe" `
     c:\Users\HomeUser\source\repos\ida-sdk-main\src\module\toshiba-mep-ida\mep.vcxproj `
     /p:Configuration=Release64 /p:Platform=x64
   ```
   Copy `mep.dll` into IDA's `procs\` directory (for example `%APPDATA%\Hex-Rays\IDA Pro\procs\mep.dll`).

2. Build `mepulator`, `mepulator_tests`, and `mepdbg.dll`:
   ```powershell
   $cmake = "C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
   & $cmake -S c:\Users\HomeUser\source\repos\vita\F00D\mepulator -B c:\Users\HomeUser\source\repos\vita\F00D\mepulator\build -G "Visual Studio 17 2022" -A x64
   & $cmake --build c:\Users\HomeUser\source\repos\vita\F00D\mepulator\build --config Release
   ```
   Run the unit test suite:
   ```powershell
   c:\Users\HomeUser\source\repos\vita\F00D\mepulator\build\Release\mepulator_tests.exe
   ```
   Copy `build\Release\mepdbg.dll` into IDA's `plugins\` directory (for example `%APPDATA%\Hex-Rays\IDA Pro\plugins\mepdbg.dll`).

## Usage in IDA Pro
1. Open a PS Vita F00D binary or database (`BootROM`, `second_loader`, `secure_kernel`, etc.) in IDA Pro with the `MeP` processor selected.
2. Select **Debugger -> Select debugger -> mepulator** (or press `F9` / Start Process).
3. IDA maps all IDB segments alongside the F00D memory map, breaks at the entry point, and shows `$0..$12/$tp/$gp/$sp/$pc`, all MeP control registers, and `INTC` registers. Breakpoints and watchpoints work in both the uncached (`0x00040000`) and cached (`0x00800000`) SRAM views.

## Headless IDA Verification
```powershell
& "C:\Program Files\IDA Professional 9.5\idat.exe" -A `
  -S"c:\Users\HomeUser\source\repos\vita\F00D\mepulator\tests\ida_headless_test.py" `
  "C:\Users\HomeUser\source\repos\vita\F00D\105_f00d.i64"
```

## CLI & Standalone GDB Server
```powershell
# Run cached-base F00D payload headless:
mepulator.exe --rom 1692_f00d.bin --base 0x00800000 --pc 0x00800100 --headless --max-steps 10000

# Run uncached startup image (BootROM / second_loader) headless:
mepulator.exe --rom PCH-1001-bootrom-retail.bin --base 0x00040000 --pc 0x00040000 --headless --max-steps 50000

# Run GDB RSP server on port 1234:
mepulator.exe --rom 1692_f00d.bin --gdb --gdb-port 1234
```
