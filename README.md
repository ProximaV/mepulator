# mepulator

PS Vita F00D / Toshiba MeP C5 emulator, standalone GDB RSP server, and integrated IDA Pro 9.x debugger plugin (`mepdbg.dll`).

## Features
- **Toshiba MeP C5 core & instruction decoder**: Full 16/32-bit MeP instruction decoding sorted by mask specificity, `Control` registers (`$pc`..`$r31`), `INTC` registers (`$ivb`, `$isr`, `$ier`, `$iet`, `$ilr0..3`), `ldcb`/`stcb` control-bus transfers, hardware `repeat`/`erepeat` loops, `sleep`/`halt`/`break`/`dbreak`/`swi`/`reti`/`dret`, and PS Vita F00D hardware reset defaults.
- **F00D MMIO peripherals**:
  - `0xE0000000`: `ARMComm` mailbox
  - `0xE0010000`: `e001device`
  - `0xE0020000`: Security gate / fuse slot `0x602` (`0x100..0x11F`)
  - `0xE0030000` & `0xE0058000`: `EEPROMProgrammer` & EEPROM keyring (`0x400` slots)
  - `0xE0040000`: `Math` bignum modular exponentiation (`PowMod`, 1..64 words)
  - `0xE0050000` / `0xE04E0000`: `Bigmac` DMAC5 crypto/DMA engine (memcpy, memset, AES-ECB/CBC/CTR encrypt+decrypt, SHA-1, SHA-256, HMAC-SHA1/SHA256, RNG)
  - `0xE3000000`: `IntcMmio` mirror of `$ivb`/`$isr`/`$ier`/`$iet`/`$ilr0..3`
- **Integrated IDA Pro Debugger (`mepdbg.dll`)**:
  - `PLUGIN_DBG | PLUGIN_MULTI` native plugin embedding `F00DMachine` directly inside IDA Pro — no external `gdbserver` process needed.
  - Auto-activates whenever the loaded database uses `toshiba-mep-ida` (`MeP`) or Python `mepf00d`.
  - Automatically loads all IDB segments into emulator RAM, resolves entry PC, supports execution breakpoints (`F2`), data read/write watchpoints, Step Into (`F7`), Step Over (`F8`), Continue (`F9`), Pause, Stop, all 56 GPR/CSR/INTC registers, and debugger CLI commands (`status`, `intc`, `irq <n>`, `reset`, `eeprom <path>`, `step [n]`).
- **Standalone CLI & GDB RSP Server (`mepulator.exe`)**:
  - Exposes 56-register XML target description, memory map XML, `Z0..Z4` breakpoints/watchpoints, and `monitor` (`qRcmd`) commands.

## Building (Windows / Visual Studio 2022)

1. Build `toshiba-mep-ida` processor module (`mep.dll`):
   ```powershell
   & "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\amd64\MSBuild.exe" `
     c:\Users\HomeUser\source\repos\ida-sdk-main\src\module\toshiba-mep-ida\mep.vcxproj `
     /p:Configuration=Release64 /p:Platform=x64
   ```
   Copy `mep.dll` into IDA's `procs\` directory.

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
   Copy `build\Release\mepdbg.dll` into IDA's `plugins\` directory.

## Usage in IDA Pro
1. Open a PS Vita F00D binary in IDA Pro with the `MeP` processor selected.
2. Select **Debugger -> Select debugger -> mepulator** (or press `F9` / Start Process).
3. IDA automatically maps all segments, breaks at the entry point, and shows `$0..$12/$tp/$gp/$sp/$pc`, all MeP control registers, and `INTC` registers.

## CLI & Standalone GDB Server
```powershell
# Run headless:
mepulator.exe --rom 1692_f00d.bin --base 0x00800000 --pc 0x00800100 --max-steps 10000

# Run GDB RSP server on port 1234:
mepulator.exe --rom 1692_f00d.bin --gdb --gdb-port 1234
```
