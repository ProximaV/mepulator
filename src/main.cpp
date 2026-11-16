#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include "arm.h"
#include "cpu.h"
#include "debugger.h"
#include "f00d_machine.h"
#include "log.h"

namespace {

void PrintUsage(const char *prog) {
    std::printf(
        "Usage: %s [options]\n"
        "Options:\n"
        "  --rom <path>       ROM/firmware binary to load (default: 1692_f00d.bin)\n"
        "  --base <addr>      Load address in MeP memory (default: 0x00800000)\n"
        "  --pc <addr>        Initial program counter (default: 0x00800000)\n"
        "  --sp <addr>        Initial stack pointer (default: 0x00040000)\n"
        "  --eeprom <path>    EEPROM image to load (default: 1692_eeprom.bin)\n"
        "  --gdb, -g          Start GDB RSP server and wait for debugger\n"
        "  --gdb-port <port>  GDB RSP TCP port (default: 1234, implies --gdb)\n"
        "  --headless         Run directly without GDB server (default)\n"
        "  --max-steps <n>    Maximum instructions in headless mode (0 = unlimited)\n"
        "  --with-arm-test    Start simulated ARM mailbox responder thread\n"
        "  --help, -h         Show this help message\n",
        prog ? prog : "mepulator");
}

bool FileExists(const char *path) {
    if (!path || !*path) {
        return false;
    }
    std::FILE *fp = std::fopen(path, "rb");
    if (!fp) {
        return false;
    }
    std::fclose(fp);
    return true;
}

const char *StopReasonName(StopReason r) {
    switch (r) {
    case StopReason::None: return "None (max-steps reached)";
    case StopReason::Breakpoint: return "Breakpoint";
    case StopReason::Watchpoint: return "Watchpoint";
    case StopReason::BreakInsn: return "BreakInsn";
    case StopReason::DbreakInsn: return "DbreakInsn";
    case StopReason::Halt: return "Halt";
    case StopReason::Swi: return "Swi";
    case StopReason::UnmappedMemory: return "UnmappedMemory";
    case StopReason::InvalidInsn: return "InvalidInsn";
    }
    return "Unknown";
}

}  // namespace

int main(int argc, char *argv[]) {
    std::setvbuf(stdout, nullptr, _IONBF, 0);

    std::string rom_path = "1692_f00d.bin";
    bool rom_explicit = false;
    std::string eeprom_path = "1692_eeprom.bin";
    bool eeprom_explicit = false;
    uint32_t base_addr = 0x00800000u;
    uint32_t entry_pc = 0x00800000u;
    bool pc_explicit = false;
    uint32_t init_sp = 0x00040000u;
    bool use_gdb = false;
    bool force_headless = false;
    int gdb_port = 1234;
    uint64_t max_steps = 0;
    bool with_arm_test = false;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (std::strcmp(arg, "--help") == 0 || std::strcmp(arg, "-h") == 0) {
            PrintUsage(argv[0]);
            return 0;
        } else if (std::strcmp(arg, "--rom") == 0 && i + 1 < argc) {
            rom_path = argv[++i];
            rom_explicit = true;
        } else if (std::strcmp(arg, "--base") == 0 && i + 1 < argc) {
            base_addr = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
            if (!pc_explicit) {
                entry_pc = base_addr;
            }
        } else if (std::strcmp(arg, "--pc") == 0 && i + 1 < argc) {
            entry_pc = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
            pc_explicit = true;
        } else if (std::strcmp(arg, "--sp") == 0 && i + 1 < argc) {
            init_sp = static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
        } else if (std::strcmp(arg, "--eeprom") == 0 && i + 1 < argc) {
            eeprom_path = argv[++i];
            eeprom_explicit = true;
        } else if (std::strcmp(arg, "--gdb") == 0 || std::strcmp(arg, "-g") == 0) {
            use_gdb = true;
        } else if (std::strcmp(arg, "--gdb-port") == 0 && i + 1 < argc) {
            gdb_port = std::atoi(argv[++i]);
            use_gdb = true;
        } else if (std::strcmp(arg, "--headless") == 0) {
            force_headless = true;
            use_gdb = false;
        } else if (std::strcmp(arg, "--max-steps") == 0 && i + 1 < argc) {
            max_steps = std::strtoull(argv[++i], nullptr, 0);
        } else if (std::strcmp(arg, "--with-arm-test") == 0) {
            with_arm_test = true;
        } else {
            std::fprintf(stderr, "Unknown or incomplete option: %s\n", arg);
            PrintUsage(argv[0]);
            return 1;
        }
    }

    F00DMachine machine;
    machine.Reset(entry_pc, true, true);
    machine.cpu.r[MEP_REG_sp] = init_sp;

    if (eeprom_explicit || FileExists(eeprom_path.c_str())) {
        if (!machine.LoadEepromFile(eeprom_path.c_str()) && eeprom_explicit) {
            std::fprintf(stderr, "Failed to load EEPROM image: %s\n", eeprom_path.c_str());
            return 1;
        }
    }

    if (rom_explicit || FileExists(rom_path.c_str())) {
        if (!machine.LoadBinaryFile(base_addr, rom_path.c_str(), "ROM")) {
            std::fprintf(stderr, "Failed to load ROM image: %s\n", rom_path.c_str());
            return 1;
        }
    } else if (!use_gdb) {
        std::fprintf(stderr, "No ROM found (%s). Specify --rom <path> or --gdb.\n", rom_path.c_str());
        return 1;
    }

    if (with_arm_test) {
        ARM *arm = new ARM(&machine.armcomm, &machine.cpu.mem);
        std::thread arm_thread(&ARM::Loop, arm);
        arm_thread.detach();
    }

    if (use_gdb && !force_headless) {
        Debugger dbg(&machine.cpu, gdb_port, &machine);
        if (!dbg.WaitForConnection()) {
            std::fprintf(stderr, "GDB server failed on port %d\n", gdb_port);
            return 1;
        }
        return 0;
    }

    const StopInfo stop = machine.RunSteps(max_steps);
    std::printf("Stopped: %s at PC=0x%08X (detail=0x%08X)\n%s\n",
                StopReasonName(stop.reason), stop.pc, stop.detail,
                machine.FormatStatus().c_str());
    return 0;
}
