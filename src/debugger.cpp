#include "debugger.h"

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
using socklen_t = int;
static inline void CloseSock(intptr_t s) {
    if (s != -1) {
        closesocket(static_cast<SOCKET>(s));
    }
}
static inline intptr_t InvalidSock() { return static_cast<intptr_t>(INVALID_SOCKET); }
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
static inline void CloseSock(intptr_t s) {
    if (s >= 0) {
        close(static_cast<int>(s));
    }
}
static inline intptr_t InvalidSock() { return -1; }
#endif

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <vector>

#include "cpu.h"
#include "f00d_machine.h"
#include "log.h"

namespace {

#ifdef _WIN32
struct WinsockGuard {
    bool ok = false;
    WinsockGuard() {
        WSADATA wsa{};
        ok = (WSAStartup(MAKEWORD(2, 2), &wsa) == 0);
    }
    ~WinsockGuard() {
        if (ok) {
            WSACleanup();
        }
    }
};
#endif

inline uint8_t HexNibble(char c, bool *valid) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    *valid = false;
    return 0;
}

const char *const kGprNames[16] = {
    "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
    "r8", "r9", "r10", "r11", "r12", "tp", "gp", "sp"
};

const char *const kCsrNames[32] = {
    "pc", "lp", "sar", "csr3", "rpb", "rpe", "rpc", "hi",
    "lo", "csr9", "csr10", "csr11", "mb0", "me0", "mb1", "me1",
    "psw", "id", "tmp", "epc", "exc", "cfg", "vid", "npc",
    "dbg", "depc", "opt", "rcfg", "ccfg", "csr29", "csr30", "csr31"
};

const char *const kIntcNames[8] = {
    "ivb", "isr", "ier", "iet", "ilr0", "ilr1", "ilr2", "ilr3"
};

} // namespace

Debugger::Debugger(Cpu *cpu_, int port_, F00DMachine *machine_)
    : cpu(cpu_), machine(machine_), port(port_) {}

Debugger::~Debugger() {
    Stop();
}

void Debugger::Stop() {
    stop_requested.store(true);
}

std::string Debugger::ToHexBytes(const uint8_t *data, size_t len) {
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0xFu]);
        out.push_back(kHex[data[i] & 0xFu]);
    }
    return out;
}

std::string Debugger::EncodeRegLE32(uint32_t val) {
    uint8_t bytes[4] = {
        static_cast<uint8_t>(val & 0xFFu),
        static_cast<uint8_t>((val >> 8) & 0xFFu),
        static_cast<uint8_t>((val >> 16) & 0xFFu),
        static_cast<uint8_t>((val >> 24) & 0xFFu),
    };
    return ToHexBytes(bytes, 4);
}

bool Debugger::DecodeRegLE32(const std::string &hex, uint32_t *out) {
    if (hex.size() < 8) {
        return false;
    }
    bool valid = true;
    uint32_t v = 0;
    for (int i = 0; i < 4; ++i) {
        const uint8_t hi = HexNibble(hex[i * 2], &valid);
        const uint8_t lo = HexNibble(hex[i * 2 + 1], &valid);
        if (!valid) {
            return false;
        }
        v |= static_cast<uint32_t>((hi << 4) | lo) << (i * 8);
    }
    *out = v;
    return true;
}

std::string Debugger::HexDecodeString(const std::string &hex) {
    std::string out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        bool valid = true;
        uint8_t ch = static_cast<uint8_t>((HexNibble(hex[i], &valid) << 4) | HexNibble(hex[i + 1], &valid));
        if (!valid) break;
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

std::string Debugger::HexEncodeString(const std::string &text) {
    return ToHexBytes(reinterpret_cast<const uint8_t *>(text.data()), text.size());
}

uint8_t Debugger::Checksum(const std::string &payload) {
    uint8_t sum = 0;
    for (unsigned char c : payload) {
        sum = static_cast<uint8_t>(sum + c);
    }
    return sum;
}

uint32_t Debugger::ReadGdbReg(uint32_t idx) const {
    if (!cpu) return 0;
    if (idx < 16) return cpu->r[idx];
    if (idx < 48) return cpu->GetCR(idx - 16);
    if (idx < 56) return cpu->GetIntc(idx - 48);
    return 0;
}

bool Debugger::WriteGdbReg(uint32_t idx, uint32_t val) {
    if (!cpu) return false;
    if (idx < 16) {
        cpu->r[idx] = val;
        return true;
    }
    if (idx < 48) {
        cpu->SetCR(idx - 16, val, true);
        return true;
    }
    if (idx < 56) {
        cpu->SetIntc(idx - 48, val);
        return true;
    }
    return false;
}

std::string Debugger::BuildStopReply(const StopInfo &info) const {
    int sig = 5; // SIGTRAP
    std::string extra;
    char buf[64];

    switch (info.reason) {
    case StopReason::Watchpoint:
        sig = 5;
        std::snprintf(buf, sizeof(buf), "%s:%08x;", info.is_write ? "watch" : "rwatch", info.detail);
        extra = buf;
        break;
    case StopReason::UnmappedMemory:
        sig = 11; // SIGSEGV
        break;
    case StopReason::InvalidInsn:
        sig = 4; // SIGILL
        break;
    case StopReason::Breakpoint:
    case StopReason::BreakInsn:
    case StopReason::DbreakInsn:
    case StopReason::Halt:
    case StopReason::Swi:
    case StopReason::None:
        sig = 5;
        break;
    }

    std::snprintf(buf, sizeof(buf), "T%02xthread:01;%s", sig, extra.c_str());
    return std::string(buf);
}

std::string Debugger::BuildTargetXml() const {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\"?>\n"
        << "<!DOCTYPE target SYSTEM \"gdb-target.dtd\">\n"
        << "<target version=\"1.0\">\n"
        << "  <architecture>mep</architecture>\n"
        << "  <feature name=\"org.gnu.gdb.mep.core\">\n";
    for (int i = 0; i < 16; ++i) {
        oss << "    <reg name=\"" << kGprNames[i] << "\" bitsize=\"32\" regnum=\"" << i << "\"";
        if (i == 15) oss << " type=\"data_ptr\"";
        oss << "/>\n";
    }
    oss << "  </feature>\n"
        << "  <feature name=\"org.gnu.gdb.mep.csr\">\n";
    for (int i = 0; i < 32; ++i) {
        oss << "    <reg name=\"" << kCsrNames[i] << "\" bitsize=\"32\" regnum=\"" << (16 + i) << "\"";
        if (i == 0 || i == 1) oss << " type=\"code_ptr\"";
        oss << "/>\n";
    }
    oss << "  </feature>\n"
        << "  <feature name=\"org.vita.f00d.intc\">\n";
    for (int i = 0; i < 8; ++i) {
        oss << "    <reg name=\"" << kIntcNames[i] << "\" bitsize=\"32\" regnum=\"" << (48 + i) << "\"/>\n";
    }
    oss << "  </feature>\n"
        << "</target>\n";
    return oss.str();
}

std::string Debugger::BuildMemoryMapXml() const {
    std::ostringstream oss;
    oss << "<?xml version=\"1.0\"?>\n"
        << "<!DOCTYPE memory-map SYSTEM \"gdb-memory-map.dtd\">\n"
        << "<memory-map>\n";
    if (cpu) {
        for (const auto &reg : cpu->mem.GetRegions()) {
            const char *type = reg.is_device ? "rom" : "ram";
            char line[128];
            std::snprintf(line, sizeof(line),
                          "  <memory type=\"%s\" start=\"0x%x\" length=\"0x%x\"/>\n",
                          type, reg.start, reg.size);
            oss << line;
        }
    }
    oss << "</memory-map>\n";
    return oss.str();
}

std::string Debugger::HandleXfer(const std::string &full_data, size_t offset, size_t length) const {
    if (offset >= full_data.size()) {
        return "l";
    }
    const size_t avail = full_data.size() - offset;
    const size_t take = std::min(avail, length);
    const char prefix = (offset + take >= full_data.size()) ? 'l' : 'm';
    return std::string(1, prefix) + full_data.substr(offset, take);
}

std::string Debugger::HandleMonitorCommand(const std::string &cmd) {
    if (!cpu) return "E01";
    std::string trimmed = cmd;
    while (!trimmed.empty() && std::isspace(static_cast<unsigned char>(trimmed.back()))) {
        trimmed.pop_back();
    }
    size_t start = 0;
    while (start < trimmed.size() && std::isspace(static_cast<unsigned char>(trimmed[start]))) {
        ++start;
    }
    trimmed = trimmed.substr(start);

    if (trimmed == "status") {
        if (machine) {
            return HexEncodeString(machine->FormatStatus() + "\n");
        }
        char buf[128];
        std::snprintf(buf, sizeof(buf), "PC=0x%08x SP=0x%08x LP=0x%08x PSW=0x%08x\n",
                      cpu->control.pc, cpu->r[MEP_REG_sp], cpu->control.lp, cpu->GetCR(16));
        return HexEncodeString(buf);
    }

    if (trimmed == "reset") {
        if (machine) {
            machine->Reset(cpu->control.pc);
        } else {
            cpu->Reset(cpu->control.pc);
        }
        return HexEncodeString("Target reset.\n");
    }

    if (trimmed == "keyring" && machine) {
        std::ostringstream oss;
        uint8_t slot602[32] = {};
        machine->eeprom.GetKeySlot(0x602, slot602, sizeof(slot602));
        oss << "Keyslot 0x602: " << ToHexBytes(slot602, 32) << "\n";
        return HexEncodeString(oss.str());
    }

    std::string core_out;
    if (cpu->TryHandleCoreCommand(trimmed, &core_out)) {
        if (!core_out.empty() && core_out.back() != '\n') {
            core_out.push_back('\n');
        }
        return HexEncodeString(core_out);
    }

    return HexEncodeString(
        "Commands: status | intc | csr [name|idx] | timer | dsu | cb <hex> [val] | "
        "irq <0..31> | swi [0..3|mode <auto|arch|hle|trap>] | signal [mask] | "
        "applet [entry] [sp] | nmi | dint | reset | keyring\n");
}

std::string Debugger::HandleContinue(bool single_step) {
    if (!cpu) return "E01";

    if (single_step) {
        if (cpu->sleeping || cpu->halted) {
            cpu->sleeping = false;
            cpu->halted = false;
            cpu->control.psw &= ~kPswBitHalt;
        }
        StopInfo info = cpu->Step(true);
        resume_ignore_bpt = (info.reason == StopReason::Breakpoint);
        return BuildStopReply(info);
    }

    StopInfo info{};
    bool first = true;
    while (!stop_requested.load()) {
        // Check for async Ctrl-C (0x03) interrupt from client if connected
        if (active_client != InvalidSock()) {
            uint8_t b = 0;
            if (RecvByte(active_client, &b, 0) && b == 0x03) {
                info = StopInfo{StopReason::None, cpu->control.pc & ~1u, 0, false};
                return BuildStopReply(info);
            }
        }

        // Batch 1024 instructions between Ctrl-C checks for high throughput
        for (int batch = 0; batch < 1024; ++batch) {
            info = cpu->Step(first && resume_ignore_bpt);
            first = false;
            resume_ignore_bpt = false;
            if (info.reason != StopReason::None) {
                if (info.reason == StopReason::Breakpoint) {
                    resume_ignore_bpt = true;
                }
                return BuildStopReply(info);
            }
        }
    }

    info = StopInfo{StopReason::None, cpu->control.pc & ~1u, 0, false};
    return BuildStopReply(info);
}

std::string Debugger::ProcessPacket(const std::string &payload, bool *should_disconnect_out) {
    if (should_disconnect_out) {
        *should_disconnect_out = false;
    }
    if (payload.empty() || !cpu) {
        return "";
    }

    const char cmd = payload[0];

    switch (cmd) {
    case '?':
        return "T05thread:01;";

    case 'Q':
        if (payload == "QStartNoAckMode") {
            no_ack_mode = true;
            return "OK";
        }
        return "";

    case 'q': {
        if (payload.rfind("qSupported", 0) == 0) {
            return "PacketSize=4096;qXfer:features:read+;qXfer:memory-map:read+;QStartNoAckMode+;hwbreak+;swbreak+";
        }
        if (payload == "qC") {
            return "QC01";
        }
        if (payload == "qfThreadInfo") {
            return "m1";
        }
        if (payload == "qsThreadInfo") {
            return "l";
        }
        if (payload == "qAttached") {
            return "1";
        }
        if (payload == "qOffsets") {
            return "Text=0;Data=0;Bss=0";
        }
        if (payload.rfind("qXfer:features:read:target.xml:", 0) == 0) {
            size_t off = 0, len = 4096;
            const std::string args = payload.substr(std::strlen("qXfer:features:read:target.xml:"));
            const size_t comma = args.find(',');
            if (comma != std::string::npos) {
                off = std::strtoul(args.substr(0, comma).c_str(), nullptr, 16);
                len = std::strtoul(args.substr(comma + 1).c_str(), nullptr, 16);
            }
            return HandleXfer(BuildTargetXml(), off, len);
        }
        if (payload.rfind("qXfer:memory-map:read::", 0) == 0) {
            size_t off = 0, len = 4096;
            const std::string args = payload.substr(std::strlen("qXfer:memory-map:read::"));
            const size_t comma = args.find(',');
            if (comma != std::string::npos) {
                off = std::strtoul(args.substr(0, comma).c_str(), nullptr, 16);
                len = std::strtoul(args.substr(comma + 1).c_str(), nullptr, 16);
            }
            return HandleXfer(BuildMemoryMapXml(), off, len);
        }
        if (payload.rfind("qRcmd,", 0) == 0) {
            return HandleMonitorCommand(HexDecodeString(payload.substr(6)));
        }
        return "";
    }

    case 'H':
    case 'T':
        return "OK";

    case 'g': {
        std::string out;
        out.reserve(56 * 8);
        for (uint32_t i = 0; i < 56; ++i) {
            out += EncodeRegLE32(ReadGdbReg(i));
        }
        return out;
    }

    case 'G': {
        const std::string hex = payload.substr(1);
        const size_t count = std::min<size_t>(56, hex.size() / 8);
        for (size_t i = 0; i < count; ++i) {
            uint32_t val = 0;
            if (!DecodeRegLE32(hex.substr(i * 8, 8), &val)) {
                return "E01";
            }
            WriteGdbReg(static_cast<uint32_t>(i), val);
        }
        return "OK";
    }

    case 'p': {
        const uint32_t regno = static_cast<uint32_t>(std::strtoul(payload.c_str() + 1, nullptr, 16));
        if (regno >= 56) {
            return "xxxxxxxx";
        }
        return EncodeRegLE32(ReadGdbReg(regno));
    }

    case 'P': {
        const size_t eq = payload.find('=');
        if (eq == std::string::npos) return "E01";
        const uint32_t regno = static_cast<uint32_t>(std::strtoul(payload.substr(1, eq - 1).c_str(), nullptr, 16));
        uint32_t val = 0;
        if (!DecodeRegLE32(payload.substr(eq + 1), &val)) {
            return "E01";
        }
        return WriteGdbReg(regno, val) ? "OK" : "E01";
    }

    case 'm': {
        const size_t comma = payload.find(',');
        if (comma == std::string::npos) return "E01";
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(1, comma - 1).c_str(), nullptr, 16));
        const uint32_t len = static_cast<uint32_t>(std::strtoul(payload.substr(comma + 1).c_str(), nullptr, 16));
        if (len == 0) return "";
        if (len > 0x10000u) return "E01";
        std::vector<uint8_t> buf(len, 0);
        if (!cpu->mem.TryRead(addr, len, buf.data(), false)) {
            return "E0E";
        }
        return ToHexBytes(buf.data(), len);
    }

    case 'M': {
        const size_t comma = payload.find(',');
        const size_t colon = payload.find(':');
        if (comma == std::string::npos || colon == std::string::npos || colon < comma) {
            return "E01";
        }
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(1, comma - 1).c_str(), nullptr, 16));
        const uint32_t len = static_cast<uint32_t>(std::strtoul(payload.substr(comma + 1, colon - comma - 1).c_str(), nullptr, 16));
        const std::string hex = payload.substr(colon + 1);
        if (hex.size() < static_cast<size_t>(len) * 2) {
            return "E01";
        }
        std::vector<uint8_t> buf(len);
        for (uint32_t i = 0; i < len; ++i) {
            bool valid = true;
            buf[i] = static_cast<uint8_t>((HexNibble(hex[i * 2], &valid) << 4) | HexNibble(hex[i * 2 + 1], &valid));
            if (!valid) return "E01";
        }
        if (len > 0 && !cpu->mem.TryWrite(addr, len, buf.data(), false)) {
            return "E0E";
        }
        return "OK";
    }

    case 'X': {
        const size_t comma = payload.find(',');
        const size_t colon = payload.find(':');
        if (comma == std::string::npos || colon == std::string::npos || colon < comma) {
            return "E01";
        }
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(1, comma - 1).c_str(), nullptr, 16));
        const uint32_t len = static_cast<uint32_t>(std::strtoul(payload.substr(comma + 1, colon - comma - 1).c_str(), nullptr, 16));
        const std::string &raw = payload.substr(colon + 1);
        if (raw.size() < len) return "E01";
        if (len > 0 && !cpu->mem.TryWrite(addr, len, raw.data(), false)) {
            return "E0E";
        }
        return "OK";
    }

    case 'Z':
    case 'z': {
        if (payload.size() < 3) return "E01";
        const int type = payload[1] - '0';
        const size_t c1 = payload.find(',', 2);
        const size_t c2 = (c1 != std::string::npos) ? payload.find(',', c1 + 1) : std::string::npos;
        if (c1 == std::string::npos || c2 == std::string::npos) return "E01";
        const uint32_t addr = static_cast<uint32_t>(std::strtoul(payload.substr(c1 + 1, c2 - c1 - 1).c_str(), nullptr, 16));
        const uint32_t len = static_cast<uint32_t>(std::strtoul(payload.substr(c2 + 1).c_str(), nullptr, 16));
        const bool add = (cmd == 'Z');

        if (type == 0 || type == 1) {
            if (add) cpu->AddBreakpoint(addr);
            else cpu->RemoveBreakpoint(addr);
            return "OK";
        }
        if (type >= 2 && type <= 4) {
            int wp_mask = 0;
            if (type == 2) wp_mask = 1;      // write
            else if (type == 3) wp_mask = 2; // read
            else wp_mask = 3;                // access (r/w)
            const uint32_t wp_sz = (len == 0) ? 4u : len;
            if (add) cpu->mem.AddWatchpoint(addr, wp_sz, wp_mask);
            else cpu->mem.RemoveWatchpoint(addr, wp_sz, wp_mask);
            return "OK";
        }
        return "";
    }

    case 's': {
        if (payload.size() > 1) {
            const uint32_t new_pc = static_cast<uint32_t>(std::strtoul(payload.c_str() + 1, nullptr, 16));
            cpu->control.pc = new_pc & ~1u;
        }
        return HandleContinue(true);
    }

    case 'c': {
        if (payload.size() > 1) {
            const uint32_t new_pc = static_cast<uint32_t>(std::strtoul(payload.c_str() + 1, nullptr, 16));
            cpu->control.pc = new_pc & ~1u;
        }
        return HandleContinue(false);
    }

    case 'v': {
        if (payload == "vCont?") {
            return "vCont;c;C;s;S;t";
        }
        if (payload.rfind("vCont;", 0) == 0) {
            const char action = (payload.size() > 6) ? payload[6] : 'c';
            if (action == 's' || action == 'S') {
                return HandleContinue(true);
            }
            if (action == 'c' || action == 'C') {
                return HandleContinue(false);
            }
            if (action == 't') {
                return "OK";
            }
        }
        return "";
    }

    case 'D':
    case 'k':
        if (should_disconnect_out) {
            *should_disconnect_out = true;
        }
        return "OK";

    default:
        return "";
    }
}

bool Debugger::SendRaw(intptr_t sock, const std::string &data) {
    size_t sent = 0;
    while (sent < data.size()) {
#ifdef _WIN32
        const int rc = send(static_cast<SOCKET>(sock), data.data() + sent, static_cast<int>(data.size() - sent), 0);
#else
        const ssize_t rc = send(static_cast<int>(sock), data.data() + sent, data.size() - sent, 0);
#endif
        if (rc <= 0) {
            return false;
        }
        sent += static_cast<size_t>(rc);
    }
    return true;
}

bool Debugger::SendPacket(intptr_t sock, const std::string &payload) {
    char csum[8];
    std::snprintf(csum, sizeof(csum), "#%02x", Checksum(payload));
    const std::string frame = "$" + payload + csum;
    return SendRaw(sock, frame);
}

bool Debugger::RecvByte(intptr_t sock, uint8_t *out, int timeout_ms) {
    fd_set rfds;
    FD_ZERO(&rfds);
#ifdef _WIN32
    FD_SET(static_cast<SOCKET>(sock), &rfds);
#else
    FD_SET(static_cast<int>(sock), &rfds);
#endif
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    const int nfds = static_cast<int>(sock) + 1;
    const int ready = select(nfds, &rfds, nullptr, nullptr, &tv);
    if (ready <= 0) {
        return false;
    }
    char ch = 0;
#ifdef _WIN32
    const int n = recv(static_cast<SOCKET>(sock), &ch, 1, 0);
#else
    const ssize_t n = recv(static_cast<int>(sock), &ch, 1, 0);
#endif
    if (n <= 0) {
        return false;
    }
    *out = static_cast<uint8_t>(ch);
    return true;
}

bool Debugger::ReadPacket(intptr_t sock, std::string *payload_out, bool *ctrl_c_out) {
    *ctrl_c_out = false;
    payload_out->clear();

    uint8_t b = 0;
    while (!stop_requested.load()) {
        if (!RecvByte(sock, &b, 1000)) {
            // Distinguish disconnect from idle timeout
            char peek_buf = 0;
#ifdef _WIN32
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(static_cast<SOCKET>(sock), &rfds);
            timeval tv{0, 0};
            if (select(0, &rfds, nullptr, nullptr, &tv) > 0 &&
                recv(static_cast<SOCKET>(sock), &peek_buf, 1, MSG_PEEK) <= 0) {
                return false;
            }
#else
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(static_cast<int>(sock), &rfds);
            timeval tv{0, 0};
            if (select(static_cast<int>(sock) + 1, &rfds, nullptr, nullptr, &tv) > 0 &&
                recv(static_cast<int>(sock), &peek_buf, 1, MSG_PEEK) <= 0) {
                return false;
            }
#endif
            continue;
        }
        if (b == 0x03) {
            *ctrl_c_out = true;
            return true;
        }
        if (b == '$') {
            break;
        }
    }

    if (stop_requested.load()) {
        return false;
    }

    std::string body;
    bool escaped = false;
    while (!stop_requested.load()) {
        if (!RecvByte(sock, &b, 5000)) {
            return false;
        }
        if (escaped) {
            body.push_back(static_cast<char>(b ^ 0x20u));
            escaped = false;
            continue;
        }
        if (b == '}') {
            escaped = true;
            continue;
        }
        if (b == '#') {
            break;
        }
        body.push_back(static_cast<char>(b));
    }

    uint8_t c1 = 0, c2 = 0;
    if (!RecvByte(sock, &c1, 5000) || !RecvByte(sock, &c2, 5000)) {
        return false;
    }

    bool valid = true;
    const uint8_t expected = static_cast<uint8_t>((HexNibble(static_cast<char>(c1), &valid) << 4) |
                                                   HexNibble(static_cast<char>(c2), &valid));
    const uint8_t actual = Checksum(body);
    if (!no_ack_mode) {
        SendRaw(sock, (valid && expected == actual) ? "+" : "-");
    }
    if (!valid || expected != actual) {
        LOG_WARN("GDB RSP checksum mismatch: expected 0x%02x got 0x%02x", expected, actual);
        payload_out->clear();
        return true;
    }

    *payload_out = std::move(body);
    return true;
}

bool Debugger::WaitForConnection() {
#ifdef _WIN32
    WinsockGuard wsa_guard;
    if (!wsa_guard.ok) {
        LOG_ERR("WSAStartup failed");
        return false;
    }
#endif

    intptr_t listen_sock = static_cast<intptr_t>(socket(AF_INET, SOCK_STREAM, 0));
    if (listen_sock == InvalidSock()) {
        LOG_ERR("GDB socket() failed");
        return false;
    }

    int opt = 1;
#ifdef _WIN32
    setsockopt(static_cast<SOCKET>(listen_sock), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&opt), sizeof(opt));
#else
    setsockopt(static_cast<int>(listen_sock), SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(static_cast<uint16_t>(port));

    if (bind(
#ifdef _WIN32
            static_cast<SOCKET>(listen_sock),
#else
            static_cast<int>(listen_sock),
#endif
            reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) != 0) {
        LOG_ERR("GDB bind(port=%d) failed", port);
        CloseSock(listen_sock);
        return false;
    }

    if (listen(
#ifdef _WIN32
            static_cast<SOCKET>(listen_sock),
#else
            static_cast<int>(listen_sock),
#endif
            1) != 0) {
        LOG_ERR("GDB listen(port=%d) failed", port);
        CloseSock(listen_sock);
        return false;
    }

    LOG("GDB server listening on 127.0.0.1:%d", port);

    while (!stop_requested.load()) {
        fd_set rfds;
        FD_ZERO(&rfds);
#ifdef _WIN32
        FD_SET(static_cast<SOCKET>(listen_sock), &rfds);
#else
        FD_SET(static_cast<int>(listen_sock), &rfds);
#endif
        timeval tv{0, 250000};
        const int ready = select(static_cast<int>(listen_sock) + 1, &rfds, nullptr, nullptr, &tv);
        if (ready <= 0) {
            continue;
        }

        sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        intptr_t client = static_cast<intptr_t>(accept(
#ifdef _WIN32
            static_cast<SOCKET>(listen_sock),
#else
            static_cast<int>(listen_sock),
#endif
            reinterpret_cast<sockaddr *>(&client_addr), &client_len));
        if (client == InvalidSock()) {
            continue;
        }

        int nodelay = 1;
#ifdef _WIN32
        setsockopt(static_cast<SOCKET>(client), IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<const char *>(&nodelay), sizeof(nodelay));
#else
        setsockopt(static_cast<int>(client), IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
#endif

        LOG("GDB client connected");
        no_ack_mode = false;
        active_client = client;

        while (!stop_requested.load()) {
            std::string payload;
            bool ctrl_c = false;
            if (!ReadPacket(client, &payload, &ctrl_c)) {
                break;
            }
            if (ctrl_c) {
                SendPacket(client, "T05thread:01;");
                continue;
            }
            if (payload.empty()) {
                continue;
            }

            bool disconnect = false;
            const std::string reply = ProcessPacket(payload, &disconnect);
            if (!SendPacket(client, reply)) {
                break;
            }
            if (disconnect) {
                break;
            }
        }

        active_client = InvalidSock();
        CloseSock(client);
        LOG("GDB client disconnected");
        break;
    }

    CloseSock(listen_sock);
    return true;
}
