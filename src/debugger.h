#pragma once

#include <atomic>
#include <cstdint>
#include <string>

class Cpu;
class F00DMachine;

class Debugger {
public:
    explicit Debugger(Cpu *cpu_, int port_ = 23946, F00DMachine *machine_ = nullptr);
    ~Debugger();

    Debugger(const Debugger &) = delete;
    Debugger &operator=(const Debugger &) = delete;

    // Start TCP listener and serve GDB clients until Stop() or client 'k'/'D' request.
    bool WaitForConnection();
    void Stop();
    int Port() const { return port; }

    // Single-packet dispatcher exposed for automated testing without sockets.
    // Sets should_continue_out if execution should enter Wait/Continue loop;
    // sets should_disconnect_out on 'k'/'D'.
    std::string ProcessPacket(const std::string &payload,
                              bool *should_disconnect_out = nullptr);

private:
    static std::string ToHexBytes(const uint8_t *data, size_t len);
    static std::string EncodeRegLE32(uint32_t val);
    static bool DecodeRegLE32(const std::string &hex, uint32_t *out);
    static std::string HexDecodeString(const std::string &hex);
    static std::string HexEncodeString(const std::string &text);
    static uint8_t Checksum(const std::string &payload);

    uint32_t ReadGdbReg(uint32_t idx) const;
    bool WriteGdbReg(uint32_t idx, uint32_t val);

    std::string BuildStopReply(const struct StopInfo &info) const;
    std::string BuildTargetXml() const;
    std::string BuildMemoryMapXml() const;
    std::string HandleXfer(const std::string &full_data, size_t offset, size_t length) const;
    std::string HandleMonitorCommand(const std::string &cmd);
    std::string HandleContinue(bool single_step);

    bool SendRaw(intptr_t sock, const std::string &data);
    bool SendPacket(intptr_t sock, const std::string &payload);
    bool RecvByte(intptr_t sock, uint8_t *out, int timeout_ms);
    bool ReadPacket(intptr_t sock, std::string *payload_out, bool *ctrl_c_out);

    Cpu *cpu = nullptr;
    F00DMachine *machine = nullptr;
    int port = 23946;
    bool no_ack_mode = false;
    bool resume_ignore_bpt = false;
    intptr_t active_client = -1;
    std::atomic<bool> stop_requested{false};
};
