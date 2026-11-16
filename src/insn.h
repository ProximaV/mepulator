#pragma once

#include <cstdint>

class Cpu;

struct insn_t {
    uint32_t sz;
    uint32_t mask;
    uint32_t match;
    void (*execute)(Cpu *cpu, uint32_t insn);
};

const insn_t *decode_insn(uint32_t raw);
uint32_t insn_table_size();
