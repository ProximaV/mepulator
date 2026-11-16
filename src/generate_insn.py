#!/usr/bin/env python3

import sys


def generate_mask(s):
	o = ""
	s = s.replace("_", "")
	if len(s) != 16:
		raise Exception("halfword pattern must be 16 bits, got {} in '{}'".format(len(s), s))
	for c in s:
		if c == '0' or c == '1':
			o += '1'
		else:
			o += '0'
	return int(o, 2)


def generate_match(s):
	o = ""
	s = s.replace("_", "")
	for c in s:
		if c == '0' or c == '1':
			o += c
		else:
			o += '0'
	return int(o, 2)


def find_bits(s):
	bit_start = dict()
	bit_end = dict()
	cur = None
	s += '0' # for case when s ends with bits
	for x, c in enumerate(s):
		if cur == c:
			continue

		if cur and cur not in ['0', '1']:
			bit_end[cur] = x
		cur = c
		if cur in bit_start:
			raise Exception("non-continuous bit in {}".format(s))
		if cur not in ['0', '1']:
			bit_start[cur] = x

	out = [] # out is (bit, start, len)
	for bit in bit_start:
		out.append((bit, bit_start[bit], bit_end[bit] - bit_start[bit]))

	return out


def main():
	with open(sys.argv[1], "r") as fin:
		data = fin.read().replace("\r\n", "\n").strip()
	descs = [d.strip() for d in data.split("\n\n\n") if d.strip()]
	entries = []
	seen_patterns = {}
	for idx, desc in enumerate(descs):
		desc = desc.split("\n")
		code = desc[0].strip().split()
		if len(code) not in (1, 2):
			raise Exception("expected 1 or 2 halfwords, got: {}".format(desc[0]))

		# match across both halfwords (little-endian: hw0 in bits 15:0, hw1 in bits 31:16)
		mask = generate_mask(code[0])
		match = generate_match(code[0])
		if len(code) == 2:
			mask |= generate_mask(code[1]) << 16
			match |= generate_match(code[1]) << 16

		if (mask, match) in seen_patterns:
			raise Exception("duplicate opcode pattern mask=0x{:08x} match=0x{:08x}: {} vs {}".format(
				mask, match, seen_patterns[(mask, match)], desc))
		seen_patterns[(mask, match)] = desc[0]

		# bits decode
		flat_code = "".join([s[::-1] for s in code]).replace("_", "")
		bits = find_bits(flat_code)
		decode_bits = ""
		for bit, start, sz in bits:
			decode_bits += "\tuint32_t {} = GetBits(insn, {}, {});\n".format(bit, start, sz)

		# vars
		x = 0
		get_vars = ""
		for line in desc[1:]:
			x += 1
			if "{" in line:
				break
			line = line.strip().replace(" ", "").replace("_", "")
			if not line:
				continue
			var_name, stmt = line.split("=")
			parts = stmt.split("||")[::-1]
			off = 0
			out = []
			for part in parts:
				if part[0] in ['0', '1']:
					var = "0b{}".format(part)
				else:
					var = part[0]
				out.append("(static_cast<uint32_t>({}) << {})".format(var, off))
				off += len(part)
			get_vars += "\tuint32_t {} = {};\n".format(var_name, " | ".join(out))

		# body
		func_name = "i_" + desc[x].split(" {")[0].strip()
		func_body = ""
		for line in desc[x + 1:]:
			if line.rstrip() == "}":
				break
			func_body += line + "\n"

		sz = len(flat_code) // 8
		specificity = bin(mask).count("1")
		entries.append((specificity, sz, idx, mask, match, func_name, decode_bits, get_vars, func_body))

	# Sort by most specific mask first so narrower encodings always match before broader ones.
	entries.sort(key=lambda e: (-e[0], -e[1], e[2]))

	gen = ""
	table = ""
	for _, sz, _, mask, match, func_name, decode_bits, get_vars, func_body in entries:
		table += "\t{{ {}, 0x{:08X}u, 0x{:08X}u, {} }},\n".format(sz, mask, match, func_name)
		gen += "INSN({}) {{\n".format(func_name)
		gen += "(void)cpu;\n(void)insn;\n"
		gen += decode_bits
		gen += get_vars
		gen += func_body
		gen += "}\n\n"

	with open(sys.argv[2], "w") as fout:
		fout.write(gen + "\n")
		fout.write("insn_t insn_table[] = {\n" + table + "};\n")


if __name__ == "__main__":
	main()
