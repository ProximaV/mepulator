#include "log.h"

#include <stdarg.h>
#include "cpu.h"

extern Cpu *g_cpu;
static LogCallback g_log_cb = nullptr;

void set_log_callback(LogCallback cb) {
	g_log_cb = cb;
}

void log_printf(const char *fmt, ...) {
	char buf[2048];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (g_log_cb) {
		g_log_cb(buf);
	} else {
		fputs(buf, stdout);
	}
}

void log_dump_state() {
	if (g_cpu) {
		log_printf("CPU state at the moment of error:\n");
		log_printf("  pc=0x%08x sp=0x%08x lp=0x%08x psw=0x%08x\n",
		           g_cpu->control.pc, g_cpu->r[MEP_REG_sp],
		           g_cpu->control.lp, g_cpu->control.psw);
		log_printf("  r0=0x%08x r1=0x%08x r2=0x%08x r3=0x%08x\n",
		           g_cpu->r[0], g_cpu->r[1], g_cpu->r[2], g_cpu->r[3]);
	}
}
