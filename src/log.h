#pragma once

#include <stdio.h>
#include <stdlib.h>

using LogCallback = void(*)(const char *msg);
void set_log_callback(LogCallback cb);
void log_printf(const char *fmt, ...);
void log_dump_state();

#if defined(_MSC_VER)
#define MEP_FUNC __FUNCTION__
#else
#define MEP_FUNC __PRETTY_FUNCTION__
#endif

#define LOG(fmt, ...) \
	do { \
		log_printf("[mepulator] " fmt "\n", ##__VA_ARGS__); \
	} while (0)

#define LOG_WARN(fmt, ...) \
	do { \
		log_printf("[mepulator WARN] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
	} while (0)

#define LOG_ERR(fmt, ...) \
	do { \
		log_printf("[mepulator ERROR] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__); \
	} while (0)

#define FATAL(fmt, ...) \
	do { \
		log_printf("[mepulator FATAL] %s:%d (%s): " fmt, __FILE__, __LINE__, __FUNCTION__, ##__VA_ARGS__); \
		log_dump_state(); \
		exit(1); \
	} while (0)

#define TRACE(fmt, ...) \
	do { \
		log_printf("[mepulator] %s:%d: " fmt, MEP_FUNC, __LINE__, ##__VA_ARGS__); \
	} while (0)
