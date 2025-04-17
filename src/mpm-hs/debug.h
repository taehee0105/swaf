/* ERROR, WARNING, NOTICE, INFO, DEBUG 메시지 출력 헤더 */

#ifndef WAF_UTIL_LOG_H
#define WAF_UTIL_LOG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>

/*
 * Define minimal log levels similar to Suricata
 */
typedef enum {
    WAF_LOG_ERROR,
    WAF_LOG_WARNING,
    WAF_LOG_NOTICE,
    WAF_LOG_INFO,
    WAF_LOG_DEBUG
} WafLogLevel;

/*
 * Global log level for filtering log output
 */
#ifndef WAF_LOG_LEVEL
#define WAF_LOG_LEVEL WAF_LOG_DEBUG
#endif

/*
 * Internal logging implementation (do not use directly)
 */
static inline void WafLogInternal(WafLogLevel level, const char *file, const char *func, int line, const char *fmt, ...) {
    if (level > WAF_LOG_LEVEL)
        return;

    const char *level_str = NULL;
    switch (level) {
        case WAF_LOG_ERROR: level_str = "ERROR"; break;
        case WAF_LOG_WARNING: level_str = "WARNING"; break;
        case WAF_LOG_NOTICE: level_str = "NOTICE"; break;
        case WAF_LOG_INFO: level_str = "INFO"; break;
        case WAF_LOG_DEBUG: level_str = "DEBUG"; break;
        default: level_str = "UNKNOWN"; break;
    }

    fprintf(stderr, "[%s] %s:%d %s(): ", level_str, file, line, func);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

/*
 * Public logging macros
 */
#define SCLogError(...)   WafLogInternal(WAF_LOG_ERROR,   __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogWarning(...) WafLogInternal(WAF_LOG_WARNING, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogNotice(...)  WafLogInternal(WAF_LOG_NOTICE,  __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogInfo(...)    WafLogInternal(WAF_LOG_INFO,    __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogDebug(...)   WafLogInternal(WAF_LOG_DEBUG,   __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

/*
 * Fatal logging macro
 */
#define FatalError(...)           \
    do {                         \
        SCLogError(__VA_ARGS__); \
        exit(EXIT_FAILURE);      \
    } while (0)

#endif /* WAF_UTIL_LOG_H */

