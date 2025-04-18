/* ERROR, WARNING, NOTICE, INFO, DEBUG 로그 출력 헤더 */

#ifndef SWAF_DEBUG_H
#define SWAF_DEBUG_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>

/* 기존 수리카타에서 최소화해 가져옴 */
typedef enum {
    WAF_LOG_ERROR,
    WAF_LOG_WARNING,
    WAF_LOG_NOTICE,
    WAF_LOG_INFO,
    WAF_LOG_DEBUG
} WafLogLevel;

/**
 * 우선순위가 가장 낮은 WAF_LOG_DEBUG를 기본값으로 사용 
 * 출력시키고 싶은 로그에 따라 변경
 */
#ifndef SWAF_LOG_LEVEL
#define SWAF_LOG_LEVEL WAF_LOG_DEBUG
#endif

/**
 * @brief 로깅 구현 함수
 * (매크로를 이용해 사용)
 */
static inline void WafLogInternal(WafLogLevel level, const char *file, const char *func, int line, const char *fmt, ...) {
    if (level > SWAF_LOG_LEVEL)
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

    /* 가변 인자 설정 */
    va_list args;
    va_start(args, fmt);
    /* fmt(문자열)과 ... 조합 */
    vfprintf(stderr, fmt, args);
    va_end(args);

    fprintf(stderr, "\n");
}

/* 로깅 매크로 */
#define SCLogError(...)   WafLogInternal(WAF_LOG_ERROR,   __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogWarning(...) WafLogInternal(WAF_LOG_WARNING, __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogNotice(...)  WafLogInternal(WAF_LOG_NOTICE,  __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogInfo(...)    WafLogInternal(WAF_LOG_INFO,    __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)
#define SCLogDebug(...)   WafLogInternal(WAF_LOG_DEBUG,   __FILE__, __FUNCTION__, __LINE__, __VA_ARGS__)

/* Fatal 로깅 매크로 */
#define FatalError(...)           \
    do {                         \
        SCLogError(__VA_ARGS__); \
        exit(EXIT_FAILURE);      \
    } while (0)

#endif /* SWAF_DEBUG_H */