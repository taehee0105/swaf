#include <hs.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>

#include "util-mpm-hs-core.h"  /* Hyperscan MPM을 위한 사용자 정의 core 헤더 */

/* 메이저, 마이너, 패치 버전을 하나의 32비트 정수로 인코딩 */
#define HS_VERSION_ENCODE(major, minor, patch) (((major) << 24) | ((minor) << 16) | ((patch) << 8))
#define HS_VERSION_AT_LEAST(major, minor, patch) \
    (HS_VERSION_32BIT >= HS_VERSION_ENCODE(major, minor, patch))

/**
 * Hyperscan 오류 코드를 사람이 읽을 수 있는 문자열로 변환
 *
 * @param error_code Hyperscan 함수에서 반환된 오류 코드
 * @return 해당 오류 코드에 대응하는 설명 문자열
 */
const char *HSErrorToStr(hs_error_t error_code)
{
    switch (error_code) {
        case HS_SUCCESS:
            return "HS_SUCCESS: The engine completed normally";
        case HS_INVALID:
            return "HS_INVALID: A parameter passed to this function was invalid";
        case HS_NOMEM:
            return "HS_NOMEM: A memory allocation failed";
        case HS_SCAN_TERMINATED:
            return "HS_SCAN_TERMINATED: The engine was terminated by callback";
        case HS_COMPILER_ERROR:
            return "HS_COMPILER_ERROR: The pattern compiler failed";
        case HS_DB_VERSION_ERROR:
            return "HS_DB_VERSION_ERROR: The given database was built for a different version of Hyperscan";
        case HS_DB_PLATFORM_ERROR:
            return "HS_DB_PLATFORM_ERROR: The given database was built for a different platform (i.e., CPU type)";
        case HS_DB_MODE_ERROR:
            return "HS_DB_MODE_ERROR: The given database was built for a different mode of operation";
        case HS_BAD_ALIGN:
            return "HS_BAD_ALIGN: A parameter passed to this function was not correctly aligned";
        case HS_BAD_ALLOC:
            return "HS_BAD_ALLOC: The memory allocator did not return correctly aligned memory";
        case HS_SCRATCH_IN_USE:
            return "HS_SCRATCH_IN_USE: The scratch region was already in use";
#if HS_VERSION_AT_LEAST(4, 4, 0)
        case HS_ARCH_ERROR:
            return "HS_ARCH_ERROR: Unsupported CPU architecture";
#endif
#if HS_VERSION_AT_LEAST(4, 6, 0)
        case HS_INSUFFICIENT_SPACE:
            return "HS_INSUFFICIENT_SPACE: Provided buffer was too small";
#endif
#if HS_VERSION_AT_LEAST(5, 1, 1)
        case HS_UNKNOWN_ERROR:
            return "HS_UNKNOWN_ERROR: Unexpected internal error";
#endif
        default:
            return "Unknown Hyperscan error code";
    }
}
