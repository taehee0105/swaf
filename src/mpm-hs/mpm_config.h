/* Hyperscan MPM 엔진의 DB 캐시 경로 설정 헤더 */

#ifndef MPM_CONFIG_H
#define MPM_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/**
 * \brief MpmConfig - Hyperscan 기반 MPM에서 컴파일 시 사용되는 설정 구조체
 */
typedef struct MpmConfig_ {
    const char *cache_dir_path;  /* Hyperscan DB 캐시 파일 저장 경로 */
    int dummy;                   /* 필요 시 확장할 수 있는 더미 필드 */
} MpmConfig;

#endif /* MPM_CONFIG_H */

