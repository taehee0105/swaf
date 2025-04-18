/**
 * Hyperscan MPM 엔진의 DB 캐시 경로 설정 헤더 
 * cache_dir_path 설정값을 Hyperscan 엔진 초기화 시 전달만 해줌
 * SoC(관심사 분리) 원칙을 위한 헤더
 */

#ifndef SWAF_MPM_CONFIG_H
#define SWAF_MPM_CONFIG_H

#include <stdint.h>
#include <stdbool.h>

/**
 * @brief MpmConfig - Hyperscan 기반 MPM에서 컴파일 시 사용되는 설정 구조체
 */
typedef struct MpmConfig_ {
    const char *cache_dir_path;  /* Hyperscan DB 캐시 파일 저장 경로 */
    int dummy;                   /* 필요 시 확장할 수 있는 더미 필드 */
} MpmConfig;

#endif /* SWAF_MPM_CONFIG_H */