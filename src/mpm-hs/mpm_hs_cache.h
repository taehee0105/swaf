/* hs db 컴파일 결과 디스크에 저장 및 불러오기 헤더 */

#ifndef SWAF_MPM_HS_CACHE_H
#define SWAF_MPM_HS_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <hs.h>

#include "debug.h"
#include "hash_lookup3.h"
#include "hash_table.h"
#include "mem.h"
#include "mpm_hs_core.h"
#include "path.h"

/**
 * Hyperscan DB 캐시 저장용 반복자 구조체
 * - PatternDatabase 목록을 순회하며 캐시 저장 시 사용
 */
typedef struct HsIteratorData {
    PatternDatabaseCache *pd_stats;  // 캐시 저장 통계 구조체
    const char *cache_path;          // 캐시 파일 경로
} HsIteratorData;

/**
 * 디스크에서 Hyperscan DB를 불러옴
 *
 * @param hs_db        역직렬화된 Hyperscan DB 포인터
 * @param hs_db_hash   PatternDatabase를 식별하는 고유 해시값
 * @param dirpath      캐시 파일이 위치한 디렉토리 경로
 * @return             성공 시 0, 실패 시 -1
 */
int HSLoadCache(hs_database_t **hs_db, uint64_t hs_db_hash, const char *dirpath);

/**
 * PatternDatabase 구조체로부터 64비트 해시값 계산
 * - 캐시 파일명을 결정할 때 사용
 */
uint64_t HSHashDb(const PatternDatabase *pd);

/**
 * Hyperscan DB를 디스크에 저장하는 반복자 함수
 * - HashTableIterate 등 반복 구조에서 콜백으로 사용
 */
void HSSaveCacheIterator(void *data, void *aux);

#endif /* SWAF_MPM_HS_CACHE_H */