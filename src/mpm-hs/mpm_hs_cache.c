/* hs db 컴파일 결과 디스크에 저장 및 불러오기 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <hs.h>

#include "debug.h"
#include "hash_lookup3.h"
#include "mpm_hs_cache.h"
#include "mem.h"
#include "path.h"
#include "debug.h"

/* 캐시 DB 파일 경로 생성 */
static const char *HSCacheConstructFPath(const char *folder_path, uint64_t hs_db_hash)
{
    static char hash_file_path[4096];
    char filename[128];
    snprintf(filename, sizeof(filename), "%020lu_v1.hs", hs_db_hash);
    if (PathMerge(hash_file_path, sizeof(hash_file_path), folder_path, filename) != 0) {
        return NULL;
    }
    return hash_file_path;
}

/* 캐시 파일을 메모리로 읽기 */
static char *HSReadStream(const char *file_path, size_t *buffer_sz)
{
    /* 바이너리로 읽기 */
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        SCLogDebug("Failed to open file %s: %s", file_path, strerror(errno));
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_sz = ftell(file);
    if (file_sz < 0) {
        SCLogDebug("Failed to get file size: %s", file_path);
        fclose(file);
        return NULL;
    }
    rewind(file);

    char *buffer = SCCalloc(file_sz, sizeof(char), char);
    if (!buffer) {
        SCLogWarning("Memory allocation failed for cache read");
        fclose(file);
        return NULL;
    }

    size_t read_bytes = fread(buffer, 1, file_sz, file);
    if (read_bytes != (size_t)file_sz) {
        SCLogDebug("Incomplete read of file %s", file_path);
        SCFree(buffer);
        fclose(file);
        return NULL;
    }

    *buffer_sz = file_sz;
    fclose(file);
    return buffer;
}

/* 하나의 정규식 패턴 구조체(SCHSPattern)를 해시값으로 변환 */
static void SCHSCachePatternHash(const SCHSPattern *p, uint32_t *h1, uint32_t *h2)
{
    hashlittle2_safe(&p->len, sizeof(p->len), h1, h2);
    hashlittle2_safe(&p->flags, sizeof(p->flags), h1, h2);
    hashlittle2_safe(p->original_pat, p->len, h1, h2);
    hashlittle2_safe(&p->id, sizeof(p->id), h1, h2);
    hashlittle2_safe(&p->offset, sizeof(p->offset), h1, h2);
    hashlittle2_safe(&p->depth, sizeof(p->depth), h1, h2);
    hashlittle2_safe(&p->sids_size, sizeof(p->sids_size), h1, h2);
    hashlittle2_safe(p->sids, p->sids_size * sizeof(uint32_t), h1, h2);
}

/* db 캐시 존재 여부 확인 후 db 로드 */
int HSLoadCache(hs_database_t **hs_db, uint64_t hs_db_hash, const char *dirpath)
{
    const char *fpath = HSCacheConstructFPath(dirpath, hs_db_hash);
    if (!fpath || !SCPathExists(fpath)) return -1;

    size_t size = 0;
    char *stream = HSReadStream(fpath, &size);
    if (!stream) return -1;

    hs_error_t err = hs_deserialize_database(stream, size, hs_db);
    SCFree(stream);
    if (err != HS_SUCCESS) {
        SCLogWarning("Failed to deserialize cache DB from %s", fpath);
        return -1;
    }
    return 0;
}

/* Hyperscan DB를 디스크에 저장 */
static int HSSaveCache(hs_database_t *hs_db, uint64_t hs_db_hash, const char *dirpath)
{
    char *stream = NULL;
    size_t size = 0;
    /* 직렬화 */
    hs_error_t err = hs_serialize_database(hs_db, &stream, &size);
    if (err != HS_SUCCESS) {
        SCLogWarning("Failed to serialize Hyperscan DB");
        return -1;
    }

    /* 경로 생성 */
    const char *fpath = HSCacheConstructFPath(dirpath, hs_db_hash);
    if (!fpath) {
        SCFree(stream);
        return -1;
    }

    FILE *file = fopen(fpath, "w");
    if (!file) {
        SCLogWarning("Could not open file to write cache: %s", fpath);
        SCFree(stream);
        return -1;
    }

    size_t written = fwrite(stream, 1, size, file);
    fclose(file);
    SCFree(stream);

    if (written != size) {
        SCLogWarning("Partial write of cache DB: %s", fpath);
        return -1;
    }
    return 0;
}

/* 파일 이름에 쓰일 해시값(64bit) 생성 */
uint64_t HSHashDb(const PatternDatabase *pd)
{
    uint64_t hash64 = 0;
    uint32_t *hash32 = (uint32_t *)&hash64;
    hashword2(&pd->pattern_cnt, 1, &hash32[0], &hash32[1]);

    for (uint32_t i = 0; i < pd->pattern_cnt; i++) {
        SCHSCachePatternHash(pd->parray[i], &hash32[0], &hash32[1]);
    }
    return hash64;
}

void HSSaveCacheIterator(void *data, void *aux)
{
    PatternDatabase *pd = (PatternDatabase *)data;
    HsIteratorData *it = (HsIteratorData *)aux;

    if (pd->no_cache)
        return;

    it->pd_stats->hs_cacheable_dbs_cnt++;
    
    /* if 이미 저장된 db */
    if (pd->cached) {
        /* 로드 카운트만 증가 */
        it->pd_stats->hs_dbs_cache_loaded_cnt++;
        return;
    }

    /* if 저장되지 않은 db */
    if (HSSaveCache(pd->hs_db, HSHashDb(pd), it->cache_path) == 0) {
        pd->cached = true;
        it->pd_stats->hs_dbs_cache_saved_cnt++;
    }
}