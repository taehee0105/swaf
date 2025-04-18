/* 해시 함수(Bob Jenkins Lookup3) 구현 헤더 */

#ifndef SWAF_HASH_LOOKUP3_H
#define SWAF_HASH_LOOKUP3_H

#include <stdint.h>
#include <stddef.h>

#define hashsize(n) ((uint32_t)1<<(n))
#define hashmask(n) (hashsize(n)-1)

uint32_t hashword(const uint32_t *k, size_t length, uint32_t initval);
void hashword2(const uint32_t *k, size_t length, uint32_t *pc, uint32_t *pb);

uint32_t hashlittle(const void *key, size_t length, uint32_t initval);
uint32_t hashlittle_safe(const void *key, size_t length, uint32_t initval);

void hashlittle2(const void *key, size_t length, uint32_t *pc, uint32_t *pb);
void hashlittle2_safe(const void *key, size_t length, uint32_t *pc, uint32_t *pb);

uint32_t hashbig(const void *key, size_t length, uint32_t initval);

#endif /* SWAF_HASH_LOOKUP3_H */