/* 해시 테이블 라이브러리 헤더 */

#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Hash bucket structure */
typedef struct HashTableBucket_ {
    void *data;
    uint16_t size;
    struct HashTableBucket_ *next;
} HashTableBucket;

/* Hash table structure */
typedef struct HashTable_ {
    HashTableBucket **array;
    uint32_t array_size;
    uint32_t (*Hash)(struct HashTable_ *, void *, uint16_t);
    char (*Compare)(void *, uint16_t, void *, uint16_t);
    void (*Free)(void *);
} HashTable;

HashTable *HashTableInit(uint32_t size,
                         uint32_t (*Hash)(HashTable *, void *, uint16_t),
                         char (*Compare)(void *, uint16_t, void *, uint16_t),
                         void (*Free)(void *));
void HashTableFree(HashTable *ht);
int HashTableAdd(HashTable *ht, void *data, uint16_t datalen);
int HashTableRemove(HashTable *ht, void *data, uint16_t datalen);
void *HashTableLookup(HashTable *ht, void *data, uint16_t datalen);
void HashTableIterate(HashTable *ht, void (*CallbackFn)(void *, void *), void *aux);
uint32_t HashTableGenericHash(HashTable *ht, void *data, uint16_t datalen);
char HashTableDefaultCompare(void *data1, uint16_t len1, void *data2, uint16_t len2);

#endif /* HASH_TABLE_H */
