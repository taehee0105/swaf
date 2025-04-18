/* 해시 테이블 구현 */

#include "debug.h"
#include "hash_table.h"
#include "mem.h"
#include "mpmcmp.h"

HashTable* HashTableInit(uint32_t size, uint32_t (*Hash)(struct HashTable_ *, void *, uint16_t), char (*Compare)(void *, uint16_t, void *, uint16_t), void (*Free)(void *)) {
    if (size == 0 || Hash == NULL)
        return NULL;

    HashTable *ht = SCCalloc(1, sizeof(HashTable), HashTable);
    if (ht == NULL)
        return NULL;

    ht->array_size = size;
    ht->Hash = Hash;
    ht->Free = Free;
    ht->Compare = Compare ? Compare : HashTableDefaultCompare;

    ht->array = SCCalloc(ht->array_size, sizeof(HashTableBucket *), HashTableBucket *);
    if (ht->array == NULL) {
        SCFree(ht);
        return NULL;
    }

    return ht;
}

void HashTableFree(HashTable *ht) {
    if (ht == NULL) return;

    for (uint32_t i = 0; i < ht->array_size; i++) {
        HashTableBucket *b = ht->array[i];
        while (b != NULL) {
            HashTableBucket *next = b->next;
            if (ht->Free != NULL) ht->Free(b->data);
            SCFree(b);
            b = next;
        }
    }
    SCFree(ht->array);
    SCFree(ht);
}

int HashTableAdd(HashTable *ht, void *data, uint16_t len) {
    if (!ht || !data) return -1;
    uint32_t hash = ht->Hash(ht, data, len);

    HashTableBucket *b = SCCalloc(1, sizeof(HashTableBucket), HashTableBucket);
    if (!b) return -1;

    b->data = data;
    b->size = len;
    b->next = ht->array[hash];
    ht->array[hash] = b;

    return 0;
}

int HashTableRemove(HashTable *ht, void *data, uint16_t len) {
    if (!ht) return -1;
    uint32_t hash = ht->Hash(ht, data, len);
    HashTableBucket *b = ht->array[hash], *prev = NULL;

    while (b) {
        if (ht->Compare(b->data, b->size, data, len)) {
            if (prev) prev->next = b->next;
            else ht->array[hash] = b->next;
            if (ht->Free) ht->Free(b->data);
            SCFree(b);
            return 0;
        }
        prev = b;
        b = b->next;
    }
    return -1;
}

void *HashTableLookup(HashTable *ht, void *data, uint16_t len) {
    if (!ht) return NULL;
    uint32_t hash = ht->Hash(ht, data, len);
    HashTableBucket *b = ht->array[hash];

    while (b) {
        if (ht->Compare(b->data, b->size, data, len))
            return b->data;
        b = b->next;
    }
    return NULL;
}

void HashTableIterate(HashTable *ht, void (*Callback)(void *, void *), void *aux) {
    if (!ht || !Callback) return;
    for (uint32_t i = 0; i < ht->array_size; i++) {
        HashTableBucket *b = ht->array[i];
        while (b) {
            Callback(b->data, aux);
            b = b->next;
        }
    }
}

uint32_t HashTableGenericHash(HashTable *ht, void *data, uint16_t len) {
    /**
     * -- cpp error code --
     * uint8_t *d = data;
     */
    uint8_t *d = (uint8_t *)data;
    uint32_t h = 0;
    for (uint32_t i = 0; i < len; i++)
        h = h * 31 + d[i];
    return h % ht->array_size;
}

char HashTableDefaultCompare(void *d1, uint16_t l1, void *d2, uint16_t l2) {
    if (l1 != l2) return 0;
    return SCMemcmp(d1, d2, l1) == 0;
}