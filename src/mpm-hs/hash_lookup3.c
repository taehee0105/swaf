#include "hash_lookup3.h"
#include <stdint.h>
#include <stddef.h>

#define rot(x,k) (((x)<<(k)) | ((x)>>(32-(k))))

#define mix(a,b,c) \
{ \
  a -= c;  a ^= rot(c, 4);  c += b; \
  b -= a;  b ^= rot(a, 6);  a += c; \
  c -= b;  c ^= rot(b, 8);  b += a; \
  a -= c;  a ^= rot(c,16);  c += b; \
  b -= a;  b ^= rot(a,19);  a += c; \
  c -= b;  c ^= rot(b, 4);  b += a; \
}

#define final(a,b,c) \
{ \
  c ^= b; c -= rot(b,14); \
  a ^= c; a -= rot(c,11); \
  b ^= a; b -= rot(a,25); \
  c ^= b; c -= rot(b,16); \
  a ^= c; a -= rot(c,4);  \
  b ^= a; b -= rot(a,14); \
  c ^= b; c -= rot(b,24); \
}

uint32_t hashword(const uint32_t *k, size_t length, uint32_t initval) {
    uint32_t a,b,c;
    a = b = c = 0xdeadbeef + (((uint32_t)length << 2) + initval);
    while (length > 3) {
        a += k[0]; b += k[1]; c += k[2];
        mix(a,b,c);
        length -= 3; k += 3;
    }
    switch(length) {
    case 3: c += k[2];
    case 2: b += k[1];
    case 1: a += k[0]; final(a,b,c);
    case 0: break;
    }
    return c;
}

void hashword2(const uint32_t *k, size_t length, uint32_t *pc, uint32_t *pb) {
    uint32_t a,b,c;
    a = b = c = 0xdeadbeef + (((uint32_t)length << 2) + *pc);
    c += *pb;
    while (length > 3) {
        a += k[0]; b += k[1]; c += k[2];
        mix(a,b,c);
        length -= 3; k += 3;
    }
    switch(length) {
    case 3: c += k[2];
    case 2: b += k[1];
    case 1: a += k[0]; final(a,b,c);
    case 0: break;
    }
    *pc = c; *pb = b;
}

uint32_t hashlittle(const void *key, size_t length, uint32_t initval) {
    const uint8_t *k = (const uint8_t *)key;
    uint32_t a, b, c;
    a = b = c = 0xdeadbeef + ((uint32_t)length) + initval;
    while (length > 12) {
        a += k[0] + ((uint32_t)k[1]<<8) + ((uint32_t)k[2]<<16) + ((uint32_t)k[3]<<24);
        b += k[4] + ((uint32_t)k[5]<<8) + ((uint32_t)k[6]<<16) + ((uint32_t)k[7]<<24);
        c += k[8] + ((uint32_t)k[9]<<8) + ((uint32_t)k[10]<<16) + ((uint32_t)k[11]<<24);
        mix(a,b,c);
        k += 12; length -= 12;
    }
    switch(length) {
    case 12: c += ((uint32_t)k[11])<<24;
    case 11: c += ((uint32_t)k[10])<<16;
    case 10: c += ((uint32_t)k[9])<<8;
    case 9 : c += k[8];
    case 8 : b += ((uint32_t)k[7])<<24;
    case 7 : b += ((uint32_t)k[6])<<16;
    case 6 : b += ((uint32_t)k[5])<<8;
    case 5 : b += k[4];
    case 4 : a += ((uint32_t)k[3])<<24;
    case 3 : a += ((uint32_t)k[2])<<16;
    case 2 : a += ((uint32_t)k[1])<<8;
    case 1 : a += k[0];
        break;
    case 0 : return c;
    }
    final(a,b,c);
    return c;
}

void hashlittle2(const void *key, size_t length, uint32_t *pc, uint32_t *pb) {
    uint32_t a,b,c;
    a = b = c = 0xdeadbeef + ((uint32_t)length) + *pc;
    c += *pb;
    const uint8_t *k = (const uint8_t *)key;
    while (length > 12) {
        a += k[0] + ((uint32_t)k[1]<<8) + ((uint32_t)k[2]<<16) + ((uint32_t)k[3]<<24);
        b += k[4] + ((uint32_t)k[5]<<8) + ((uint32_t)k[6]<<16) + ((uint32_t)k[7]<<24);
        c += k[8] + ((uint32_t)k[9]<<8) + ((uint32_t)k[10]<<16) + ((uint32_t)k[11]<<24);
        mix(a,b,c);
        k += 12; length -= 12;
    }
    switch(length) {
    case 12: c += ((uint32_t)k[11])<<24;
    case 11: c += ((uint32_t)k[10])<<16;
    case 10: c += ((uint32_t)k[9])<<8;
    case 9 : c += k[8];
    case 8 : b += ((uint32_t)k[7])<<24;
    case 7 : b += ((uint32_t)k[6])<<16;
    case 6 : b += ((uint32_t)k[5])<<8;
    case 5 : b += k[4];
    case 4 : a += ((uint32_t)k[3])<<24;
    case 3 : a += ((uint32_t)k[2])<<16;
    case 2 : a += ((uint32_t)k[1])<<8;
    case 1 : a += k[0];
        break;
    case 0 : *pc = c; *pb = b; return;
    }
    final(a,b,c); *pc = c; *pb = b;
}

uint32_t hashlittle_safe(const void *key, size_t length, uint32_t initval) {
    return hashlittle(key, length, initval);
}

void hashlittle2_safe(const void *key, size_t length, uint32_t *pc, uint32_t *pb) {
    hashlittle2(key, length, pc, pb);
}

uint32_t hashbig(const void *key, size_t length, uint32_t initval) {
    /* 간단하게 하려고 hashlittle이라고 부름 */
    return hashlittle(key, length, initval);
}