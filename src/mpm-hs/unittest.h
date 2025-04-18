/* 유닛 테스트 프레임워크 헤더 */

#ifndef SWAF_UNITTEST_H
#define SWAF_UNITTEST_H

#ifdef UNITTESTS

#include <stdint.h>

/* 테스트 등록 구조체 */
typedef struct UtTest_ {
    const char *name;
    int (*TestFn)(void);
    struct UtTest_ *next;
} UtTest;

/* 유닛 테스트 등록 및 실행 관련 함수들 */
void UtRegisterTest(const char *name, int (*TestFn)(void));
void UtListTests(const char *regex_arg);
uint32_t UtRunTests(const char *regex_arg);
void UtInitialize(void);
void UtCleanup(void);
int UtRunSelftest(const char *regex_arg);

/* 테스트 실패/성공 매크로 */
#define FAIL return 0
#define PASS return 1

#define FAIL_IF(expr) do { if (expr) return 0; } while (0)
#define FAIL_IF_NOT(expr) FAIL_IF(!(expr))
#define FAIL_IF_NULL(expr) FAIL_IF((expr) == NULL)
#define FAIL_IF_NOT_NULL(expr) FAIL_IF((expr) != NULL)

extern int unittests_fatal;

#endif /* UNITTESTS */

#endif /* SWAF_UNITTEST_H */