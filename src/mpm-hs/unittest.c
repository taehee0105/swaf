/* 유닛 테스트 프레임워크 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pcre2.h>

#include "mem.h"
#include "optimize.h"
#include "unittest.h"

#ifdef UNITTESTS

#define PCRE2_CODE_UNIT_WIDTH 8

static pcre2_code *parse_regex;
static pcre2_match_data *parse_regex_match;

static UtTest *ut_list = NULL;
int unittests_fatal = 0;

static UtTest *UtAllocTest(void) {
    UtTest *ut = SCMalloc(sizeof(UtTest), UtTest);
    if (unlikely(ut == NULL))
        return NULL;
    memset(ut, 0, sizeof(UtTest));
    return ut;
}

static int UtAppendTest(UtTest **list, UtTest *test) {
    if (*list == NULL) {
        *list = test;
    } else {
        UtTest *tmp = *list;
        while (tmp->next != NULL) {
            tmp = tmp->next;
        }
        tmp->next = test;
    }
    return 0;
}

void UtRegisterTest(const char *name, int (*TestFn)(void)) {
    UtTest *ut = UtAllocTest();
    if (ut == NULL) return;
    ut->name = name;
    ut->TestFn = TestFn;
    ut->next = NULL;
    UtAppendTest(&ut_list, ut);
}

static int UtRegex(const char *regex_arg) {
    int en;
    PCRE2_SIZE eo;
    int opts = PCRE2_CASELESS;

    if (regex_arg == NULL)
        return -1;

    parse_regex = pcre2_compile((PCRE2_SPTR)regex_arg, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (parse_regex == NULL) return -1;
    parse_regex_match = pcre2_match_data_create_from_pattern(parse_regex, NULL);
    return 1;
}

void UtListTests(const char *regex_arg) {
    UtTest *ut;
    int ret = 0, rcomp = 0;
    rcomp = UtRegex(regex_arg);

    for (ut = ut_list; ut != NULL; ut = ut->next) {
        if (rcomp == 1) {
            ret = pcre2_match(parse_regex, (PCRE2_SPTR)ut->name, strlen(ut->name), 0, 0, parse_regex_match, NULL);
            if (ret >= 1) printf("%s\n", ut->name);
        } else {
            printf("%s\n", ut->name);
        }
    }

    pcre2_code_free(parse_regex);
    pcre2_match_data_free(parse_regex_match);
}

uint32_t UtRunTests(const char *regex_arg) {
    UtTest *ut;
    uint32_t good = 0, bad = 0;
    int ret = 0, rcomp = 0;

    rcomp = (regex_arg != NULL) ? UtRegex(regex_arg) : -1;

    for (ut = ut_list; ut != NULL; ut = ut->next) {
        if (rcomp == 1) {
            ret = pcre2_match(parse_regex, (PCRE2_SPTR)ut->name, strlen(ut->name), 0, 0, parse_regex_match, NULL);
            if (ret < 1) continue;
        }

        printf("Test %s: ", ut->name);
        fflush(stdout);

        ret = ut->TestFn();

        if (!ret) {
            printf("FAILED\n");
            if (unittests_fatal == 1) exit(EXIT_FAILURE);
            bad++;
        } else {
            printf("PASS\n");
            good++;
        }
    }

    printf("==== TEST RESULTS ====\n");
    printf("PASSED: %u\n", good);
    printf("FAILED: %u\n", bad);
    printf("======================\n");

    if (rcomp == 1) {
        pcre2_code_free(parse_regex);
        pcre2_match_data_free(parse_regex_match);
    }
    return bad;
}

void UtInitialize(void) {
    ut_list = NULL;
}

void UtCleanup(void) {
    UtTest *tmp = ut_list, *otmp;
    while (tmp != NULL) {
        otmp = tmp->next;
        SCFree(tmp);
        tmp = otmp;
    }
    ut_list = NULL;
}

#endif /* UNITTESTS */