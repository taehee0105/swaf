#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>
#include <stddef.h>
#include "unittest.h"
#include "util-mpm-hs.h"

int main(void) {
    MpmHSRegister(); 
    UtInitialize();
    SCHSRegisterTests();  // SCHSTestXX 등록 함수
    UtRunTests(NULL);     // 전체 테스트 실행
    UtCleanup();
    return 0;
}
