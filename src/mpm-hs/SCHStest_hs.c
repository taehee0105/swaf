/* 유닛 테스트 메인 */

#define PCRE2_CODE_UNIT_WIDTH 8

#include <pcre2.h>
#include <stddef.h>

#include "mpm_hs.h"
#include "unittest.h"

int main(void) {
    MpmHSRegister(); 
    UtInitialize();
    SCHSRegisterTests();  /* SCHSTest 등록 함수 */
    UtRunTests(NULL);     /* 전체 테스트 실행 */
    UtCleanup();
    return 0;
}