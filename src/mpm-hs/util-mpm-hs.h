/* MPM pattern matcher that calls the Hyperscan regex matcher. */

#ifndef SURICATA_UTIL_MPM_HS__H
#define SURICATA_UTIL_MPM_HS__H

void MpmHSRegister(void);

void MpmHSGlobalCleanup(void);

/* 유닛 테스트를 위한 함수 */
void SCHSRegisterTests(void);   

#endif /* MPM_HS_H */
