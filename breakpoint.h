#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#include <stdint.h>
#include <sys/types.h>

// 브레이크포인트 구조체
typedef struct breakpoint {
    uintptr_t addr;               // 브레이크포인트 주소
    uint64_t original_data;       // 원래의 명령어 데이터
    struct breakpoint* next;      // 다음 브레이크포인트로의 포인터
} breakpoint_t;

// 브레이크포인트 관리 함수들
int set_breakpoint(pid_t pid, breakpoint_t** head, uintptr_t addr);
int remove_breakpoint(pid_t pid, breakpoint_t** head, uintptr_t addr);
void list_breakpoints(breakpoint_t* head);

#endif // BREAKPOINT_H
