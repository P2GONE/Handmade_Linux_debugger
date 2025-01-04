#include "breakpoint.h"
#include "ptrace.h"
#include <stdio.h>
#include <stdlib.h>

#define BREAKPOINT_INT3 0xCC

// 브레이크포인트 설정 함수
int set_breakpoint(pid_t pid, breakpoint_t** head, uintptr_t addr) {
    // 브레이크포인트가 이미 설정되어 있는지 확인
    breakpoint_t* current = *head;
    while (current) {
        if (current->addr == addr) {
            printf("Breakpoint already set at 0x%lx\n", addr);
            return -1;
        }
        current = current->next;
    }

    // 현재 메모리 내용 읽기
    uint64_t original_data;
    if (pt_read_memory(pid, addr, &original_data) != SUCCESS) {
        perror("Failed to read memory for breakpoint");
        return -1;
    }

    // 브레이크포인트 삽입 (INT 3)
    uint64_t data_with_int3 = (original_data & ~0xFF) | BREAKPOINT_INT3;
    if (pt_write_memory(pid, addr, data_with_int3) != SUCCESS) {
        perror("Failed to write breakpoint");
        return -1;
    }

    // 브레이크포인트 구조체 생성
    breakpoint_t* bp = malloc(sizeof(breakpoint_t));
    if (!bp) {
        perror("Failed to allocate memory for breakpoint");
        return -1;
    }
    bp->addr = addr;
    bp->original_data = original_data;
    bp->next = *head;
    *head = bp;

    printf("Breakpoint set at 0x%lx\n", addr);
    return 0;
}

// 브레이크포인트 제거 함수
int remove_breakpoint(pid_t pid, breakpoint_t** head, uintptr_t addr) {
    breakpoint_t* current = *head;
    breakpoint_t* prev = NULL;

    while (current) {
        if (current->addr == addr) {
            // 원래 명령어 복원
            if (pt_write_memory(pid, addr, current->original_data) != SUCCESS) {
                perror("Failed to restore original instruction");
                return -1;
            }

            // 리스트에서 브레이크포인트 제거
            if (prev) {
                prev->next = current->next;
            } else {
                *head = current->next;
            }

            free(current);
            printf("Breakpoint removed from 0x%lx\n", addr);
            return 0;
        }
        prev = current;
        current = current->next;
    }

    printf("No breakpoint found at 0x%lx\n", addr);
    return -1;
}

// 브레이크포인트 목록 출력 함수
void list_breakpoints(breakpoint_t* head) {
    breakpoint_t* current = head;
    if (!current) {
        printf("No breakpoints set.\n");
        return;
    }

    printf("Current breakpoints:\n");
    while (current) {
        printf("  0x%lx\n", current->addr);
        current = current->next;
    }
}
