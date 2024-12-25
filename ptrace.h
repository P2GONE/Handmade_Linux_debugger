#pragma once

#ifndef _SPRAY_PTRACE_H_
#define _SPRAY_PTRACE_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <signal.h>
#include <sys/user.h>
#include <sys/ptrace.h>
#include <errno.h>
#include <assert.h>

// 함수 반환값 정의
#define SUCCESS 0
#define FAILURE 1

// 메모리 읽기
static inline int pt_read_memory(pid_t pid, uintptr_t addr, uint64_t *read) {
    assert(read != NULL);

    errno = 0;
    uint64_t value = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);
    if (errno == 0) {
        *read = value;
        return SUCCESS;
    } else {
        return FAILURE;
    }
}

// 메모리 쓰기
static inline int pt_write_memory(pid_t pid, uintptr_t addr, uint64_t write) {
    if (ptrace(PTRACE_POKEDATA, pid, addr, write) == -1) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

// 레지스터 읽기
static inline int pt_read_registers(pid_t pid, struct user_regs_struct *regs) {
    assert(regs != NULL);
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

// 레지스터 쓰기
static inline int pt_write_registers(pid_t pid, struct user_regs_struct *regs) {
    assert(regs != NULL);
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

// 프로세스 실행 계속
static inline int pt_continue_execution(pid_t pid) {
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

// 디버거로 설정
static inline int pt_trace_me(void) {
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

// 명령 단위 실행
static inline int pt_single_step(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

// 신호 정보 가져오기
static inline int pt_get_signal_info(pid_t pid, siginfo_t *siginfo) {
    assert(siginfo != NULL);
    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, siginfo) == -1) {
        return FAILURE;
    } else {
        return SUCCESS;
    }
}

#endif /* _SPRAY_PTRACE_H_ */
