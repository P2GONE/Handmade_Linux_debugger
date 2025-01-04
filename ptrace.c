#include "ptrace.h"
#include <stdio.h>
#include <errno.h>

// 메모리 읽기 함수
int pt_read_memory(pid_t pid, uintptr_t addr, uint64_t* data) {
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, pid, (void*)addr, NULL);
    if (word == -1 && errno != 0) {
        return FAILURE;
    }
    *data = (uint64_t)word;
    return SUCCESS;
}

// 메모리 쓰기 함수
int pt_write_memory(pid_t pid, uintptr_t addr, uint64_t data) {
    if (ptrace(PTRACE_POKEDATA, pid, (void*)addr, (void*)data) == -1) {
        return FAILURE;
    }
    return SUCCESS;
}

// 레지스터 읽기 함수
int pt_read_registers(pid_t pid, struct user_regs_struct* regs) {
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) == -1) {
        return FAILURE;
    }
    return SUCCESS;
}

// 레지스터 쓰기 함수
int pt_write_registers(pid_t pid, struct user_regs_struct* regs) {
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) == -1) {
        return FAILURE;
    }
    return SUCCESS;
}

// 단일 명령어 실행 함수
int pt_single_step(pid_t pid) {
    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) {
        return FAILURE;
    }
    return SUCCESS;
}

// 시그널 정보 얻기 함수
int pt_get_signal_info(pid_t pid, siginfo_t* siginfo) {
    if (ptrace(PTRACE_GETSIGINFO, pid, NULL, siginfo) == -1) {
        return FAILURE;
    }
    return SUCCESS;
}
