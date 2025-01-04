#ifndef PTRACE_H
#define PTRACE_H

#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdint.h>
#include <sys/types.h>   // pid_t 정의
#include <signal.h>      // siginfo_t 정의

// 성공/실패 매크로 정의
#define SUCCESS 0
#define FAILURE -1

int pt_read_memory(pid_t pid, uintptr_t addr, uint64_t* data);
int pt_write_memory(pid_t pid, uintptr_t addr, uint64_t data);
int pt_read_registers(pid_t pid, struct user_regs_struct* regs);
int pt_write_registers(pid_t pid, struct user_regs_struct* regs);
int pt_single_step(pid_t pid);
int pt_get_signal_info(pid_t pid, siginfo_t* siginfo);

#endif // PTRACE_H
