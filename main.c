#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>
#include <stdint.h>
#include <ctype.h>

#include "ptrace.h"
#include "breakpoint.h" 
#include "disass.h" 

// 디버거 상태를 나타내는 구조체
typedef struct {
    char* prog_name;      // 디버깅 대상 프로그램 이름
    pid_t pid;            // 디버깅 대상 프로세스 ID
    breakpoint_t* head;   // 브레이크포인트 리스트의 헤드
} debugger_t;

// 디버거 초기화 함수
void debugger_init(debugger_t* dbg, const char* prog_name, pid_t pid) {
    dbg->prog_name = strdup(prog_name); // 문자열 복사
    dbg->pid = pid;
    dbg->head = NULL;
}

// 메모리 읽기 함수 (다양한 크기 지원)
void debugger_read_memory(debugger_t* dbg, uintptr_t addr, size_t size) {
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        printf("Unsupported size: %zu bytes. Supported sizes are 1, 2, 4, or 8 bytes.\n", size);
        return;
    }

    uint64_t value;
    if (pt_read_memory(dbg->pid, addr, &value) == SUCCESS) {
        uint64_t mask;
        switch (size) {
            case 1:
                mask = 0xFF;
                break;
            case 2:
                mask = 0xFFFF;
                break;
            case 4:
                mask = 0xFFFFFFFF;
                break;
            case 8:
                mask = 0xFFFFFFFFFFFFFFFF;
                break;
            default:
                mask = 0;
                break;
        }
        printf("Read %zu byte%s at 0x%lx: 0x%llx\n", 
               size, 
               size > 1 ? "s" : "", 
               addr, 
               value & mask);
    } else {
        perror("Failed to read memory");
    }
}

// 메모리 쓰기 함수
void debugger_write_memory(debugger_t* dbg, uintptr_t addr, uint64_t value) {
    if (pt_write_memory(dbg->pid, addr, value) == SUCCESS) {
        printf("Wrote 0x%lx to memory at 0x%lx\n", value, addr);
    } else {
        perror("Failed to write memory");
    }
}

// 레지스터 읽기 함수 (모든 일반 레지스터 표시)
void debugger_read_registers(debugger_t* dbg) {
    struct user_regs_struct regs;
    if (pt_read_registers(dbg->pid, &regs) == SUCCESS) {
        printf("Registers read successfully.\n");
        printf("RIP: 0x%llx\n", regs.rip);
        printf("RAX: 0x%llx\n", regs.rax);
        printf("RBX: 0x%llx\n", regs.rbx);
        printf("RCX: 0x%llx\n", regs.rcx);
        printf("RDX: 0x%llx\n", regs.rdx);
        printf("RSI: 0x%llx\n", regs.rsi);
        printf("RDI: 0x%llx\n", regs.rdi);
        printf("RSP: 0x%llx\n", regs.rsp);
        printf("RBP: 0x%llx\n", regs.rbp);
        printf("R8 : 0x%llx\n", regs.r8);
        printf("R9 : 0x%llx\n", regs.r9);
        printf("R10: 0x%llx\n", regs.r10);
        printf("R11: 0x%llx\n", regs.r11);
        printf("R12: 0x%llx\n", regs.r12);
        printf("R13: 0x%llx\n", regs.r13);
        printf("R14: 0x%llx\n", regs.r14);
        printf("R15: 0x%llx\n", regs.r15);
    } else {
        perror("Failed to read registers");
    }
}

// 레지스터 쓰기 함수
void debugger_write_registers(debugger_t* dbg, struct user_regs_struct* regs) {
    if (pt_write_registers(dbg->pid, regs) == SUCCESS) {
        printf("Registers written successfully.\n");
    } else {
        perror("Failed to write registers");
    }
}

// 단일 명령어 실행 함수
void debugger_single_step(debugger_t* dbg) {
    int wait_status;
    if (pt_single_step(dbg->pid) == SUCCESS) {
        waitpid(dbg->pid, &wait_status, 0);
        if (WIFSTOPPED(wait_status)) {
            printf("Single step executed. Signal: %d\n", WSTOPSIG(wait_status));
        } else {
            printf("Unexpected status: 0x%x\n", wait_status);
        }
    } else {
        perror("Failed to execute single step");
    }
}

// 시그널 정보 읽기 함수
void debugger_read_signal_info(debugger_t* dbg) {
    siginfo_t siginfo;
    if (pt_get_signal_info(dbg->pid, &siginfo) == SUCCESS) {
        printf("Signal info:\n");
        printf("  Signal number: %d\n", siginfo.si_signo);
        printf("  Error number: %d\n", siginfo.si_errno);
        printf("  Code: %d\n", siginfo.si_code);
    } else {
        perror("Failed to get signal info");
    }
}

// 헥스덤프 메모리 함수
void debugger_hexdump_memory(debugger_t* dbg, uintptr_t addr, size_t length) {
    size_t i;
    uint64_t data;
    printf("Hexdump of memory at 0x%lx (length: %zu bytes):\n", addr, length);
    for (i = 0; i < length; i += 8) {
        if (pt_read_memory(dbg->pid, addr + i, &data) != SUCCESS) {
            perror("Failed to read memory for hexdump");
            break;
        }
        printf("0x%lx: ", addr + i);
        size_t j;
        for (j = 0; j < 8 && (i + j) < length; j++) {
            printf("%02llx ", (data >> (j * 8)) & 0xFF);
        }
        printf("\n");
    }
}

// 스택 메모리 덤프 함수
void debugger_stack_dump(debugger_t* dbg, size_t length) {
    struct user_regs_struct regs;
    if (pt_read_registers(dbg->pid, &regs) != SUCCESS) {
        perror("Failed to read registers for stack dump");
        return;
    }
    uintptr_t rsp = regs.rsp;
    printf("Stack dump (RSP = 0x%lx, length: %zu bytes):\n", rsp, length);
    debugger_hexdump_memory(dbg, rsp, length);
}

// 브레이크포인트 설정 함수 (별도 함수로 래핑)
int set_breakpoint_at_addr(debugger_t* dbg, uintptr_t addr) {
    return set_breakpoint(dbg->pid, &dbg->head, addr);
}

// 브레이크포인트 제거 함수 (별도 함수로 래핑)
int remove_breakpoint_at_addr(debugger_t* dbg, uintptr_t addr) {
    return remove_breakpoint(dbg->pid, &dbg->head, addr);
}

// 브레이크포인트 목록 출력 함수 (별도 함수로 래핑)
void list_current_breakpoints(debugger_t* dbg) {
    list_breakpoints(dbg->head);
}

// 명령어 파싱 함수
int parse_command(char* line, char** args, int max_args) {
    int argc = 0;
    char* token = strtok(line, " ");
    while (token != NULL && argc < max_args - 1) {
        args[argc++] = token;
        token = strtok(NULL, " ");
    }
    args[argc] = NULL;
    return argc;
}

// 디스어셈블 함수 선언 (헤더 파일 사용)
extern void disassemble(const char* prog_path, uintptr_t addr, size_t count);


// 메뉴 출력 함수
void my_gdb_menu(){
    printf(" My MENU \n");
    printf("[continue] : program continue\n");
    printf("[readmem] <addr> [size] : read memory (size: 1,2,4,8 bytes)\n");
    printf("[writemem] <addr> <value> : write memory\n");
    printf("[readregs] : read registers\n");
    printf("[hexdump] <addr> [length] : hexdump memory\n");
    printf("[stackdump] [length] : dump stack memory (default: 64 bytes)\n");
    printf("[single] : Execute a single instruction step\n");
    printf("[signal] : Display the current signal information\n");
    printf("[break] [addr] : set breakpoint at address\n");
    printf("[delete] [addr] : remove breakpoint at address\n");
    printf("[bplist] : list all breakpoints\n");
    printf("[exit] : program exit\n\n");
}


// 디버거 루프 실행 함수
void debugger_run(debugger_t* dbg) {
    int wait_status;
    waitpid(dbg->pid, &wait_status, 0); // 자식 프로세스가 SIGTRAP을 보낼 때까지 대기

    printf("Debugger started. Monitoring process %d\n", dbg->pid);

    char line[256]; // 사용자 명령 입력용 버퍼
    char* args[10];
    while (1) {
        printf("jaehun_debug > ");
        if (fgets(line, sizeof(line), stdin) == NULL) {
            printf("EOF received. Exiting debugger.\n");
            break;
        }

        line[strcspn(line, "\n")] = '\0'; // 입력에서 개행 문자 제거
        if (strlen(line) == 0) continue; // 빈 명령은 무시

        // 명령어 파싱
        int argc = parse_command(line, args, 10);
        if (argc == 0) continue;

        // 명령어 처리
        if (strcmp(args[0], "continue") == 0) {
            ptrace(PTRACE_CONT, dbg->pid, NULL, NULL); // 디버깅 대상 프로세스 계속 실행
            waitpid(dbg->pid, &wait_status, 0);       // 상태 대기
            if (WIFEXITED(wait_status)) {
                printf("Process %d exited with status %d\n", dbg->pid, WEXITSTATUS(wait_status));
                break;
            }

            // 브레이크포인트 처리
            if (WIFSTOPPED(wait_status) && WSTOPSIG(wait_status) == SIGTRAP) {
                struct user_regs_struct regs;
                pt_read_registers(dbg->pid, &regs);
                uintptr_t rip = regs.rip - 1; // 브레이크포인트는 RIP이 1 증가한 상태
                printf("Hit breakpoint at 0x%lx\n", rip);

                // 브레이크포인트에 해당하는지 확인
                breakpoint_t* bp = dbg->head;
                while (bp) {
                    if (bp->addr == rip) {
                        // 원래 명령어 복원
                        pt_write_memory(dbg->pid, rip, bp->original_data);

                        // RIP을 원래 위치로 되돌림
                        regs.rip = rip;
                        pt_write_registers(dbg->pid, &regs);

                        // 한 단계 실행 (단일 스텝)
                        pt_single_step(dbg->pid);
                        waitpid(dbg->pid, &wait_status, 0);

                        // 브레이크포인트 다시 삽입
                        pt_write_memory(dbg->pid, rip, (bp->original_data & ~0xFF) | BREAKPOINT_INT3);
                        break;
                    }
                    bp = bp->next;
                }
            }

        } else if (strcmp(args[0], "readmem") == 0) {
            if (argc < 2) {
                printf("Usage: readmem <address> [size]\n");
                printf("Size can be 1, 2, 4, or 8 bytes. Default is 8.\n");
                continue;
            }
            uintptr_t addr = strtoull(args[1], NULL, 16);
            size_t size = 8; // 기본 크기
            if (argc >= 3) {
                size = strtoull(args[2], NULL, 10);
            }
            debugger_read_memory(dbg, addr, size);

        } else if (strcmp(args[0], "writemem") == 0) {
            if (argc < 3) {
                printf("Usage: writemem <address> <value>\n");
                continue;
            }
            uintptr_t addr = strtoull(args[1], NULL, 16);
            uint64_t value = strtoull(args[2], NULL, 16);
            debugger_write_memory(dbg, addr, value);

        } else if (strcmp(args[0], "readregs") == 0) {
            debugger_read_registers(dbg);

        } else if (strcmp(args[0], "hexdump") == 0) {
            if (argc < 2) {
                printf("Usage: hexdump <address> [length]\n");
                printf("Length is in bytes. Default is 64.\n");
                continue;
            }
            uintptr_t addr = strtoull(args[1], NULL, 16);
            size_t length = 64; // 기본 길이
            if (argc >= 3) {
                length = strtoull(args[2], NULL, 10);
            }
            debugger_hexdump_memory(dbg, addr, length);

        } else if (strcmp(args[0], "stackdump") == 0) {
            size_t length = 64; // 기본 길이
            if (argc >= 2) {
                length = strtoull(args[1], NULL, 10);
            }
            debugger_stack_dump(dbg, length);

        } else if (strcmp(args[0], "single") == 0) {
            debugger_single_step(dbg);

        } else if (strcmp(args[0], "signal") == 0) {
            debugger_read_signal_info(dbg);

        } else if (strcmp(args[0], "break") == 0 || strcmp(args[0], "b") == 0) {
            if (argc < 2) {
                printf("Usage: break <address>\n");
                continue;
            }
            uintptr_t addr = strtoull(args[1], NULL, 16);
            set_breakpoint_at_addr(dbg, addr);

        } else if (strcmp(args[0], "delete") == 0 || strcmp(args[0], "d") == 0) {
            if (argc < 2) {
                printf("Usage: delete <address>\n");
                continue;
            }
            uintptr_t addr = strtoull(args[1], NULL, 16);
            remove_breakpoint_at_addr(dbg, addr);

        } else if (strcmp(args[0], "bplist") == 0 || strcmp(args[0], "bp") == 0) {
            list_current_breakpoints(dbg);

        } else {
            printf("Unknown command: %s\n", args[0]);
        }
    }
}

// 메인 함수
int main(int argc, char* argv[]) {
    my_gdb_menu();
    if (argc < 2) {
        printf("Usage: %s <program_to_debug>\n", argv[0]);
        return -1;
    }

    const char* prog_name = argv[1];
    pid_t pid = fork();

    if (pid == 0) {
        // 자식 프로세스 (디버깅 대상)
        printf("Executing program: %s\n", prog_name);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL); // 디버거에 의해 추적 설정
        execl(prog_name, prog_name, NULL);     // 디버깅 대상 실행
        perror("execl failed");
        exit(-1);
    } else if (pid > 0) {
        // 부모 프로세스 (디버거)
        debugger_t dbg;
        debugger_init(&dbg, prog_name, pid); // 디버거 초기화
        debugger_run(&dbg);                 // 디버거 루프 실행
        free(dbg.prog_name);                // 메모리 해제
    } else {
        perror("fork failed");
        return -1;
    }

    return 0;
}
