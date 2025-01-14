#include "disass.h" // 헤더 파일 이름을 일치시킵니다.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 디스어셈블러 초기화 함수 (필요 시 구현)
int disassemble_init() {
    // 현재는 초기화 작업이 필요 없으므로 성공 반환
    return 0;
}

// 디스어셈블러 종료 함수 (필요 시 구현)
void disassemble_cleanup() {
    // 현재는 종료 작업이 필요 없으므로 빈 함수
}

// objdump를 활용한 디스어셈블 함수 구현
void disassemble_objdump(const char* exe_path, uintptr_t addr, size_t count) {
    // 디스어셈블할 주소를 헥사 문자열로 변환 (콜론 포함)
    char addr_str[20];
    snprintf(addr_str, sizeof(addr_str), " %lx:", addr);

    // 디스어셈블할 주소 범위 설정 (예: 5개의 명령어를 대략 80바이트)
    uintptr_t stop_addr = addr + (count * 16); // 명령어당 최대 16바이트 가정
    char command[512];
    snprintf(command, sizeof(command),
             "objdump -d --start-address=0x%lx --stop-address=0x%lx %s",
             addr, stop_addr, exe_path);

    // 명령어 실행
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("popen failed");
        return;
    }

    // 출력 결과 읽기
    char buffer[512];
    printf("Disassembly at 0x%lx:\n", addr);
    int found = 0;
    size_t printed = 0;

    while (fgets(buffer, sizeof(buffer), pipe)) {
        // 특정 주소에서 시작하는 라인만 찾기
        if (strstr(buffer, addr_str)) {
            printf("%s", buffer);
            found = 1;
            continue;
        }

        // 찾은 이후의 명령어 라인 출력
        if (found && strncmp(buffer, " ", 1) == 0) {
            printf("%s", buffer);
            printed++;
            if (printed >= count)
                break;
        }

        // 다른 함수의 시작 라인이 나오면 중단
        if (found && strncmp(buffer, " ", 1) != 0) {
            break;
        }
    }

    if (!found) {
        printf("No disassembly found at 0x%lx.\n", addr);
    }

    pclose(pipe);
}
