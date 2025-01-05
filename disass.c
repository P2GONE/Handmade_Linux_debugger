// disassemble.c
#include "disass.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// 디스어셈블 함수 구현 (GNU objdump 사용)
void disassemble(const char* prog_path, uintptr_t addr, size_t count) {
    if (prog_path == NULL) {
        fprintf(stderr, "Program path is NULL.\n");
        return;
    }

    // objdump 명령어 구성
    // -d: 디스어셈블, -j .text: .text 섹션만
    // grep을 사용하여 특정 주소에서 시작하는 라인과 그 이후 라인 출력
    char command[512];
    snprintf(command, sizeof(command),
             "objdump -d -j .text %s | grep -A %zu '^%lx:'",
             prog_path, count, addr);

    // 명령어 실행
    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("objdump failed");
        return;
    }

    // 출력 결과 읽기
    char buffer[512];
    printf("Disassembly at 0x%lx:\n", addr);
    while (fgets(buffer, sizeof(buffer), pipe)) {
        printf("%s", buffer);
    }

    pclose(pipe);
}

// 심볼 이름을 주소로 변환하는 함수 구현
int get_symbol_address(const char* prog_path, const char* symbol, uintptr_t* addr) {
    if (prog_path == NULL || symbol == NULL || addr == NULL) {
        fprintf(stderr, "Invalid arguments to get_symbol_address.\n");
        return -1;
    }

    // nm 명령어를 사용하여 심볼의 주소를 가져옵니다.
    // -n 옵션은 주소 순으로 정렬하지 않으며, 특정 심볼을 검색합니다.
    char command[512];
    snprintf(command, sizeof(command), "nm %s | grep ' %s$'", prog_path, symbol);

    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("popen failed");
        return -1;
    }

    char buffer[512];
    if (fgets(buffer, sizeof(buffer), pipe) == NULL) {
        // 심볼을 찾지 못함
        pclose(pipe);
        fprintf(stderr, "Symbol '%s' not found in %s.\n", symbol, prog_path);
        return -1;
    }

    pclose(pipe);

    // 출력 형식: 주소 심볼
    // 예: 0000000000401136 T main
    uintptr_t symbol_addr = 0;
    char symbol_type;
    if (sscanf(buffer, "%lx %c %s", &symbol_addr, &symbol_type, buffer) < 1) {
        fprintf(stderr, "Failed to parse nm output for symbol '%s'.\n", symbol);
        return -1;
    }

    *addr = symbol_addr;
    return 0;
}