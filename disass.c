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