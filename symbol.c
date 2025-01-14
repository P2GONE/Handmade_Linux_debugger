#include "symbol.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// `objdump -t` 명령어를 사용하여 심볼 테이블을 추출하고, 원하는 심볼을 검색합니다.
int get_symbol_address(const char* exe_path, const char* symbol_name, uintptr_t* addr) {
    if (exe_path == NULL || symbol_name == NULL || addr == NULL) {
        fprintf(stderr, "Invalid arguments to get_symbol_address.\n");
        return SYMBOL_NOT_FOUND;
    }

    // objdump -t <exe_path> 명령어를 실행하여 심볼 테이블을 가져옵니다.
    char command[512];
    snprintf(command, sizeof(command), "objdump -t %s", exe_path);

    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("popen failed");
        return SYMBOL_NOT_FOUND;
    }

    char buffer[512];
    int found = 0;

    while (fgets(buffer, sizeof(buffer), pipe)) {
        // 각 라인은 다음과 같은 형식입니다:
        // 0000000000401136 l    d .text  0000000000000000 main
        // 또는
        // 0000000000000000 g     F .text  0000000000000000 _start
        // 심볼 이름이 마지막에 위치하므로 이를 기준으로 검색합니다.

        // 심볼 이름을 찾기 위해 라인을 토큰화합니다.
        char* token;
        char* saveptr;
        uintptr_t symbol_addr = 0;
        char sym_name[256] = {0};
        int is_global = 0;

        // 첫 번째 토큰: 주소
        token = strtok_r(buffer, " \t\n", &saveptr);
        if (token == NULL)
            continue;
        symbol_addr = strtoull(token, NULL, 16);

        // 두 번째 토큰: 심볼 유형
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;

        // 세 번째 토큰: 섹션 이름 등
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;

        // 네 번째 토큰: 심볼 크기 등
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;

        // 마지막 토큰: 심볼 이름
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;
        strncpy(sym_name, token, sizeof(sym_name) - 1);

        // 심볼 이름이 일치하는지 확인
        if (strcmp(sym_name, symbol_name) == 0) {
            *addr = symbol_addr;
            found = 1;
            break;
        }
    }

    pclose(pipe);

    if (found) {
        return SYMBOL_SUCCESS;
    } else {
        return SYMBOL_NOT_FOUND;
    }
}

// 모든 심볼을 출력하는 함수
int list_symbols(const char* exe_path) {
    if (exe_path == NULL) {
        fprintf(stderr, "Invalid argument to list_symbols.\n");
        return -1;
    }

    // objdump -t <exe_path> 명령어를 실행하여 심볼 테이블을 가져옵니다.
    char command[512];
    snprintf(command, sizeof(command), "objdump -t %s", exe_path);

    FILE* pipe = popen(command, "r");
    if (!pipe) {
        perror("popen failed");
        return -1;
    }

    char buffer[512];
    printf("Symbol list for %s:\n", exe_path);
    while (fgets(buffer, sizeof(buffer), pipe)) {
        // 각 라인은 다음과 같은 형식입니다:
        // 0000000000401136 l    d .text  0000000000000000 main
        // 또는
        // 0000000000000000 g     F .text  0000000000000000 _start
        // 심볼 이름이 마지막에 위치하므로 이를 기준으로 출력합니다.

        // 심볼 이름을 찾기 위해 라인을 토큰화합니다.
        char* token;
        char* saveptr;
        uintptr_t symbol_addr = 0;
        char sym_name[256] = {0};

        // 첫 번째 토큰: 주소
        token = strtok_r(buffer, " \t\n", &saveptr);
        if (token == NULL)
            continue;
        symbol_addr = strtoull(token, NULL, 16);

        // 두 번째 토큰: 심볼 유형
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;

        // 세 번째 토큰: 섹션 이름 등
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;

        // 네 번째 토큰: 심볼 크기 등
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;

        // 마지막 토큰: 심볼 이름
        token = strtok_r(NULL, " \t\n", &saveptr);
        if (token == NULL)
            continue;
        strncpy(sym_name, token, sizeof(sym_name) - 1);

        // 심볼 이름과 주소 출력
        printf("0x%lx: %s\n", symbol_addr, sym_name);
    }

    pclose(pipe);

    return 0;
}
