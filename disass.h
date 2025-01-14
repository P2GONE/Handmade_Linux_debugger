#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#include <stdint.h>
#include <stddef.h>

// 디스어셈블러 초기화 함수 (필요 시 구현)
int disassemble_init();

// objdump를 활용한 디스어셈블 함수
void disassemble_objdump(const char* exe_path, uintptr_t addr, size_t count);

// 디스어셈블러 종료 함수 (필요 시 구현)
void disassemble_cleanup();

#endif // DISASSEMBLE_H
