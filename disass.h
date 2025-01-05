// disassemble.h
#ifndef DISASSEMBLE_H
#define DISASSEMBLE_H

#include <stdint.h>
#include <stddef.h>

// 디스어셈블 함수
// prog_path: 디스어셈블할 프로그램의 경로
// addr: 디스어셈블을 시작할 주소
// count: 디스어셈블할 명령어의 개수
void disassemble(const char* prog_path, uintptr_t addr, size_t count);


#endif // DISASSEMBLE_H
