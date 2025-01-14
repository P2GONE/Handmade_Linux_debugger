#ifndef SYMBOL_H
#define SYMBOL_H

#include <stdint.h>

// 성공적으로 심볼 주소를 찾았을 때 반환되는 코드
#define SYMBOL_SUCCESS 0

// 심볼을 찾지 못했을 때 반환되는 코드
#define SYMBOL_NOT_FOUND -1

// 심볼 관련 함수 선언

/**
 * @brief 주어진 프로그램 경로와 심볼 이름을 기반으로 심볼의 메모리 주소를 찾습니다.
 *
 * @param exe_path 디버깅 대상 실행 파일의 경로
 * @param symbol_name 찾고자 하는 심볼의 이름
 * @param addr 심볼의 주소가 저장될 변수의 포인터
 * @return int SYMBOL_SUCCESS(0) 또는 SYMBOL_NOT_FOUND(-1)
 */
int get_symbol_address(const char* exe_path, const char* symbol_name, uintptr_t* addr);

/**
 * @brief 주어진 프로그램 경로의 모든 심볼을 출력합니다.
 *
 * @param exe_path 디버깅 대상 실행 파일의 경로
 * @return int 성공 시 0, 실패 시 -1
 */
int list_symbols(const char* exe_path);

#endif // SYMBOL_H
