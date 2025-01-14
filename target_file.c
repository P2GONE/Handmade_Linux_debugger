// test.c
#include <stdio.h>

int input_func(){
        long  v1;
        if ( (unsigned int)__isoc99_scanf("%ld", &v1) != 1 )
                _exit(1);
        return v1;
}
// 현재 RIP 주소를 출력하는 함수
void leak_rip() {
    void* rip;
    __asm__ volatile (
        "call 1f\n"    // 라벨 1로 호출, RIP 값을 스택에 푸시
        "1: pop %0\n"   // 라벨 1의 주소를 rip 변수에 팝
        : "=r"(rip)      // 출력 피연산자
        :                // 입력 피연산자 없음
        : "memory"       // 클로버드 레지스터
    );
    printf("Current RIP: %p\n", rip);
}

int input_num()
{
    char s[80];
    //suspicious 
    if(scanf("%80s", s) !=1)
        exit(1);
    return puts(s);
}

int main() {
    printf("Leaking RIP address...\n");
    leak_rip();
    input_func();
    input_num();
    return 0;
}
