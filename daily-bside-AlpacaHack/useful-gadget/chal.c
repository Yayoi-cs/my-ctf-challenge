// gcc chal.c -o chal -no-pie -fno-stack-protector

#include <stdio.h>

__asm__("pop %rax\nret\n");

int main(void) {
    char buf[0x20];
    puts("what's your name");
    fgets(buf, 0x48, stdin);
    return 0;
}

__attribute__((constructor)) void setup() {
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
}

