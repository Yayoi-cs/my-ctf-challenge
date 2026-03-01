// gcc -DNDEBUG -o chal main.c -no-pie
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

void win() {
    execve("/bin/sh", NULL, NULL);
}

void safe() {
    unsigned num[100], pos;
    printf("pos > ");
    scanf("%u", &pos);
    assert(pos<100);
    printf("val > ");
    scanf("%u", &num[pos]);
}

int main(void) {
    /* disable stdio buffering */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    safe();

    return 0;
}

