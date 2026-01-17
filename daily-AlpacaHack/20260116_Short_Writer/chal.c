// gcc -o chal main.c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
** How to get the address of `win` **

  $ nm chal | grep win
  XXXXXXXXX

*/

void win() {
    execve("/bin/sh", NULL, NULL);
}

int main(void) {
    short shorts[100], pos;

    /* disable stdio buffering */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    printf("pos > ");
    scanf("%hd", &pos);
    if (pos >= 100) {
        puts("You're a hacker!");
        return 1;
    }
    printf("val > ");
    scanf("%hd", &shorts[pos]);

    return 0;
}

