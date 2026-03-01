// gcc -o chal main.c -no-pie -fno-stack-protector

#include <stdio.h>
#include <string.h>
#include <unistd.h>

void win() {
    execve("/bin/sh",NULL,NULL);
}

void ask_room_number() {
    long age;
    printf("Input your room number> ");
    scanf("%ld",age);
    printf("Ok! I'll visit your room!");
}

void show_welcome() {
    char name[0x20];
    printf("Input your name> ");
    fgets(name,sizeof(name),stdin);
    printf("Welcome! %s",name);
}

int main(void) {
    /* disable stdio buffering */
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    show_welcome();
    ask_room_number();

    return 0;
}

