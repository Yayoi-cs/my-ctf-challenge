// gcc chal.c -o chal -no-pie

#include <stdio.h>
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <string.h>

#define PASSWD "ALPACAPA\n"

char name[0x10];
char passwd[0x10];
struct iovec iov;

void win() {
    execve("/bin/sh", NULL, NULL);
}

int main() {
    iov.iov_base = passwd;
    iov.iov_len = sizeof(passwd);
    fgets(name,0x28,stdin);
    readv(STDIN_FILENO,&iov,1);
    if (strcmp(passwd, PASSWD) == 0) {
        printf("Welcome! %s\n",name);
    } else {
        printf("Wait a minute, who are you?\n");
    }
}

__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}

