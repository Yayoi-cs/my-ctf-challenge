// gcc chal.c -o chal
#include <stdio.h>

char buf[0x10];
void vuln() {
    fgets(buf,sizeof(buf),stdin);
    printf(buf);
}

int main(void) {
    while(1) {
        vuln();
    }
}

__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}