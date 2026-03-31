#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>

char flag[0x40];

int main(void) {
    FILE *f_ptr = fopen("flag.txt","r");
    if (f_ptr == NULL) {
        puts("open flag.txt failed. please open a ticket"); 
        exit(1);
    }
    fseek(f_ptr,0,SEEK_END);
    long f_sz = ftell(f_ptr);
    assert(f_sz < 0x40);
    fseek(f_ptr,0,SEEK_SET);
    fgets(flag,sizeof(flag),f_ptr);
    printf("flag @ %p\n",flag);

    char buf[0x10];
    fgets(buf,sizeof(buf),stdin);
    printf(buf);
}

__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}

