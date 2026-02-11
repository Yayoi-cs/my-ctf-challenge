#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#define MAX_N_ANIMAL 0x40

long animal_numbers[MAX_N_ANIMAL];

void handler() {
    execve("/bin/sh",NULL,NULL);
}

int main(void) {
    signal(SIGSEGV, handler);
    unsigned alpaca, llama, i;
    puts("Input the number of alpaca.");
    scanf("%u%*c",&alpaca);
    puts("Input the number of llama.");
    scanf("%u%*c",&llama);
    if (alpaca+llama > MAX_N_ANIMAL) {
        puts("Hmm....");
        exit(1);
    }
    i=0;
    while(i<alpaca) {
        printf("Question %u(Alpaca): Input the identity number.",i);
        scanf("%ld%*c",&animal_numbers[i++]);
    }
    while(i<alpaca+llama) {
        printf("Question %u(Llama): Input the identity number.",i);
        scanf("%ld%*c",&animal_numbers[i++]);
    }
    puts("Thanks for the information!");
    return 0;
}

__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}
