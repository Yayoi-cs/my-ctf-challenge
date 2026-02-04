#include <stdio.h>
#include <sys/mman.h>

int main(void) {
    void *addr = mmap(NULL, 0x100, PROT_WRITE|PROT_EXEC, 
                      MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    
    puts("Alpaca> ");
    fgets(addr, 0x100, stdin);
    
    ((void(*)())addr)();
    
    return 0;
}

__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}

