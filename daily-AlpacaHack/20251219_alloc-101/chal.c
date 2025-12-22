// gcc chal.c -o chal

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

char *item;

void menu() {
    puts("1. allocate");
    puts("2. free");
    puts("3. read");
    puts("4. allocate flag");
}

int main(void) {
    FILE *f_ptr = fopen("flag.txt","r");
    if (f_ptr == NULL) {
        puts("open flag.txt failed. please open a ticket"); 
        exit(1);
    }
    fseek(f_ptr,0,SEEK_END);
    long f_sz = ftell(f_ptr);
    printf("file information: %ld bytes\n",f_sz);
    fseek(f_ptr,0,SEEK_SET);
    menu();
    while(1) {
        int choice;
        printf("choice> ");
        scanf("%d%*c",&choice);
        switch(choice) {
            case 1: {
                printf("size> ");
                int size;
                scanf("%d%*c",&size);
                item = malloc(size);
                printf("[DEBUG] item: %p\n",item);
            }
            break;
            case 2: {
                assert(item != NULL);
                free(item);
                //item == NULL;
            }
            break;
            case 3: {
                assert(item != NULL);
                puts(item);
            }
            break;
            case 4: {
                char *flag = malloc(f_sz);
                printf("[DEBUG] flag: %p\n",flag);
                fgets(flag,f_sz,f_ptr);
            }
            break;
            default: {
                exit(0);
            }
        }
    }
}

__attribute__((constructor))
void setup() {
    setbuf(stdin,NULL);
    setbuf(stdout,NULL);
}

