#include "print.h"
#include "libsig.h"
#include <stdio.h>

#include <stdbool.h>
#include <stdint.h>

#include <mram.h>

extern __mram_ptr void *__sys_sec_mram_start;
#define CACHE_SIZE 8

int main (void){
    char string [CACHE_SIZE*2] = "Hello word!!\0";
    mram_write(string, __sys_sec_mram_start, CACHE_SIZE);
    mram_write(&string[CACHE_SIZE], (__mram_ptr void *)((uint32_t)__sys_sec_mram_start + CACHE_SIZE), CACHE_SIZE);
    return 0;
}

