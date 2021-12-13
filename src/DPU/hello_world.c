#include <stdint.h>
#include <mram.h>

extern __mram_ptr void *__sys_sec_mram_start;

#define MRAM_BLOCK_SIZE (8)

int main (void){
    char string [MRAM_BLOCK_SIZE*2] = "Hello world!!\0";
    mram_write(string, __sys_sec_mram_start, MRAM_BLOCK_SIZE);
    /* Looks that doing two writes is more stable */
    mram_write(&string[MRAM_BLOCK_SIZE], (__mram_ptr void *)((uint32_t)__sys_sec_mram_start +  MRAM_BLOCK_SIZE), MRAM_BLOCK_SIZE);
    return 0;
}
