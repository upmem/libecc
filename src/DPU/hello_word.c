#include <stdint.h>
#include <mram.h>

extern __mram_ptr void *__sys_sec_mram_start;

#define MRAM_BLOCK_SIZE (8)

int main (void){
    char string [MRAM_BLOCK_SIZE*2] = "Hello word!!\0";
    mram_write(string, __sys_sec_mram_start, sizeof(string));
    return 0;
}
