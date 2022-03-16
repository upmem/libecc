#include "dpu_jump.h"
#include <mram.h>

extern void *__sys_dpu_iram_start;
extern void *__sys_dpu_wram_start;

#pragma clang section text=".text_last"

void dpu_jump(uint32_t app_data , int app_data_size, uint32_t app_text, int app_text_size){
    uint32_t iram_start = (uint32_t) __sys_dpu_iram_start;
    uint32_t iram_addr = (uint32_t) __sys_dpu_iram_start;
    uint32_t mram_addr = (uint32_t) app_text;
    /* Load application data */
    mram_read((__mram_ptr void *)app_data, __sys_dpu_wram_start, MRAM_TRANSFER_SIZE(app_data_size));
    /* Load application code */
    for (int i=0; i < app_text_size; i++){
        __asm volatile("ldmai %[iram_addr], %[mram_addr], 8" ::  [iram_addr] "r" (iram_addr), [mram_addr] "r" (mram_addr));
        iram_addr +=8;
        mram_addr +=8;
    }
     __asm volatile("jump  %[iram_start]" ::[iram_start] "r" (iram_start));
}
