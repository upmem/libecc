#include "dpu_jump.h"
#include <mram.h>

#pragma clang section text=".text_last"

void dpu_jump(uint32_t app_data , int app_data_size, uint32_t app_text, int app_text_size){
    uint32_t iram_start = (uint32_t) 0;
    uint32_t iram_addr = (uint32_t) 0;
    uint32_t wram_addr = (uint32_t) 0;
    uint32_t mram_addr = app_data;
    int size = app_data_size;
    /* Load application data - data section is multiple of 8 bytes thanks to linker
     *   Not working with mram_read
    */
    //mram_read((__mram_ptr void *)app_data, 0, app_data_size);
    while (size) {
        /* Write batch of (64 * 1) bits */
        __asm volatile("ldma %[wram_addr], %[mram_addr], 0" ::  [wram_addr] "r" (wram_addr), [mram_addr] "r" (mram_addr));
        wram_addr +=8;
        mram_addr +=8;
        size -=8;
    }
    mram_addr = app_text;
    size = app_text_size;
    /* Load application code - text is multiple of 32 bytes thanks to linker*/
    while (app_text_size) {
        /* Write batch of (64 * 4) bits */
        __asm volatile("ldmai %[iram_addr], %[mram_addr], 3" ::  [iram_addr] "r" (iram_addr), [mram_addr] "r" (mram_addr));
        iram_addr +=32;
        mram_addr +=32;
        app_text_size -=32;
    }
    __asm volatile("jump  %[iram_start]" ::[iram_start] "r" (iram_start));
}
