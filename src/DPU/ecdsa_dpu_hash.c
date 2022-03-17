#include "libsig.h"
#include <stdio.h>
#include <string.h>

#include <mram.h>
#include "ecdsa.h"

__mram_noinit mram_t mram;

int main (void){
    __dma_aligned uint8_t out_hash[SHA256_SIZE];
    sha256((const u8 *)(uint32_t) mram.app_text, mram.app_text_size, (u8 *)out_hash);
    mram_write(out_hash, mram.hash, SHA256_SIZE);
    return 0;
}
