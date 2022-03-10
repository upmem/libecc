#ifndef __DPU_JUMP_H__
#define __DPU_JUMP_H__
#include <stdint.h>
#define MRAM_BLOCK_SIZE (8)
#define MRAM_TRANSFER_SIZE(size) (size + ((MRAM_BLOCK_SIZE - (size % MRAM_BLOCK_SIZE))%MRAM_BLOCK_SIZE))

void dpu_jump(uint32_t app_data , int app_data_size, uint32_t app_text, int app_text_size);
#endif // __DPU_JUMP_H__
