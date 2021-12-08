#ifndef __DPU_JUMP_H__
#define __DPU_JUMP_H__
#include <stdint.h>

void dpu_jump(uint32_t app_data , int app_data_size, uint32_t app_text, int app_text_size);
#endif // __DPU_JUMP_H__
