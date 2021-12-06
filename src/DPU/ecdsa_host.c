#include <assert.h>
#include <stdio.h>

#include <dpu.h>
#include <dpu_management.h>
#include <assert.h>
#include <fcntl.h>
#include <linux/mman.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <alloca.h>

#include "pim.h"


#ifndef DPU_BINARY
#define DPU_BINARY "./ecdsa_dpu"
#endif

const uint8_t public_key[] = {
    0xd8, 0x14, 0x7d, 0x49, 0xe0, 0x7c, 0x32, 0x66,
	0x59, 0x8b, 0x85, 0xd6, 0x61, 0x50, 0xda, 0xc3,
	0x0d, 0x7b, 0x38, 0xe4, 0x3c, 0xc9, 0x40, 0x58,
	0x23, 0x50, 0x1c, 0x70, 0x91, 0xdb, 0x86, 0x1c,
	0x0e, 0x98, 0x17, 0xdf, 0x71, 0x76, 0x91, 0xed,
	0x83, 0x3d, 0xe6, 0x1b, 0x7b, 0x64, 0xc9, 0x77,
	0xb8, 0xf8, 0x37, 0xc2, 0xc1, 0x0a, 0xdf, 0xd9,
	0xf3, 0x83, 0xce, 0x78, 0xc7, 0xf7, 0x89, 0x78
};


/* SHA-256 of "abc" msg */
const uint8_t calculated_hash[] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

#ifndef SIG_KO
static const uint8_t signature_ok[] =
{
    0x9b, 0x19, 0xcf, 0x16, 0xee, 0xa0, 0x0f, 0x03,  0xde, 0x7b, 0x59, 0x14, 0xa4, 0x4c, 0x9f, 0xad,
    0xe7, 0x7e, 0xf9, 0x9d, 0x2e, 0x78, 0x23, 0xf5,  0x63, 0xda, 0x75, 0xac, 0x1b, 0x15, 0x50, 0x28,
    0x00, 0xb8, 0x78, 0x72, 0x28, 0x22, 0xdd, 0x56,  0xd2, 0x14, 0xe9, 0x36, 0x92, 0xca, 0x58, 0x71,
    0x73, 0xe8, 0xaa, 0x2d, 0x8d, 0x6c, 0xfe, 0x9c,  0x1d, 0x91, 0xa3, 0xb5, 0x4b, 0x6f, 0xf4, 0x83
};
#else
/* last byte modified */
static const uint8_t signature_ko[] =
{
    0x9b, 0x19, 0xcf, 0x16, 0xee, 0xa0, 0x0f, 0x03,  0xde, 0x7b, 0x59, 0x14, 0xa4, 0x4c, 0x9f, 0xad,
    0xe7, 0x7e, 0xf9, 0x9d, 0x2e, 0x78, 0x23, 0xf5,  0x63, 0xda, 0x75, 0xac, 0x1b, 0x15, 0x50, 0x28,
    0x00, 0xb8, 0x78, 0x72, 0x28, 0x22, 0xdd, 0x56,  0xd2, 0x14, 0xe9, 0x36, 0x92, 0xca, 0x58, 0x71,
    0x73, 0xe8, 0xaa, 0x2d, 0x8d, 0x6c, 0xfe, 0x9c,  0x1d, 0x91, 0xa3, 0xb5, 0x4b, 0x6f, 0xf4, 0x81
};
#endif

extern int usleep (__useconds_t __useconds);

#define __dma_aligned __attribute__((aligned(8)))

#define DATA_SIZE ((256/8)*5)
#define MAX_STRING_SIZE 128

typedef struct {
	unsigned int string_size;
	uint8_t		 data[MAX_STRING_SIZE] __dma_aligned;
	uint8_t		 shared_data[DATA_SIZE] __dma_aligned;
	int64_t 	 ret;__dma_aligned
	uint8_t		 code[] __dma_aligned;
} mram_t;

static void prepare_data(mram_t *area)
{
	area->string_size = 1 + snprintf(area->data, MAX_STRING_SIZE, "%s: DPU mram mapped @%p", __TIME__, area);
	memcpy(area->shared_data, public_key, sizeof(public_key));
	memcpy(&area->shared_data[sizeof(public_key)], calculated_hash, sizeof(calculated_hash));
#ifndef SIG_KO
	memcpy(&area->shared_data[sizeof(public_key) + sizeof(calculated_hash)], signature_ok, sizeof(signature_ok));
#else
	memcpy(&area->shared_data[sizeof(public_key) + sizeof(calculated_hash)], signature_ko, sizeof(signature_ko));
#endif
	area->ret = ~0;
}

static void print_secure(int fd)
{
    printf("======================= Display secure memory =======================\n");
    fflush(stdout);
    usleep(20000);
    if (ioctl(fd, PIM_IOCTL_SHOW_S_MRAM, NULL) != 0) {
        printf("Failed to call TEE\n");
    }
    printf("=====================================================================\n");
    fflush(stdout);
}

int main(void)
{
    //struct dpu_set_t set;
	mram_t *area1, *area2;
	//unsigned int offset = 0;
	//int dpu_id;
	pim_params_t params;
	int retval;
	int fdpu;
	int rankid;
	int dpuid;

	fdpu = open("/dev/pim", O_RDWR);
	if (fdpu < 0) {
		perror("Failed to open DPU device node");
		exit(EXIT_FAILURE);
	}

	// Try to get magic memory
	void * va = mmap(NULL, 64U<<20, PROT_READ|PROT_WRITE, MAP_SHARED, fdpu, 0);
	if ( va == MAP_FAILED ) perror("failed to get DPU memory");
	else {
		area1 = (mram_t*)(va);
		area2 = (mram_t*)((unsigned long)va+(32U<<20));
		prepare_data(area1);
		prepare_data(area2);
	}

	// Copy DPU program to MRAM
	int fdbin = open(DPU_BINARY,O_RDONLY);
	int readb = read(fdbin, area1->code, 32U<<20);
	if ( readb ) {
		lseek(fdbin, 0, SEEK_SET);
		read(fdbin, area2->code, readb);
	}
	close(fdbin);
	printf("are1->ret %ld\n", area1->ret);
	printf("are2->ret %ld\n", area2->ret);

    // Load and run DPU program
	params.arg1 = (uint64_t)(area1->code);
	params.arg2 = (uint64_t)(area2->code);
	retval = readb ? ioctl(fdpu, PIM_IOCTL_LOAD_DPU, &params) : -1;
	if ( retval < 0 ) {
		perror("Failed to control pim");
	} else {
		printf("Dpu load returned %ld\n", params.ret0);
	}

	sleep(20);
	// Poll DPU1
	params.arg1 = (uint64_t)area1;
	retval = ioctl(fdpu, PIM_IOCTL_GET_DPU_STATUS, &params);
	if ( retval < 0 ) {
		perror("Failed to poll pim");
	} else {
		printf("Dpu %p status is %ld %ld\n", area1, params.ret0, params.ret1);
	}

	// Naive test for MRAM mux control
	params.arg1 = (uint64_t)area1;
	retval = ioctl(fdpu, PIM_IOCTL_GET_DPU_MRAM, &params);
	if ( retval < 0 ) {
		perror("Failed to get mram");
	} else {
		printf("Dpu %p unmuxed its MRAM\n", area1);
	}
	printf("are1->ret %ld\n", area1->ret);


	// Poll DPU2
	params.arg1 = (uint64_t)area2;
	retval = ioctl(fdpu, PIM_IOCTL_GET_DPU_STATUS, &params);
	if ( retval < 0 ) {
		perror("Failed to poll pim");
	} else {
		printf("Dpu %p status is %ld %ld\n", area2, params.ret0, params.ret1);
	}

	printf("are2->ret %ld\n", area2->ret);

	print_secure(fdpu);

	// Exit gracefully
	close(fdpu);
    exit(EXIT_SUCCESS);
}