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
#include "user_sig_data.h"
#include "pim.h"
#define __dma_aligned __attribute__((aligned(8)))
#include "ecdsa.h"


#define DPU_CLUSTER_MEMORY_SIZE (64U<<20)

#define DPU_BINARY_ECDSA "./ecdsa_dpu"
#define DPU_BINARY_HASH "./ecdsa_dpu_hash"
#define APP_TEXT_BINARY "./hello_world_dpu.text"
#define APP_DATA_BINARY "./hello_world_dpu.data"

extern int usleep (__useconds_t __useconds);


static void prepare_data(mram_t *area)
{
    int fdbin;
    area->dpu_policy = DPU_POLICY_VERIFY_AND_JUMP;
    /* Copying signature data */
    memcpy(area->sig_data, public_key, sizeof(public_key));
    //memcpy(&area->sig_data[sizeof(public_key)], calculated_hash, sizeof(calculated_hash));
    memcpy(&area->sig_data[sizeof(public_key) + sizeof(calculated_hash)], signature, sizeof(signature));
#ifdef SIG_KO
    memset(&area->sig_data[sizeof(public_key) + sizeof(calculated_hash)], 0, 1);
#endif

    /* Copying user application code */
    fdbin = open(APP_TEXT_BINARY,O_RDONLY);
    area->app_text_size = read(fdbin, area->app_text, APP_MAX_SIZE);
    close(fdbin);
    /* Copying user application data */
    fdbin = open(APP_DATA_BINARY,O_RDONLY);
    area->app_data_size = read(fdbin, area->app_data, APP_MAX_SIZE);
    close(fdbin);
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
    mram_t *area1, *area2;
    pim_params_t params;
    int retval;
    int fdpu, fdbin, readb;

    // Open pim node
    fdpu = open("/dev/pim", O_RDWR);
    if (fdpu < 0) {
        perror("Failed to open /dev/pim device node");
        exit(EXIT_FAILURE);
    }

    // Try to get magic memory
    void *va = mmap(NULL, DPU_CLUSTER_MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fdpu, 0);
    if (va == MAP_FAILED ) {
        perror("Failed to get DPU memory");
        exit(EXIT_FAILURE);
    } else {
        area1 = (mram_t*)(va);
        area2 = (mram_t*)((unsigned long)va+(DPU_CLUSTER_MEMORY_SIZE/2));
        prepare_data(area1);
        prepare_data(area2);
    }

    // Copy DPU HASH program to MRAM
    fdbin = open(DPU_BINARY_HASH,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open DPU_BINARY_HASH");
        exit(EXIT_FAILURE);
    }

    readb = read(fdbin, area1->code, (DPU_CLUSTER_MEMORY_SIZE/2));
    if (readb == 0) {
        perror("DPU_BINARY_HASH is empty");
        exit(EXIT_FAILURE);
    }
    lseek(fdbin, 0, SEEK_SET);
    read(fdbin, area2->code, readb);
    close(fdbin);

    // Load and run DPU program
    params.arg1 = (uint64_t)(area1->code);
    params.arg2 = (uint64_t)(area2->code);
    retval = ioctl(fdpu, PIM_IOCTL_LOAD_DPU, &params);
    if (retval < 0 ) {
        perror("Failed to control pim");
        exit(EXIT_FAILURE);
    } else {
        printf("Dpu load returned %ld\n", params.ret0);
    }

    // Poll DPU1
    do {
        params.arg1 = (uint64_t)area1;
        retval = ioctl(fdpu, PIM_IOCTL_GET_DPU_STATUS, &params);
        if (retval !=0 ) {
            perror("Failed to poll pim");
            break;
        }
    } while (params.ret1 == 1);
    printf("Dpu %p status is %ld %ld\n", area1, params.ret0, params.ret1);

    // Poll DPU2
    do {
        params.arg1 = (uint64_t)area2;
        retval = ioctl(fdpu, PIM_IOCTL_GET_DPU_STATUS, &params);
        if ( retval != 0 ) {
            perror("Failed to poll pim");
            break;
        }
    } while (params.ret1 == 1);
    printf("Dpu %p status is %ld %ld\n", area2, params.ret0, params.ret1);

    if (memcmp(&area1->sig_data[P256_PUB_KEY_SIZE], calculated_hash, sizeof(calculated_hash)) !=0 ){
        printf("#### Error DPU hash doesn't match the expected value\n");
    } else {
        printf("#### DPU hash all good!\n");
    }
    printf("debug_1 0x%lx debug_2 0x%lx debug_3 0x%lx \n", area1->debug_1, area1->debug_2, area1->debug_3);

    // Copy DPU ECDSA program to MRAM
    fdbin = open(DPU_BINARY_ECDSA,O_RDONLY);
    if (fdbin < 0) {
        perror("Failed to open DPU_BINARY_ECDSA");
        exit(EXIT_FAILURE);
    }

    readb = read(fdbin, area1->code, (DPU_CLUSTER_MEMORY_SIZE/2));
    if (readb == 0) {
        perror("DPU_BINARY_ECDSA is empty");
        exit(EXIT_FAILURE);
    }
    lseek(fdbin, 0, SEEK_SET);
    read(fdbin, area2->code, readb);
    close(fdbin);

    // Load and run DPU program
    params.arg1 = (uint64_t)(area1->code);
    params.arg2 = (uint64_t)(area2->code);
    retval = ioctl(fdpu, PIM_IOCTL_LOAD_DPU, &params);
    if (retval < 0 ) {
        perror("Failed to control pim");
        exit(EXIT_FAILURE);
    } else {
        printf("Dpu load returned %ld\n", params.ret0);
    }

    // Poll DPU1
    do {
        params.arg1 = (uint64_t)area1;
        retval = ioctl(fdpu, PIM_IOCTL_GET_DPU_STATUS, &params);
        if (retval !=0 ) {
            perror("Failed to poll pim");
            break;
        }
    } while (params.ret1 == 1);
    printf("Dpu %p status is %ld %ld\n", area1, params.ret0, params.ret1);

    // Poll DPU2
    do {
        params.arg1 = (uint64_t)area2;
        retval = ioctl(fdpu, PIM_IOCTL_GET_DPU_STATUS, &params);
        if ( retval != 0 ) {
            perror("Failed to poll pim");
            break;
        }
    } while (params.ret1 == 1);
    printf("Dpu %p status is %ld %ld\n", area2, params.ret0, params.ret1);

    print_secure(fdpu);
    printf("Verification status %ld %ld\n", area1->verification_status, area2->verification_status);
    // Exit gracefully
    close(fdpu);
    exit(EXIT_SUCCESS);
}
