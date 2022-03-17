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


static void load_sign_data(mram_t *area)
{
    int fdbin;
#ifdef VERIFY_ONLY
    area->dpu_policy = DPU_POLICY_VERIFY_ONLY;
#else
    area->dpu_policy = DPU_POLICY_VERIFY_AND_JUMP;
#endif
    /* Copying signature data */
    memcpy(area->pub_key, public_key, sizeof(public_key));
    /* Hash is calculated and copied by the dedicated DPU application */
    memcpy(area->signature, signature, sizeof(signature));
#ifdef SIG_KO
    memset(area->signature, 0, 1);
#endif

    /* Copying user application (Hello World) code */
    fdbin = open(APP_TEXT_BINARY,O_RDONLY);
    area->app_text_size = read(fdbin, area->app_text, APP_MAX_SIZE);
    close(fdbin);
    /* Copying user application (Hello World) data */
    fdbin = open(APP_DATA_BINARY,O_RDONLY);
    area->app_data_size = read(fdbin, area->app_data, APP_MAX_SIZE);
    close(fdbin);
}

static void print_secure(int fdpim)
{
    printf("======================= Display secure memory =======================\n");
    fflush(stdout);
    usleep(20000);
    if (ioctl(fdpim, PIM_IOCTL_SHOW_S_MRAM, NULL) != 0) {
        printf("Failed to call TEE\n");
    }
    printf("=====================================================================\n");
    fflush(stdout);
}

static int dpu_pair_run (int fdpim, const char *dpu_bin, void *dpu0_code_ptr, void *dpu1_code_ptr) {
    int fdbin, byte_num;
    pim_params_t params;
    int status = -1;
    do {
        /* Copy DPU application elf to MRAM */
        fdbin = open(dpu_bin, O_RDONLY);
        if (fdbin < 0) {
            perror("Failed to open DPU_BINARY");
            break;
        }
        byte_num = read(fdbin, dpu0_code_ptr, (DPU_CLUSTER_MEMORY_SIZE/2));
        if (byte_num == 0) {
            perror("DPU_BINARY is empty");
            break;
        }
        lseek(fdbin, 0, SEEK_SET);
        read(fdbin, dpu1_code_ptr, byte_num);
        close(fdbin);

        /* Load and run DPU program */
        params.arg1 = (uint64_t)(dpu0_code_ptr);
        params.arg2 = (uint64_t)(dpu1_code_ptr);
        if (ioctl(fdpim, PIM_IOCTL_LOAD_DPU, &params) < 0 ) {
            perror("Failed to control pim");
            break;
        }

        /* Poll DPU0 */
        do {
            params.arg1 = (uint64_t)dpu0_code_ptr;
            if (ioctl(fdpim, PIM_IOCTL_GET_DPU_STATUS, &params) !=0 ) {
                perror("Failed to poll pim");
                break;
            }
        } while (params.ret1 == 1);
        if (params.ret1 != 0) {
            printf("Polling returned %ld %ld", params.ret0, params.ret1);
            break;
        }

        /* Poll DPU1 */
        do {
            params.arg1 = (uint64_t)dpu1_code_ptr;
            if (ioctl(fdpim, PIM_IOCTL_GET_DPU_STATUS, &params) != 0 ) {
                perror("Failed to poll pim");
                break;
            }
        } while (params.ret1 == 1);
        if (params.ret1 != 0) {
            printf("Polling returned %ld %ld", params.ret0, params.ret1);
            break;
        }

        status = 0;

    } while (0);
    return status;
}

int main(void)
{
    mram_t *dpu0_mram, *dpu1_mram;
    int fdpim;
    int status = EXIT_FAILURE;
    /* Open pim node */
    fdpim = open("/dev/pim", O_RDWR);
    do {
        if (fdpim < 0) {
            perror("Failed to open /dev/pim device node");
            break;
        }

        /* Try to get magic memory */
        void *va = mmap(NULL, DPU_CLUSTER_MEMORY_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED, fdpim, 0);
        if (va == MAP_FAILED ) {
            perror("Failed to get DPU memory");
            break;
        }

        dpu0_mram = (mram_t*)(va);
        dpu1_mram = (mram_t*)((unsigned long)va+(DPU_CLUSTER_MEMORY_SIZE/2));
        /* load signature and public key in MRAM */
        load_sign_data(dpu0_mram);
        load_sign_data(dpu1_mram);

        /* Offload SHA256 calculation to DPUs */
        if (dpu_pair_run(fdpim, DPU_BINARY_HASH, dpu0_mram->code, dpu1_mram->code) != 0) {
            break;
        }
        /* Check hash value against expected value */
        if (
            (memcmp(dpu0_mram->hash, calculated_hash, sizeof(calculated_hash)) !=0) ||
            (memcmp(dpu1_mram->hash, calculated_hash, sizeof(calculated_hash)) !=0)
        ) {
            printf("#### Error DPU hash doesn't match the expected value\n");
            break;
        }
        printf("#### SHA256 all good!\n");


        /* Offload ECDSA P-256 signature verification to DPUs */
        if (dpu_pair_run(fdpim, DPU_BINARY_ECDSA, dpu0_mram->code, dpu1_mram->code) != 0) {
            break;
        }
        /* check verification status */
        if (
            (dpu0_mram->verification_status != 0) ||
            (dpu1_mram->verification_status != 0)
        ) {
            printf("#### ECDSA P-256 signature verification failed, %ld %ld\n", dpu0_mram->verification_status, dpu1_mram->verification_status);
            break;
        }
        printf("#### ECDSA P-256 signature verification all good!\n");

        /* print secure MRAM content */
        print_secure(fdpim);
        status = EXIT_SUCCESS;

    } while(0);

    /* Exit gracefully */
    close(fdpim);
    exit(status);
}
