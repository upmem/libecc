HOST_CC = gcc
DPU_CC = dpu-upmem-dpurte-clang
DPU_OBJCPY = llvm-objcopy
DPU_OBJDUMP = llvm-objdump


ROOT_DIR=../..
BUILD_DIR=$(ROOT_DIR)/build
include $(ROOT_DIR)/common.mk

CFLAGS += -I$(ROOT_DIR)/src/ -I$(ROOT_DIR)/src/external_deps

WARNING_CFLAGS ?= -Wall -Wextra
HOST_LDFLAGS = `dpu-pkg-config --libs dpu`
HOST_CFLAGS = $(WARNING_CFLAGS) -std=c11 `dpu-pkg-config --cflags dpu` -O2
ifdef SIG_KO
HOST_CFLAGS += -DSIG_KO
endif
BIN_LDFLAGS += -Wl,-Tdpu.lds

all:	dpu  host app
ifeq ($(WITH_DYNAMIC_LIBS),1)
# If the user asked for dynamic libraries, compile versions of our binaries against them
all:	nn_example_dyn fp_example_dyn curve_basic_examples_dyn curve_ecdh_dyn
endif

dpu:
	$(DPU_CC) $(BIN_CFLAGS) ecdsa_dpu.c $(ROOT_DIR)/src/external_deps/rand.c dpu_jump.c  $(LIBSIGN) $(BIN_LDFLAGS) -o ecdsa_dpu
	$(DPU_OBJDUMP) -xS  ecdsa_dpu > ecdsa_dpu.objdump

host:
	$(HOST_CC) $(HOST_CFLAGS) ecdsa_host.c $(HOST_LDFLAGS) -o ecdsa_host

app:
	$(DPU_CC) $(BIN_CFLAGS) hello_word.c $(BIN_LDFLAGS) -o hello_word_dpu
	$(DPU_OBJCPY) -O binary --only-section=.text hello_word_dpu hello_word_dpu.text
	$(DPU_OBJCPY) -O binary --only-section=.data hello_word_dpu hello_word_dpu.data

clean:
	@rm -f ecdsa_dpu  ecdsa_dpu.objdump ecdsa_host  hello_word_dpu  hello_word_dpu.text hello_word_dpu.data

.PHONY: all clean
