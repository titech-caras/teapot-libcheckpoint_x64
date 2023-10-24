#pragma once

#include <stdint.h>
#include <stdbool.h>

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define MEM_HISTORY_LEN 1024
#define SCRATCHPAD_SIZE 1048576
#define MAX_CHECKPOINTS 1

#define SCRATCHPAD_TOP "scratchpad+" STR(SCRATCHPAD_SIZE - 8)

#define SWITCH_TO_SCRATCHPAD_STACK "mov %rsp, old_rsp\n" "lea " SCRATCHPAD_TOP ", %rsp\n"
#define SWITCH_TO_ORIGINAL_STACK "mov old_rsp, %rsp\n"

typedef struct memory_history {
    void *addr;
    uint64_t data;
} memory_history_t;

typedef struct general_register_state {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15;
    uint64_t flags;
} general_register_state_t;

typedef __attribute__((aligned(256))) struct checkpoint_metadata {
    // Size must be kept at 32 * 8 bytes
    general_register_state_t registers;
    uint64_t instruction_cnt;
    memory_history_t *memory_history_top;
    uint64_t return_address;

    uint64_t alignment[12];
} checkpoint_metadata_t;

typedef __attribute__((aligned(64))) struct xsave_area {
    // Let's just give XSAVE more than enough room...
    char data[2048];
} xsave_area_t;

typedef __attribute__((aligned(16))) uint8_t scratchpad_t[SCRATCHPAD_SIZE];

#define ROLLBACK_ROB_LEN 0
#define ROLLBACK_ASAN 1
#define ROLLBACK_SIGSEGV 2
#define ROLLBACK_EXT_LIB 3
#define ROLLBACK_MALFORMED_INDIRECT_BR 4

extern scratchpad_t scratchpad;
extern checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
extern uint64_t checkpoint_cnt;

__attribute__((preserve_most)) void libcheckpoint_enable();
__attribute__((preserve_most)) void libcheckpoint_disable();

void make_checkpoint();
void add_instruction_counter_check_restore();
void restore_checkpoint(int type);
void restore_checkpoint_registers();
