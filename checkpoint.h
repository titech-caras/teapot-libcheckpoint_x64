#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "config.h"
#include "dift_support.h"

//==========config===========
#define VERBOSE
//#define VERBOSE_DBGINFO
#define COVERAGE
#define TIME
//===========================


#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define MEM_HISTORY_LEN 1024
#define GUARD_LIST_LEN 300
#define SCRATCHPAD_SIZE 1048576

#if defined(SPECFUZZ_PRIORITIZED_SIMULATION) || defined(BRANCH_FULL_EXEC_COUNT)
#define USE_BRANCH_EXEC_COUNT
#endif

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

    dift_tag_t dift_reg_tags[DIFT_REG_TAGS_SIZE];

    uint32_t *guard_list_top;

    uint64_t alignment[5];
} checkpoint_metadata_t;

typedef struct statistics {
    struct {
        uint64_t normal_time, spec_time, ckpt_time, rstr_time;
    } rdtsc_runtime;

    uint64_t total_ckpt;
    uint64_t ckpt_depth[MAX_CHECKPOINTS];
    uint64_t rollback_reason[5];

    uint64_t total_bug;
    uint64_t bug_type[100];
} statistics_t;

typedef __attribute__((aligned(64))) struct xsave_area {
    // Let's just give XSAVE more than enough room...
    char data[2048];
} xsave_area_t;

typedef __attribute__((aligned(16))) uint8_t scratchpad_t[SCRATCHPAD_SIZE];

#define ROLLBACK_ROB_LEN 0
//#define ROLLBACK_ASAN 1
#define ROLLBACK_SIGSEGV 2
#define ROLLBACK_EXT_LIB 3
#define ROLLBACK_MALFORMED_INDIRECT_BR 4

/*#define GADGET_SPECFUZZ_ASAN_READ 1
#define GADGET_SPECFUZZ_ASAN_WRITE 3
#define GADGET_SIGSEGV 11
#define GADGET_SPECTAINT_BCB 21
#define GADGET_SPECTAINT_BCBS 22
*/
#define GADGET_KASPER_MDS 41
#define GADGET_KASPER_CACHE 42
#define GADGET_KASPER_PORT 43

extern scratchpad_t scratchpad;
extern checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
extern uint32_t guard_list[GUARD_LIST_LEN];
extern uint64_t checkpoint_cnt, instruction_cnt;
extern statistics_t simulation_statistics;
extern uint64_t last_rdtsc;

extern volatile bool in_restore_memlog;

__attribute__((preserve_most)) void libcheckpoint_enable(int argc, char **argv);
__attribute__((preserve_most)) void libcheckpoint_disable();

void make_checkpoint();
void add_instruction_counter_check_restore();
void restore_checkpoint(int type);
void restore_checkpoint_memlog();
void restore_checkpoint_registers();

__attribute__((naked)) void restore_checkpoint_SIGSEGV();
