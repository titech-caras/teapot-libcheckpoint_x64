#include "checkpoint.h"
#include "signal_handler.h"
#include "dift_support.h"

#include <stdio.h>
#include <assert.h>
#include <string.h>

#define COVERAGE

uint64_t PROTECTED_ZONE_START;

checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
xsave_area_t processor_extended_states[MAX_CHECKPOINTS];

memory_history_t memory_history[MEM_HISTORY_LEN];
memory_history_t *memory_history_top = &memory_history[0];
uint32_t guard_list[GUARD_LIST_LEN];
uint32_t *guard_list_top = &guard_list[0];

scratchpad_t scratchpad;
void *old_rsp, *scratchpad_rsp;

statistics_t simulation_statistics;

uint64_t checkpoint_cnt = 0;
uint64_t instruction_cnt = 0;
bool libcheckpoint_enabled = false;
volatile bool in_restore_memlog = false;

uint64_t PROTECTED_ZONE_END;

__attribute__((weak)) void __asan_init(void);

#ifdef COVERAGE
__attribute__((weak)) void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop);
__attribute__((weak)) void __sanitizer_cov_trace_pc_guard(uint32_t *guard);
extern uint32_t guard_start asm("__guard_start__NaHCO3__");
extern uint32_t guard_end asm("__guard_end__NaHCO3__");
#endif

void poison_protected_zone() {
    // Poison first page
    for (void *i = (void*)0; i < (void*)4096; i += 64 * 8) {
        *(uint64_t*)(0x7fff8000 + ((uint64_t)i >> 3)) = -1;
    }

    for (void *i = &PROTECTED_ZONE_START; i <= (void*)&PROTECTED_ZONE_END; i += 64 * 8) {
        *(uint64_t*)(0x7fff8000 + ((uint64_t)i >> 3)) = -1;
    }
}

void print_statistics() {
    fprintf(stderr, "Total Checkpoints: %lu\n", simulation_statistics.total_ckpt);
    fprintf(stderr, "\tRollback ROB_LEN: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_ROB_LEN]);
    //fprintf(stderr, "\tRollback ASAN: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_ASAN]);
    fprintf(stderr, "\tRollback SIGSEGV: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_SIGSEGV]);
    fprintf(stderr, "\tRollback EXT_LIB: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_EXT_LIB]);
    fprintf(stderr, "\tRollback MALFORMED_INDIRECT_BR: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_MALFORMED_INDIRECT_BR]);

    fprintf(stderr, "Total Bugs: %lu\n", simulation_statistics.total_bug);
    fprintf(stderr, "\tBug ASAN: %lu\n", simulation_statistics.bug_type[GADGET_SPECFUZZ_ASAN]);
    fprintf(stderr, "\tBug SIGSEGV: %lu\n", simulation_statistics.bug_type[GADGET_SPECFUZZ_SIGSEGV]);
    fprintf(stderr, "\tBug KASPER: %lu\n", simulation_statistics.bug_type[GADGET_KASPER]);
}

__attribute__((preserve_most)) void libcheckpoint_enable(int argc, char **argv) {
    if (__asan_init) {
        __asan_init();
    }

#ifdef COVERAGE
    if (__sanitizer_cov_trace_pc_guard_init) {
        __sanitizer_cov_trace_pc_guard_init(&guard_start, &guard_end);
    }
#endif

    poison_protected_zone();
    map_dift_pages();
    dift_taint_args(argc, argv);
    setup_signal_handler();

    libcheckpoint_enabled = true;
}

__attribute__((preserve_most)) void libcheckpoint_disable() {
    libcheckpoint_enabled = false;

    print_statistics();
}

#define DEF_RESTORE_CHECKPOINT(REASON) \
    __attribute__((naked)) void restore_checkpoint_##REASON() { \
        asm volatile(SWITCH_TO_SCRATCHPAD_STACK); \
        asm volatile("mov $" STR(ROLLBACK_##REASON) ", %rdi"); \
        asm volatile("jmp restore_checkpoint"); \
    }

DEF_RESTORE_CHECKPOINT(ROB_LEN)
//DEF_RESTORE_CHECKPOINT(ASAN)
DEF_RESTORE_CHECKPOINT(SIGSEGV)
DEF_RESTORE_CHECKPOINT(EXT_LIB)
DEF_RESTORE_CHECKPOINT(MALFORMED_INDIRECT_BR)

#undef DEF_RESTORE_CHECKPOINT

void restore_checkpoint(int type) {
    assert(checkpoint_cnt > 0);

    simulation_statistics.total_ckpt++;
    simulation_statistics.rollback_reason[type]++;

    checkpoint_cnt--;
    restore_checkpoint_memlog();

#ifdef COVERAGE
    if (__sanitizer_cov_trace_pc_guard) {
        while (guard_list_top > checkpoint_metadata[checkpoint_cnt].guard_list_top) {
            guard_list_top--;
            __sanitizer_cov_trace_pc_guard(&guard_start + *guard_list_top);
        }
    }
#endif

    instruction_cnt = checkpoint_metadata[checkpoint_cnt].instruction_cnt;
    memcpy(dift_reg_tags, checkpoint_metadata[checkpoint_cnt].dift_reg_tags, DIFT_REG_TAGS_SIZE);

    restore_checkpoint_registers();
}

__attribute__((noinline)) void restore_checkpoint_memlog() {
    in_restore_memlog = true;
    while (memory_history_top > checkpoint_metadata[checkpoint_cnt].memory_history_top) {
        // This may fail if the address is only readable. SIGSEGV handler detects this and the entry will be skipped.
        memory_history_top--;
        *(uint64_t*)(memory_history_top->addr) = memory_history_top->data;
    }
    in_restore_memlog = false;
}