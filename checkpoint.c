#include "checkpoint.h"
#include "signal_handler.h"
#include "dift_support.h"

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

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

uint64_t last_rdtsc = 0;
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
    for (void *i = &PROTECTED_ZONE_START; i <= (void*)&PROTECTED_ZONE_END; i += 64 * 8) {
        *(uint64_t*)(0x7fff8000 + ((uint64_t)i >> 3)) = -1;
    }
}

void print_statistics() {
    fprintf(stderr, "Total Checkpoints: %lu\n", simulation_statistics.total_ckpt);

    for (int i = 0; i < MAX_CHECKPOINTS; i++) {
        fprintf(stderr, "\tDepth %d: %lu\n", i + 1, simulation_statistics.ckpt_depth[i]);
    }

    puts("");
    puts("Rollbacks");
    fprintf(stderr, "\tRollback ROB_LEN: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_ROB_LEN]);
    //fprintf(stderr, "\tRollback ASAN: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_ASAN]);
    fprintf(stderr, "\tRollback SIGSEGV: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_SIGSEGV]);
    fprintf(stderr, "\tRollback EXT_LIB: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_EXT_LIB]);
    fprintf(stderr, "\tRollback MALFORMED_INDIRECT_BR: %lu\n", simulation_statistics.rollback_reason[ROLLBACK_MALFORMED_INDIRECT_BR]);

    puts("");
    fprintf(stderr, "Total Bugs: %lu\n", simulation_statistics.total_bug);
    fprintf(stderr, "\tBug KASPER_MDS: %lu\n", simulation_statistics.bug_type[GADGET_KASPER_MDS]);
    fprintf(stderr, "\tBug KASPER_CACHE: %lu\n", simulation_statistics.bug_type[GADGET_KASPER_CACHE]);
    fprintf(stderr, "\tBug KASPER_PORT: %lu\n", simulation_statistics.bug_type[GADGET_KASPER_PORT]);

#ifdef TIME

    uint64_t total_time = simulation_statistics.rdtsc_runtime.normal_time +
            simulation_statistics.rdtsc_runtime.spec_time +
            simulation_statistics.rdtsc_runtime.ckpt_time +
            simulation_statistics.rdtsc_runtime.rstr_time;
    fprintf(stderr, "Time spent %%: Normal: %.2lf%% / Spec: %.2lf%% / Ckpt: %.2lf%% / Rstr: %.2lf%%\n",
            simulation_statistics.rdtsc_runtime.normal_time * 100.0 / total_time,
            simulation_statistics.rdtsc_runtime.spec_time * 100.0 / total_time,
            simulation_statistics.rdtsc_runtime.ckpt_time * 100.0 / total_time,
            simulation_statistics.rdtsc_runtime.rstr_time * 100.0 / total_time);
#endif
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

    fprintf(stderr, "[NaHCO3], "
        "Gadget Type, Gadget Address, Mem Access Address, "
        "Tag, Instruction Counter, Checkpoint Addresses\n");
    last_rdtsc = __rdtsc();
    libcheckpoint_enabled = true;
    atexit((void (*)(void)) libcheckpoint_disable);
}

__attribute__((preserve_most)) void libcheckpoint_disable() {
    if (!libcheckpoint_enabled)
        return;

    libcheckpoint_enabled = false;

#ifdef VERBOSE
    print_statistics();
#endif
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

#ifdef TIME
    uint64_t rdtsc_time = __rdtsc();
    simulation_statistics.rdtsc_runtime.spec_time += rdtsc_time - last_rdtsc;
    last_rdtsc = rdtsc_time;
#endif

    simulation_statistics.total_ckpt++;
    simulation_statistics.ckpt_depth[checkpoint_cnt - 1]++;
    simulation_statistics.rollback_reason[type]++;

    checkpoint_cnt--;

#ifdef VERBOSE_DBGINFO
    fprintf(stderr, "[NaHCO3] Rollback: to 0x%lx at nested level %lu\n",
            checkpoint_metadata[checkpoint_cnt].return_address, checkpoint_cnt);
#endif

    restore_checkpoint_memlog();

#ifdef COVERAGE
    if (__sanitizer_cov_trace_pc_guard) {
        while (guard_list_top > checkpoint_metadata[checkpoint_cnt].guard_list_top) {
            guard_list_top--;
            uint32_t *guard_ptr = &guard_start + *guard_list_top;
            if (!*guard_ptr) continue;
            __sanitizer_cov_trace_pc_guard(guard_ptr);
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
