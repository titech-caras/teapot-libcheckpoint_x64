#include "checkpoint.h"
#include "signal_handler.h"
#include "dift_support.h"
#include <stdio.h>

uint64_t PROTECTED_ZONE_START;

checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
xsave_area_t processor_extended_states[MAX_CHECKPOINTS];

memory_history_t memory_history[MEM_HISTORY_LEN];
memory_history_t *memory_history_top = &memory_history[0];
scratchpad_t scratchpad;
void *old_rsp;

struct {
    uint64_t total_ckpt;
    uint64_t rollback_reason[5];
} statistics;

uint64_t checkpoint_cnt = 0;
uint64_t instruction_cnt = 0;
bool libcheckpoint_enabled = false;

uint64_t PROTECTED_ZONE_END;

void __asan_init();

void poison_protected_zone() {
    for (void *i = &PROTECTED_ZONE_START; i <= (void*)&PROTECTED_ZONE_END; i += 64 * 8) {
        *(uint64_t*)(0x7fff8000 + ((uint64_t)i >> 3)) = -1;
    }
}

void print_statistics() {
    fprintf(stderr, "Statistics:\n");
    fprintf(stderr, "\tCheckpoints: %lu\n", statistics.total_ckpt);
    fprintf(stderr, "\tRollback ROB_LEN: %lu\n", statistics.rollback_reason[ROLLBACK_ROB_LEN]);
    fprintf(stderr, "\tRollback ASAN: %lu\n", statistics.rollback_reason[ROLLBACK_ASAN]);
    fprintf(stderr, "\tRollback SIGSEGV: %lu\n", statistics.rollback_reason[ROLLBACK_SIGSEGV]);
    fprintf(stderr, "\tRollback EXT_LIB: %lu\n", statistics.rollback_reason[ROLLBACK_EXT_LIB]);
    fprintf(stderr, "\tRollback MALFORMED_INDIRECT_BR: %lu\n", statistics.rollback_reason[ROLLBACK_MALFORMED_INDIRECT_BR]);
}

void libcheckpoint_enable() {
    __asan_init();

    poison_protected_zone();
    map_dift_pages();
    setup_signal_handler();

    libcheckpoint_enabled = true;
}

void libcheckpoint_disable() {
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
DEF_RESTORE_CHECKPOINT(ASAN)
DEF_RESTORE_CHECKPOINT(SIGSEGV)
DEF_RESTORE_CHECKPOINT(EXT_LIB)
DEF_RESTORE_CHECKPOINT(MALFORMED_INDIRECT_BR)

void restore_checkpoint(int type) {
    statistics.total_ckpt++;
    statistics.rollback_reason[type]++;

    checkpoint_cnt--;
    while (memory_history_top > checkpoint_metadata[checkpoint_cnt].memory_history_top) {
        memory_history_top--;
        *(uint64_t*)(memory_history_top->addr) = memory_history_top->data;
    }

    instruction_cnt = checkpoint_metadata[checkpoint_cnt].instruction_cnt;

    restore_checkpoint_registers();
}
