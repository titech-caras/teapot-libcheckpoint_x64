#include "checkpoint.h"
#include "signal_handler.h"
#include "dift_support.h"

checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
xsave_area_t processor_extended_states[MAX_CHECKPOINTS];

memory_history_t memory_history[MEM_HISTORY_LEN];
uint64_t checkpoint_cnt = 0;
uint64_t instruction_cnt = 0;
bool libcheckpoint_enabled = false;

memory_history_t *memory_history_top = &memory_history[0];

uint64_t shadow_stack[1024];
uint64_t *shadow_stack_top = shadow_stack + 1024 - 8;

void libcheckpoint_enable() {
    libcheckpoint_enabled = true;

    map_dift_pages();
    setup_signal_handler();
}

void libcheckpoint_disable() {
    libcheckpoint_enabled = false;
}

void restore_checkpoint() {
    checkpoint_cnt--;
    while (memory_history_top > checkpoint_metadata[checkpoint_cnt].memory_history_top) {
        memory_history_top--;
        *(uint64_t*)(memory_history_top->addr) = memory_history_top->data;
    }

    instruction_cnt = checkpoint_metadata[checkpoint_cnt].instruction_cnt;

    restore_checkpoint_registers();
}
