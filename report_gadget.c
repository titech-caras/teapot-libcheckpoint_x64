#include "checkpoint.h"

#include <stdio.h>

__attribute__((naked)) void report_gadget_specfuzz() {
    asm volatile(SWITCH_TO_SCRATCHPAD_STACK);
    asm volatile("jmp report_gadget_specfuzz_impl");

    // FIXME: actually should continue to execute instead of quit?
}

void report_gadget_specfuzz_impl(uint64_t gadget_addr, uint64_t access_addr) {
    uint64_t checkpoint_addr = checkpoint_metadata[checkpoint_cnt - 1].return_address;
    fprintf(stderr, "[NaHCO3], 1, 0x%lx, 0x%lx, 0, 0x%lx\n", gadget_addr, access_addr, checkpoint_addr);

    restore_checkpoint(ROLLBACK_ASAN);
}
