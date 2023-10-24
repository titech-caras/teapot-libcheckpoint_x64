#include "report_gadget.h"
#include "checkpoint.h"

#include <stdio.h>

void report_gadget(int gadget_type, uint64_t gadget_addr, uint64_t access_addr, uint64_t checkpoint_addr) {
    simulation_statistics.total_bug++;
    simulation_statistics.bug_type[gadget_type]++;

    fprintf(stderr, "[NaHCO3], %d, 0x%lx, 0x%lx, 0, 0x%lx\n",
            gadget_type, gadget_addr, access_addr, checkpoint_addr);
}

__attribute__((preserve_most)) void report_gadget_specfuzz_asan(uint64_t gadget_addr, uint64_t access_addr) {
    uint64_t checkpoint_addr = checkpoint_metadata[checkpoint_cnt - 1].return_address;
    report_gadget(GADGET_SPECFUZZ_ASAN, gadget_addr, access_addr, checkpoint_addr);
}

void report_gadget_specfuzz_sigsegv(uint64_t gadget_addr, uint64_t access_addr) {
    uint64_t checkpoint_addr = checkpoint_metadata[checkpoint_cnt - 1].return_address;
    report_gadget(GADGET_SPECFUZZ_SIGSEGV, gadget_addr, access_addr, checkpoint_addr);
}