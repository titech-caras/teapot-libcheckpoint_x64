#include "report_gadget.h"
#include "checkpoint.h"

#include <stdio.h>

void report_gadget(int gadget_type, uint64_t gadget_addr, uint64_t access_addr) {
    simulation_statistics.total_bug++;
    simulation_statistics.bug_type[gadget_type]++;

    fprintf(stderr, "[NaHCO3], %d, 0x%lx, 0x%lx, 0, 0x%lx, %lu\n",
            gadget_type, gadget_addr, access_addr,
            checkpoint_metadata[checkpoint_cnt - 1].return_address,
            instruction_cnt);
}

#define DEF_REPORT_GADGET(TYPE) \
    void report_gadget_##TYPE(uint64_t gadget_addr, uint64_t access_addr) { \
        report_gadget(GADGET_##TYPE, gadget_addr, access_addr); \
    }

__attribute__((preserve_most)) DEF_REPORT_GADGET(SPECFUZZ_ASAN);
DEF_REPORT_GADGET(SPECFUZZ_SIGSEGV);
__attribute__((preserve_most)) DEF_REPORT_GADGET(KASPER);

#undef DEF_REPORT_GADGET