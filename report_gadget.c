#include "report_gadget.h"
#include "checkpoint.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <sys/mman.h>

// FIXME: refactor
uint64_t r11_tmp;
#define PRESERVE_R11() asm volatile("movq %r11, r11_tmp")
#define RESTORE_R11() asm volatile("movq r11_tmp, %r11")

void make_report_call_nop(uint64_t gadget_addr) {
    uint64_t page_aligned_addr = gadget_addr & ~(4096UL - 1);
    if (mprotect((void*)page_aligned_addr, 8192, PROT_READ | PROT_WRITE | PROT_EXEC) == -1) {
        perror("mprotect");
        return;
    }

    // NOP DWORD ptr [EAX + EAX*1 + 00H]
    *(uint32_t*)gadget_addr = 0x00441f0f;
    *(uint8_t*)(gadget_addr + 4) = 0x00;

    if (mprotect((void*)page_aligned_addr, 8192, PROT_READ | PROT_EXEC) == -1)
        perror("mprotect");
}

void report_gadget(int gadget_type, uint64_t gadget_addr, uint64_t access_addr) {
    simulation_statistics.total_bug++;
    simulation_statistics.bug_type[gadget_type]++;
    uint64_t ckpt_addr = checkpoint_metadata[checkpoint_cnt - 1].return_address;

    if (gadget_type == GADGET_KASPER || gadget_type == GADGET_SPECFUZZ_ASAN) {
#ifdef VERBOSE
        fprintf(stderr, "[NaHCO3], %d, 0x%lx, 0x%lx, 0, 0x%lx, %lu\n",
            gadget_type, gadget_addr, access_addr, ckpt_addr, instruction_cnt);
#endif
        make_report_call_nop(gadget_addr);

        if (gadget_type == GADGET_KASPER) {
            gadget_desc_t gadget = {
                .gadget_addr = gadget_addr,
                .access_addr = access_addr,
                .ckpt_addr = ckpt_addr,
                .gadget_type = gadget_type
            };
            union sigval si_sigval = {
                .sival_ptr = (void*)&gadget
            };
            sigqueue(getpid(), SIGUSR1, si_sigval);
        }
    }
}

#define DEF_REPORT_GADGET(TYPE) \
    void report_gadget_##TYPE(uint64_t gadget_addr, uint64_t access_addr) { \
        PRESERVE_R11(); \
        report_gadget(GADGET_##TYPE, gadget_addr, access_addr); \
        RESTORE_R11(); \
    }

__attribute__((preserve_most)) DEF_REPORT_GADGET(SPECFUZZ_ASAN);
DEF_REPORT_GADGET(SPECFUZZ_SIGSEGV);
__attribute__((preserve_most)) DEF_REPORT_GADGET(KASPER);

#undef DEF_REPORT_GADGET
