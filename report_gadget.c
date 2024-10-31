#include "report_gadget.h"
#include "checkpoint.h"
#include "config.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
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

void report_gadget(const char * gadget_desc, int gadget_type, uint64_t gadget_addr, uint64_t access_addr, dift_tag_t tag) {
    static char buf[PIPE_BUF];

    simulation_statistics.total_bug++;
    simulation_statistics.bug_type[gadget_type]++;

    char *buf_ptr = buf;

    buf_ptr += sprintf(buf_ptr, "[teapot], %d %s, 0x%lx, 0x%lx, 0x%hhx, %lu, ",
        gadget_type, gadget_desc, gadget_addr, access_addr, tag, instruction_cnt);

    for (size_t i = checkpoint_cnt; i > 0; i--) {
        buf_ptr += sprintf(buf_ptr, "0x%lx, ", checkpoint_metadata[i - 1].return_address);
    }
    *(buf_ptr++) = '\n';
    *buf_ptr = 0;

    fputs(buf, stderr);

#ifdef SILENCE_GADGET_AFTER_FIRST_DISCOVERY
    make_report_call_nop(gadget_addr);
#endif

    /*if (gadget_type == GADGET_KASPER) {
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
    }*/
}

#define DEF_REPORT_GADGET(TYPE) \
    void report_gadget_##TYPE(uint64_t gadget_addr, uint64_t access_addr, dift_tag_t tag) { \
        PRESERVE_R11(); \
        report_gadget(STR(TYPE), GADGET_##TYPE, gadget_addr, access_addr, tag); \
        RESTORE_R11(); \
    }

/*__attribute__((preserve_most)) DEF_REPORT_GADGET(SPECFUZZ_ASAN_READ);
__attribute__((preserve_most)) DEF_REPORT_GADGET(SPECFUZZ_ASAN_WRITE);
__attribute__((preserve_most)) DEF_REPORT_GADGET(SPECTAINT_BCB);
__attribute__((preserve_most)) DEF_REPORT_GADGET(SPECTAINT_BCBS);*/
__attribute__((preserve_most)) DEF_REPORT_GADGET(KASPER_CACHE);
__attribute__((preserve_most)) DEF_REPORT_GADGET(KASPER_MDS);
__attribute__((preserve_most)) DEF_REPORT_GADGET(KASPER_PORT);

#undef DEF_REPORT_GADGET
