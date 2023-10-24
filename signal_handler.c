#include "signal_handler.h"
#include "checkpoint.h"

#define __USE_GNU
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

extern void restore_checkpoint_SIGSEGV();

void signal_handler(int sig, siginfo_t *info, void *ucontext) {
    if (checkpoint_cnt != 0) {
        uint64_t checkpoint_addr = checkpoint_metadata[checkpoint_cnt - 1].return_address;
        ucontext_t *uc = (ucontext_t *)ucontext;
        greg_t *rip = &uc->uc_mcontext.gregs[REG_RIP];

        fprintf(stderr, "[NaHCO3], 11, 0x%lx, 0x%lx, 0, 0x%lx\n", *(int64_t*)rip, (int64_t)info->si_addr, checkpoint_addr);

        *rip = (int64_t)&restore_checkpoint_SIGSEGV;
    } else {
        fprintf(stderr, "Signal caught outside simulation: %s\n", strsignal(sig));
        abort();
    }
}

void setup_signal_handler() {
    static char signal_stack[SIGSTKSZ]; // so that SIGSEGV doesn't overwrite stack contents in speculation
    stack_t ss = {
        .ss_size = SIGSTKSZ,
        .ss_sp = signal_stack,
    };
    struct sigaction sa = {
        .sa_sigaction = signal_handler,
        .sa_flags = SA_ONSTACK | SA_SIGINFO
    };
    sigaltstack(&ss, 0);
    sigfillset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, 0);
}