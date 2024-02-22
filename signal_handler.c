#include "signal_handler.h"
#include "checkpoint.h"
#include "report_gadget.h"

#define __USE_GNU
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

void signal_handler(int sig, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = (ucontext_t *)ucontext;
    greg_t *rip = &uc->uc_mcontext.gregs[REG_RIP];

    if (checkpoint_cnt != 0) {
        report_gadget_SPECFUZZ_SIGSEGV((uint64_t) *rip, (uint64_t) info->si_addr);
        *rip = (int64_t)&restore_checkpoint_SIGSEGV;
    } else if (in_restore_memlog) {
        *rip = (int64_t)&restore_checkpoint_memlog;
    } else {
        fprintf(stderr, "Signal caught outside simulation: %s\n", strsignal(sig));
        abort();
    }
}

void setup_signal_handler() {
    static char signal_stack[SIGSTKSZ]; // so that SIGSEGV doesn't overwrite stack contents in speculation
    static stack_t ss = {
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
    sigaction(SIGFPE, &sa, 0);
    sigaction(SIGBUS, &sa, 0);

    signal(SIGUSR1, SIG_IGN);
}