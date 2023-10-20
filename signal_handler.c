#include "signal_handler.h"
#include "checkpoint.h"

#define __USE_GNU
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

void signal_handler(int sig, siginfo_t *info, void *ucontext) {
    if (checkpoint_cnt != 0) {
        ucontext_t *uc = (ucontext_t *)ucontext;
        greg_t *rip = &uc->uc_mcontext.gregs[REG_RIP];
        *rip = (int64_t)&restore_checkpoint;
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