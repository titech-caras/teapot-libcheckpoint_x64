#include "checkpoint.h"

#define __USE_GNU

#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <ucontext.h>

checkpoint_metadata_t checkpoint_metadata[MAX_CHECKPOINTS];
xsave_area_t processor_extended_states[MAX_CHECKPOINTS];

memory_history_t memory_history[MEM_HISTORY_LEN];
uint64_t checkpoint_cnt = 0;
uint64_t instruction_cnt = 0;
bool libcheckpoint_enabled = false;

memory_history_t *memory_history_top = &memory_history[0];

uint64_t shadow_stack[1024];
uint64_t *shadow_stack_top = shadow_stack + 1024 - 8;

void sigsegv_handler(int sig, siginfo_t *info, void *ucontext) {
    if (checkpoint_cnt != 0) {
        ucontext_t *uc = (ucontext_t *)ucontext;
        greg_t *rip = &uc->uc_mcontext.gregs[REG_RIP];
        *rip = (int64_t)&restore_checkpoint;
    } else {
        _exit(1);
    }
}

void libcheckpoint_enable() {
    libcheckpoint_enabled = true;

    static char signal_stack[SIGSTKSZ]; // so that SIGSEGV doesn't overwrite stack contents in speculation
    stack_t ss = {
        .ss_size = SIGSTKSZ,
        .ss_sp = signal_stack,
    };
    struct sigaction sa = {
        .sa_sigaction = sigsegv_handler,
        .sa_flags = SA_ONSTACK | SA_SIGINFO
    };
    sigaltstack(&ss, 0);
    sigfillset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, 0);
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
