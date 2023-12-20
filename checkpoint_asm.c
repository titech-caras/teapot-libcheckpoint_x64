#include "checkpoint.h"
#include "dift_support.h"

// FIXME: refactor this thing, why is a file full of assembly .c?

#ifdef COVERAGE
void hfuzz_trace_pc(uintptr_t pc);
#endif

#define RDTSC_STAT() \
        "rdtsc\n" \
        "shl $32, %rdx\n" \
        "or %rdx, %rax\n" \
        "mov %rax, %rdx\n" \
        "sub last_rdtsc, %rax\n" \
        "mov %rdx, last_rdtsc\n"

struct {
    void *trampoline_addr, *return_addr;
} checkpoint_target_metadata;
__attribute__((naked)) void make_checkpoint() {
    // TODO: refactor this to use the scratchpad, don't switch stacks
    // Store %rax and FLAGS
    asm volatile (
        SWITCH_TO_SCRATCHPAD_STACK
        "push %rax\n"
        "lahf\n"
        "seto %al\n"
        "push %rax\n" // flags
        "push %rbx\n"
        "mov checkpoint_cnt, %rax\n"
        /*"cmp $" STR(MAX_CHECKPOINTS) ", %rax\n" // TODO: use a better strategy to determine checkpoint skipping
        "jge .Lskip_checkpoint\n"*/
        "cmpb $0, libcheckpoint_enabled\n"
        "je .Lskip_checkpoint\n"
        "incl checkpoint_cnt\n" // Increment count in memory
        );

    // Take timer & store processor extended states
    asm volatile (
        "push %rax\n" // Save the original counter for now
        "push %rdx\n"
        "lea processor_extended_states, %rbx\n"
        "shl $11, %rax\n" // XSAVE area is aligned to 2048 bytes
        "add %rax, %rbx\n"

#ifdef TIME
        RDTSC_STAT()
        "add %rax, simulation_statistics+0\n" // normal_time
#endif

        "mov $0xFFFFFFFF, %eax\n"
        "mov $0xFFFFFFFF, %edx\n" // TODO: maybe save only the necessary components?
        //"xsave (%rbx)\n"
        //"fxsave64 (%rbx)\n"
        "movaps %xmm0, (%rbx)\n"
        "movaps %xmm1, 16(%rbx)\n"
        "movaps %xmm2, 32(%rbx)\n"
        "movaps %xmm3, 48(%rbx)\n"
        "movaps %xmm4, 64(%rbx)\n"
        "movaps %xmm5, 80(%rbx)\n"
        "movaps %xmm6, 96(%rbx)\n"
        "movaps %xmm7, 112(%rbx)\n"

        "pop %rdx\n"
        "pop %rax\n"
        );

    // Dancing in stack to checkpoint %rax, %rbx, %rsp, return address, and FLAGS
    asm volatile (
        "lea checkpoint_metadata, %rbx\n"
        "shl $8, %rax\n" // Because we assume metadata is aligned to 256 bytes
        "add %rbx, %rax\n"
        "mov (%rsp), %rbx\n" // Original %rbx
        "mov %rbx, 8(%rax)\n" // checkpoint->rbx
        "mov 16(%rsp), %rbx\n" // Original %rax
        "mov %rbx, (%rax)\n" // checkpoint->rax
        "mov 8(%rsp), %rbx\n" // Original FLAGS
        "mov %rbx, 128(%rax)\n" // checkpoint->flags
        "mov checkpoint_target_metadata+8, %rbx\n" // return address
        "mov %rbx, 152(%rax)\n" // checkpoint->return_address
        "mov old_rsp, %rbx\n"
        "mov %rbx, 48(%rax)\n" // checkpoint->rsp
        );

#ifdef ENABLE_DIFT
    // Store the dift tags
    asm volatile (
        "movaps %xmm0, scratchpad\n"
        "movaps dift_reg_tags+0, %xmm0\n"
        "movaps %xmm0, 160(%rax)\n"
        "movaps dift_reg_tags+16, %xmm0\n"
        "movaps %xmm0, 176(%rax)\n"
        "movaps dift_reg_tags+32, %xmm0\n"
        "movaps %xmm0, 192(%rax)\n"
        "movaps scratchpad, %xmm0\n"
        );
#endif

    // Store other general purpose registers
    asm volatile (
        // rax stored above
        // rbx stored above
        "mov %rcx, 16(%rax)\n"
        "mov %rdx, 24(%rax)\n"
        "mov %rsi, 32(%rax)\n"
        "mov %rdi, 40(%rax)\n"
        // rsp stored above
        "mov %rbp, 56(%rax)\n"
        "mov %r8, 64(%rax)\n"
        "mov %r9, 72(%rax)\n"
        "mov %r10, 80(%rax)\n"
        "mov %r11, 88(%rax)\n"
        "mov %r12, 96(%rax)\n"
        "mov %r13, 104(%rax)\n"
        "mov %r14, 112(%rax)\n"
        "mov %r15, 120(%rax)\n"
        // flags stored above
        );

    // Store current counters
    asm volatile (
        "mov instruction_cnt, %rbx\n"
        "mov %rbx, 136(%rax)\n" // checkpoint->instruction_cnt
        "mov memory_history_top, %rbx\n"
        "mov %rbx, 144(%rax)\n" // checkpoint->memory_history_top
        "mov guard_list_top, %rbx\n"
        "mov %rbx, 208(%rax)\n" // checkpoint->guard_list_top
        );

#ifdef COVERAGE
    // Call Trace PC
    asm volatile (
        "movq checkpoint_target_metadata+8, %rdi\n" // Return address
        "mov %rax, %rbx\n"
        "call hfuzz_trace_pc\n"
        "mov %rbx, %rax\n"
        "mov 16(%rax), %rcx\n" // Restore the caller-saved registers
        "mov 24(%rax), %rdx\n"
        "mov 32(%rax), %rsi\n"
        "mov 40(%rax), %rdi\n"
        "mov 64(%rax), %r8\n"
        "mov 72(%rax), %r9\n"
        "mov 80(%rax), %r10\n"
        "mov 88(%rax), %r11\n"
    );
#endif

#ifdef TIME
    asm volatile(
        "mov %rax, %rbx\n"
        RDTSC_STAT()
        "add %rax, simulation_statistics+16\n" // ckpt_time
        "mov 24(%rbx), %rdx\n"
        );
#endif

    // Exit cleanup, go to the trampoline
    asm volatile (
        "pop %rbx\n"
        "pop %rax\n" // flags
        "add $0x7f, %al\n"
        "sahf\n"
        "pop %rax\n"
        SWITCH_TO_ORIGINAL_STACK
        "jmp *(checkpoint_target_metadata)\n" // Trampoline address
        );

    // If we don't do checkpointing at all, we don't want to go to the trampoline
    asm volatile (
        ".Lskip_checkpoint:"
        "pop %rbx\n"
        "pop %rax\n" // flags
        "add $0x7f, %al\n"
        "sahf\n"
        "pop %rax\n"
        SWITCH_TO_ORIGINAL_STACK
        "jmp *(checkpoint_target_metadata+8)\n" // Return address
        );
}

__attribute__((naked)) void restore_checkpoint_registers() {
    // Load address of current metadata into %rax
    asm volatile(
        "mov checkpoint_cnt, %rax\n"
        "mov %rax, %r8\n" // Make a copy of the counter to use for XRSTOR stuff
        "lea checkpoint_metadata, %rbx\n"
        "shl $8, %rax\n" // Because we assume metadata is aligned to 256 bytes
        "add %rbx, %rax\n"
        );

    // Restore processor extendreport_gadget_specfuzz_impled states
    asm volatile (
        "mov %rax, %r11\n"
        "lea processor_extended_states, %r9\n"
        "shl $11, %r8\n" // XSAVE area is aligned to 2048 bytes
        "add %r9, %r8\n"
        "mov $0xFFFFFFFF, %eax\n"
        "mov $0xFFFFFFFF, %edx\n" // TODO: maybe restore only the necessary components?
        //"xrstor (%r8)\n"
        //"fxrstor64 (%r8)\n"

        "movaps (%r8), %xmm0 \n"
        "movaps 16(%r8), %xmm1 \n"
        "movaps 32(%r8), %xmm2 \n"
        "movaps 48(%r8), %xmm3 \n"
        "movaps 64(%r8), %xmm4 \n"
        "movaps 80(%r8), %xmm5 \n"
        "movaps 96(%r8), %xmm6 \n"
        "movaps 112(%r8), %xmm7 \n"

        "mov %r11, %rax\n"
        );

    // Restore registers
    asm volatile(
        // Restore %rax later
        // Restore %rbx later
        "mov 16(%rax), %rcx\n"
        "mov 24(%rax), %rdx\n"
        "mov 32(%rax), %rsi\n"
        "mov 40(%rax), %rdi\n"
        "mov 48(%rax), %rsp\n"
        "mov 56(%rax), %rbp\n"
        "mov 64(%rax), %r8\n"
        "mov 72(%rax), %r9\n"
        "mov 80(%rax), %r10\n"
        "mov 88(%rax), %r11\n"
        "mov 96(%rax), %r12\n"
        "mov 104(%rax), %r13\n"
        "mov 112(%rax), %r14\n"
        "mov 120(%rax), %r15\n"
        );

#ifdef TIME
    asm volatile(
        "mov %rax, %rbx\n"
        RDTSC_STAT()
        "add %rax, simulation_statistics+24\n" // rstr_time
        "mov %rbx, %rax\n"
        "mov 24(%rax), %rdx\n"
        );
#endif

    asm volatile(
        "mov %rax, %rbx\n"
        "mov 128(%rbx), %rax\n" // checkpoint->flags
        "add $0x7f, %al\n"
        "sahf\n"
        "mov 152(%rbx), %rax\n" // checkpoint->return_address
        "mov %rax, checkpoint_target_metadata+8\n"
        "mov (%rbx), %rax\n" // restore %rax
        "mov 8(%rbx), %rbx\n" // restore %rbx
        "jmp *(checkpoint_target_metadata+8)"
        );
}
