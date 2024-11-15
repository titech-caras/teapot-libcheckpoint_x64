#include "dift_support.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <stdio.h>

dift_tag_t dift_reg_tags[DIFT_REG_TAGS_SIZE];

/*
 * If a manual tag update is required as a result of a gadget policy,
 * it is buffered here first and updated after DIFT propagation.
 */
dift_tag_t dift_reg_queued_tag = 0x0;
uint8_t dift_reg_queued_id = 0x0;

void *mmap_helper(void *base_addr, size_t len, int prot) {
    int flags = MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_NORESERVE;
    void *addr = mmap(base_addr, len, prot, flags, -1, 0);
    if (addr != base_addr) {
        fprintf(stderr, "Map address 0x%llx failed: %s\n", (unsigned long long)base_addr, strerror(errno));
        abort();
    }
    return addr;
}

void map_dift_pages() {
    mmap_helper((void *) 0x400000000000, 0x200000000000, PROT_READ | PROT_WRITE); // HighMem Tags
    mmap_helper((void *) 0x200000000000, 0x7fff8000, PROT_READ | PROT_WRITE); // LowMem Tags
    mmap_helper((void *) 0x10007fff8000, 0x100000000 - 0x7fff8000, PROT_NONE); // Gap
    mmap_helper((void *) 0x20007fff8000, 0x200000000000 - 0x7fff8000, PROT_NONE); // Gap
}

void dift_taint_args(int argc, char **argv) {
    // Taint source: argc and argv.

    dift_reg_tags[DIFT_ARG0] = TAG_ATTACKER;

    for (int i = 0; i < argc; i++) {
        size_t len = strlen(argv[i]);
        memset(DIFT_MEM_ADDR(argv[i]), TAG_ATTACKER, len);
    }
}