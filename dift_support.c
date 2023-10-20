#include "dift_support.h"

#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

void map_dift_pages() {
    void* high_tag = mmap((void *) 0x400000000000, 0x200000000000,
                          PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_NORESERVE, -1, 0);
    if ((long long) high_tag == -1)
        fprintf(stderr, "High tag mapping error: %s\n", strerror(errno));
    void* low_tag = mmap((void *) 0x200000000000, 0x7fff8000,
                         PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
    if ((long long) low_tag == -1)
        fprintf(stderr, "Low tag mapping error: %s\n", strerror(errno));
    void *inaccessible1 = mmap((void *) 0x10007fff8000, 0x7fff8000,
                               PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
    if ((long long) inaccessible1 == -1)
        fprintf(stderr, "Inaccessible1 mapping error: %s\n", strerror(errno));
    void *inaccessible2 = mmap((void *) 0x20007fff8000, 0x200000000000 - 0x7fff8000,
                               PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED_NOREPLACE, -1, 0);
    if ((long long) inaccessible2 == -1)
        fprintf(stderr, "Inaccessible2 mapping error: %s\n", strerror(errno));
}
