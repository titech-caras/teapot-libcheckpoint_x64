#pragma once

#include <stdint.h>

#define ENABLE_DIFT

#define TAG_ATTACKER 1
#define TAG_SECRET 2

typedef uint8_t dift_tag_t;

#define DIFT_REG_TAGS_SIZE 48

// 0~15 = rax~r15, 16~47=zmm0~zmm31
extern dift_tag_t dift_reg_tags[DIFT_REG_TAGS_SIZE];

#define DIFT_REG_RAX 0
#define DIFT_REG_RBX 1
#define DIFT_REG_RCX 2
#define DIFT_REG_RDX 3
#define DIFT_REG_RSI 4
#define DIFT_REG_RDI 5
#define DIFT_REG_RSP 6
#define DIFT_REG_RBP 7
#define DIFT_REG_R8 8
#define DIFT_REG_R9 9
#define DIFT_REG_R10 10
#define DIFT_REG_R11 11
#define DIFT_REG_R12 12
#define DIFT_REG_R13 13
#define DIFT_REG_R14 14
#define DIFT_REG_R15 15
// TODO: xmm registers

#define DIFT_ARG0 DIFT_REG_RDI
#define DIFT_ARG1 DIFT_REG_RSI
#define DIFT_ARG2 DIFT_REG_RDX
#define DIFT_ARG3 DIFT_REG_RCX
#define DIFT_ARG4 DIFT_REG_R8
#define DIFT_ARG5 DIFT_REG_R9
#define DIFT_RET DIFT_REG_RAX

#define DIFT_MEM_ADDR(addr) ((dift_tag_t*)((size_t)addr ^ (1ULL << 45)))
#define DIFT_MEM_TAG(addr) (*(DIFT_MEM_ADDR(addr)))

void map_dift_pages();
void dift_taint_args(int argc, char **argv);