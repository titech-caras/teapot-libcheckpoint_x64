#pragma once

#include <stdint.h>

#define TAG_ATTACKER 1
#define TAG_SECRET 2

// 0~15 = rax~r15, 16~47=zmm0~zmm31
extern uint8_t dift_reg_tags[48];

void map_dift_pages();