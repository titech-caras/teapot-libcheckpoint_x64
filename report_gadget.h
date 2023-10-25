#pragma once
#include <stdint.h>

void report_gadget_SPECFUZZ_SIGSEGV(uint64_t gadget_addr, uint64_t access_addr);