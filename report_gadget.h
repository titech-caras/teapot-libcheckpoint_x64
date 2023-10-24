#pragma once
#include <stdint.h>

__attribute__((preserve_most)) void report_gadget_specfuzz_asan(uint64_t gadget_addr, uint64_t access_addr);
void report_gadget_specfuzz_sigsegv(uint64_t gadget_addr, uint64_t access_addr);