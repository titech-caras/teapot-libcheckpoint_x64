#include "dift_support.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// TODO: eventually move this into an independent project and make the interface compatible with dfsan

#define DIFT_WRAPPER(function_name, return_type, ...) return_type function_name##__dift_wrapper__(__VA_ARGS__)

// Taint source: fread.
DIFT_WRAPPER(fread, size_t, void *buffer, size_t size, size_t count, FILE *stream) {
    size_t written_size = fread(buffer, size, count, stream);
    if (written_size > 0) {
        memset(DIFT_MEM_ADDR(buffer), TAG_ATTACKER, written_size);
    }
    return written_size;
}

// Taint source: getc.
DIFT_WRAPPER(getc, int, FILE *file) {
    dift_reg_tags[DIFT_RET] = TAG_ATTACKER;
    return getc(file);
}

// Taint source: getchar.
DIFT_WRAPPER(getchar, int) {
    dift_reg_tags[DIFT_RET] = TAG_ATTACKER;
    return getchar();
}

DIFT_WRAPPER(atoi, int, const char *str) {
    dift_reg_tags[DIFT_RET] = DIFT_MEM_TAG(str);
    return atoi(str);
}

DIFT_WRAPPER(strlen, size_t, const char *str) {
    dift_reg_tags[DIFT_RET] = DIFT_MEM_TAG(str);
    return strlen(str);
}

DIFT_WRAPPER(strdup, char*, const char *string) {
    char *result = strdup(string);
    memcpy(DIFT_MEM_ADDR(result), DIFT_MEM_ADDR(string), strlen(string));
    return result;
}

DIFT_WRAPPER(memcpy, void*, void *dest, void *src, size_t count) {
    memcpy(DIFT_MEM_ADDR(dest), DIFT_MEM_ADDR(src), count);
    return memcpy(dest, src, count);
}

DIFT_WRAPPER(memmove, void*, void *dest, void *src, size_t count) {
    memmove(DIFT_MEM_ADDR(dest), DIFT_MEM_ADDR(src), count);
    return memmove(dest, src, count);
}

DIFT_WRAPPER(strcpy, char*, char *dest, const char *src) {
    memcpy(DIFT_MEM_ADDR(dest), DIFT_MEM_ADDR(src), strlen(src));
    return strcpy(dest, src);
}

DIFT_WRAPPER(memset, void*, void *dest, int ch, size_t count) {
    memset(DIFT_MEM_ADDR(dest), dift_reg_tags[DIFT_ARG1], count);
    return memset(dest, ch, count);
}
