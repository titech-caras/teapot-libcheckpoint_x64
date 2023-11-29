#include "dift_support.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#include <arpa/inet.h>

#include <zlib.h>

// TODO: eventually move this into an independent project and make the interface compatible with dfsan

#define DIFT_WRAPPER(function_name, return_type, ...) return_type function_name##__dift_wrapper__(__VA_ARGS__)

// Taing source: read.
DIFT_WRAPPER(read, ssize_t, int fd, void *buf, size_t count) {
    ssize_t read_size = read(fd, buf, count);
    if (read_size > 0) {
        memset(DIFT_MEM_ADDR(buf), TAG_ATTACKER, read_size);
    }
    return read_size;
}

// Taint source: fread.
DIFT_WRAPPER(fread, size_t, void *buffer, size_t size, size_t count, FILE *stream) {
    size_t read_cnt = fread(buffer, size, count, stream);
    if (read_cnt > 0) {
        memset(DIFT_MEM_ADDR(buffer), TAG_ATTACKER, read_cnt * size);
    }
    return read_cnt;
}

// Taint source: fread_unlocked.
DIFT_WRAPPER(fread_unlocked, size_t, void *buffer, size_t size, size_t count, FILE *stream) {
    size_t read_cnt = fread_unlocked(buffer, size, count, stream);
    if (read_cnt > 0) {
        memset(DIFT_MEM_ADDR(buffer), TAG_ATTACKER, read_cnt * size);
    }
    return read_cnt;
}

// Taint source: fgets.
DIFT_WRAPPER(fgets, char *, char *str, int n, FILE *stream) {
    char *result = fgets(str, n, stream);
    for (int i = 0; i < n; i++) {
        if (str[i] == '\n' || str[i] == '\r' || str[i] == 0) {
            break;
        }
        DIFT_MEM_TAG(str + i) = TAG_ATTACKER;
    }
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return result;
}

// Taint source: getc.
DIFT_WRAPPER(getc, int, FILE *file) {
    dift_reg_tags[DIFT_RET] = TAG_ATTACKER;
    return getc(file);
}

// Taint source: fgetc.
DIFT_WRAPPER(fgetc, int, FILE *file) {
    dift_reg_tags[DIFT_RET] = TAG_ATTACKER;
    return fgetc(file);
}

// Taint source: getchar.
DIFT_WRAPPER(getchar, int) {
    dift_reg_tags[DIFT_RET] = TAG_ATTACKER;
    return getchar();
}

DIFT_WRAPPER(calloc, void*, size_t num, size_t size) {
    void *addr = calloc(num, size);
    memset(DIFT_MEM_ADDR(addr), 0, num * size);
    return addr;
}

DIFT_WRAPPER(inflate, int, z_streamp stream, int flush) {
    int result = inflate(stream, flush);
    memset(DIFT_MEM_ADDR(stream->next_out), DIFT_MEM_TAG(stream->next_in), stream->avail_out);
    memcpy(DIFT_MEM_ADDR(&stream->next_out), DIFT_MEM_ADDR(&stream->next_in), sizeof(void*));
    memcpy(DIFT_MEM_ADDR(&stream->avail_out), DIFT_MEM_ADDR(&stream->avail_in), sizeof(stream->avail_in));
    return result;
}

DIFT_WRAPPER(atoi, int, const char *str) {
    dift_reg_tags[DIFT_RET] = DIFT_MEM_TAG(str);
    return atoi(str);
}

DIFT_WRAPPER(strtol, long int, const char *nptr, char **endptr, int base) {
    dift_reg_tags[DIFT_RET] = DIFT_MEM_TAG(nptr);
    return strtol(nptr, endptr, base);
}

DIFT_WRAPPER(strtoul, unsigned long int, const char *nptr, char **endptr, int base) {
    dift_reg_tags[DIFT_RET] = DIFT_MEM_TAG(nptr);
    return strtoul(nptr, endptr, base);
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
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return strcpy(dest, src);
}

DIFT_WRAPPER(strcat, char*, char *dest, const char *src) {
    memcpy(DIFT_MEM_ADDR(dest + strlen(dest)), DIFT_MEM_ADDR(src), strlen(src));
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return strcat(dest, src);
}

DIFT_WRAPPER(strncat, char*, char *dest, const char *src, size_t n) {
    memcpy(DIFT_MEM_ADDR(dest + strlen(dest)), DIFT_MEM_ADDR(src), n);
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return strncat(dest, src, n);
}

DIFT_WRAPPER(__strncat_chk, char*, char *dest, const char *src, size_t n, size_t s1len) {
    char * __strncat_chk(char * s1, const char * s2, size_t n, size_t s1len);

    memcpy(DIFT_MEM_ADDR(dest + n), DIFT_MEM_ADDR(src), strlen(src));
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return __strncat_chk(dest, src, n, s1len);
}

DIFT_WRAPPER(strncpy, char*, char *dest, const char *src, size_t num) {
    memcpy(DIFT_MEM_ADDR(dest), DIFT_MEM_ADDR(src), num);
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return strncpy(dest, src, num);
}

DIFT_WRAPPER(memset, void*, void *dest, int ch, size_t count) {
    memset(DIFT_MEM_ADDR(dest), dift_reg_tags[DIFT_ARG1], count);
    return memset(dest, ch, count);
}

DIFT_WRAPPER(strtok_r, char *, char *str, const char *delims, char **saveptr) {
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return strtok_r(str, delims, saveptr);
}

DIFT_WRAPPER(strtok, char *, char *str, const char *delims) {
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return strtok(str, delims);
}

DIFT_WRAPPER(strstr, char *, const char *haystack, const char *needle) {
    dift_reg_tags[DIFT_RET] = dift_reg_tags[DIFT_ARG0];
    return strstr(haystack, needle);
}

DIFT_WRAPPER(inet_pton, int, int af, const char *src, void *dst) {
    memset(DIFT_MEM_ADDR(dst), DIFT_MEM_TAG(src), sizeof(struct in_addr));
    return inet_pton(af, src, dst);
}

DIFT_WRAPPER(log2, double, double arg) {
    // TODO: automate transformation of purely functional functions
    // TODO: tag the xmm register
    return log2(arg);
}
