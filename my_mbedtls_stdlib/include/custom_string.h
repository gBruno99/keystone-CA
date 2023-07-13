#ifndef CUSTOM_STRING_H
#define CUSTOM_STRING_H

#include <stdint.h>
#include <stddef.h>

size_t custom_strlen(const char *str);
int custom_strncmp(const char *string1, const char *string2, size_t count);
char *custom_strncpy(char *strDest, const char *strSource, size_t count);
void *custom_memmove(void *dest, const void *src, size_t count);
int custom_memcmp(const void *buffer1, const void *buffer2, size_t count);
void *custom_memset(void *dest, int c, size_t count);
void *custom_memcpy(void *dest, const void *src, size_t count);

#endif