#ifndef CUSTOM_STRING_H
#define CUSTOM_STRING_H

#include <stdint.h>
#include <stddef.h>

size_t my_strlen(const char *str);
int my_strncmp(const char *string1, const char *string2, size_t count);
char *my_strncpy(char *strDest, const char *strSource, size_t count);
void *my_memmove(void *dest, const void *src, size_t count);
int my_memcmp(const void *buffer1, const void *buffer2, size_t count);
void *my_memset(void *dest, int c, size_t count);
void *my_memcpy(void *dest, const void *src, size_t count);

#endif