#include "include/custom_string.h"

size_t custom_strlen(const char *str)
{
    unsigned int count = 0;
    while(*str!='\0')
    {
        count++;
        str++;
    }
    return count;
}

int custom_strncmp(const char *string1, const char *string2, size_t count)
{
    while ( count && *string1 && ( *string1 == *string2 ) )
    {
        ++string1;
        ++string2;
        --count;
    }
    if ( count == 0 )
    {
        return 0;
    }
    else
    {
        return ( *(unsigned char *)string1 - *(unsigned char *)string2 );
    }
}

// Function to implement `custom_strncpy()` function
char *custom_strncpy(char *strDest, const char *strSource, size_t count)
{
    // return if no memory is allocated to the destination
    if (strDest == NULL) {
        return NULL;
    }
 
    // take a pointer pointing to the beginning of the destination string
    char* ptr = strDest;
 
    // copy first `num` characters of C-string pointed by source
    // into the array pointed by destination
    while (*strSource && count--)
    {
        *strDest = *strSource;
        strDest++;
        strSource++;
    }
 
    // null terminate destination string
    *strDest = '\0';
 
    // the destination is returned by standard `custom_strncpy()`
    return ptr;
}

void *custom_memmove(void *dest, const void *src, size_t count)
{
    char *pDest = (char *)dest;
    const char *pSrc =( const char*)src;
    //allocate memory for tmp array
    /*
    char *tmp  = (char *)malloc(sizeof(char ) * n);
    if(NULL == tmp)
    {
        return NULL;
    }
    else
    {
      */
    unsigned int i = 0;
    // copy src to tmp array
    for(i =0; i < count ; ++i)
    {
        *(pDest + i) = *(pSrc + i);
    }
        /*
        //copy tmp to dest
        for(i =0 ; i < n ; ++i)
        {
            *(pDest + i) = *(tmp + i);
        }
        free(tmp); //free allocated memory
        */
    //}
    return dest;
}

int
custom_memcmp(const void *buffer1, const void *buffer2, size_t count)
{
    const unsigned char *s1 = (const unsigned char*)buffer1;
    const unsigned char *s2 = (const unsigned char*)buffer2;

  while (count-- > 0)
    {
      if (*s1++ != *s2++)
	  return s1[-1] < s2[-1] ? -1 : 1;
    }
  return 0;
}

void *custom_memcpy(void *dest, const void *src, size_t count)
{
  const char* s = src;
  char *d = dest;

  if ((((uintptr_t)dest | (uintptr_t)src) & (sizeof(uintptr_t)-1)) == 0) {
    while ((void*)d < (dest + count - (sizeof(uintptr_t)-1))) {
      *(uintptr_t*)d = *(const uintptr_t*)s;
      d += sizeof(uintptr_t);
      s += sizeof(uintptr_t);
    }
  }

  while (d < (char*)(dest + count))
    *d++ = *s++;

  return dest;
}

void *custom_memset(void *dest, int c, size_t count)
{
  if ((((uintptr_t)dest | count) & (sizeof(uintptr_t)-1)) == 0) {
    uintptr_t word = c & 0xFF;
    word |= word << 8;
    word |= word << 16;
    word |= word << 16 << 16;

    uintptr_t *d = dest;
    while (d < (uintptr_t*)(dest + count))
      *d++ = word;
  } else {
    char *d = dest;
    while (d < (char*)(dest + count))
      *d++ = c;
  }
  return dest;
}