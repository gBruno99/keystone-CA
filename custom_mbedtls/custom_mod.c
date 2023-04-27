#include "custom_functions.h"
#include "custom_string.h"

// asn1parse.c
void mbedtls_asn1_free_named_data_list_mod(int *ne)
{
    *ne = 0;
}