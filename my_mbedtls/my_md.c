#include "custom_functions.h"
#include "sha3.h"

const custom_md_info_t custom_keystone_sha3_info = {
    "KEYSTONE_SHA3",
    CUSTOM_MD_KEYSTONE_SHA3,
    CUSTOM_HASH_MAX_SIZE,
    200 - 2*CUSTOM_HASH_MAX_SIZE,
};

const custom_md_info_t *custom_md_info_from_type(custom_md_type_t md_type)
{
    switch (md_type) {
        case CUSTOM_MD_KEYSTONE_SHA3:
            return &custom_keystone_sha3_info;
        default:
            return NULL;
    }
}

int custom_md(const custom_md_info_t *md_info, const unsigned char *input, size_t ilen,
               unsigned char *output)
{
    if (md_info == NULL) {
        return CUSTOM_ERR_MD_BAD_INPUT_DATA;
    }

    switch (md_info->type) {
        case CUSTOM_MD_KEYSTONE_SHA3:
            sha3(input, ilen, output, CUSTOM_HASH_MAX_SIZE);
            return 0;
        default:
            return CUSTOM_ERR_MD_BAD_INPUT_DATA;
    }
}

unsigned char custom_md_get_size(const custom_md_info_t *md_info)
{
    if (md_info == NULL) {
        return 0;
    }

    return md_info->size;
}

