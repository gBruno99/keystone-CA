#include "custom_functions.h"
#include "custom_string.h"

// pk.c
const mbedtls_pk_info_t *mbedtls_pk_info_from_type(mbedtls_pk_type_t pk_type)
{
    switch (pk_type)
    {
// #if defined(MBEDTLS_RSA_C)
//         case MBEDTLS_PK_RSA:
//             return &mbedtls_rsa_info;
// #endif /* MBEDTLS_RSA_C */
#if defined(MBEDTLS_ECP_LIGHT)
    case MBEDTLS_PK_ECKEY:
        return &mbedtls_eckey_info;
    case MBEDTLS_PK_ECKEY_DH:
        return &mbedtls_eckeydh_info;
#endif /* MBEDTLS_ECP_LIGHT */
#if defined(MBEDTLS_PK_CAN_ECDSA_SOME)
    case MBEDTLS_PK_ECDSA:
        return &mbedtls_ecdsa_info;
#endif /* MBEDTLS_PK_CAN_ECDSA_SOME */
    /* MBEDTLS_PK_RSA_ALT omitted on purpose */
    default:
        return NULL;
    }
}

int mbedtls_pk_setup(mbedtls_pk_context *ctx, const mbedtls_pk_info_t *info)
{
    if (info == NULL || ctx->pk_info != NULL)
    {
        return MBEDTLS_ERR_PK_BAD_INPUT_DATA;
    }

    if ((ctx->pk_ctx = info->ctx_alloc_func()) == NULL)
    {
        return MBEDTLS_ERR_PK_ALLOC_FAILED;
    }

    ctx->pk_info = info;

    return 0;
}

mbedtls_pk_type_t mbedtls_pk_get_type(const mbedtls_pk_context *ctx)
{
    if (ctx == NULL || ctx->pk_info == NULL)
    {
        return MBEDTLS_PK_NONE;
    }

    return ctx->pk_info->type;
}
