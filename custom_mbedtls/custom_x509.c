#include "custom_functions.h"
#include "custom_string.h"

// x509_create.c
const x509_attr_descriptor_t *x509_attr_descr_from_name(const char *name, size_t name_len)
{
    const x509_attr_descriptor_t *cur;

    for (cur = x509_attrs; cur->name != NULL; cur++)
    {
        if (cur->name_len == name_len &&
            strncmp(cur->name, name, name_len) == 0)
        {
            break;
        }
    }

    if (cur->name == NULL)
    {
        return NULL;
    }

    return cur;
}
/*
int mbedtls_x509_string_to_names(mbedtls_asn1_named_data **head, const char *name)
{
    int ret = 0;
    const char *s = name, *c = s;
    const char *end = s + strlen(s);
    const char *oid = NULL;
    const x509_attr_descriptor_t *attr_descr = NULL;
    int in_tag = 1;
    char data[MBEDTLS_X509_MAX_DN_NAME_SIZE];
    char *d = data;

    // Clear existing chain if present
    mbedtls_asn1_free_named_data_list(head);

    while (c <= end) {
        if (in_tag && *c == '=') {
            if ((attr_descr = x509_attr_descr_from_name(s, c - s)) == NULL) {
                ret = MBEDTLS_ERR_X509_UNKNOWN_OID;
                goto exit;
            }

            oid = attr_descr->oid;
            s = c + 1;
            in_tag = 0;
            d = data;
        }

        if (!in_tag && *c == '\\' && c != end) {
            c++;

            // Check for valid escaped characters
            if (c == end || *c != ',') {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        } else if (!in_tag && (*c == ',' || c == end)) {
            mbedtls_asn1_named_data *cur =
                mbedtls_asn1_store_named_data(head, oid, strlen(oid),
                                              (unsigned char *) data,
                                              d - data);

            if (cur == NULL) {
                return MBEDTLS_ERR_X509_ALLOC_FAILED;
            }

            // set tagType
            cur->val.tag = attr_descr->default_tag;

            while (c < end && *(c + 1) == ' ') {
                c++;
            }

            s = c + 1;
            in_tag = 1;
        }

        if (!in_tag && s != c + 1) {
            *(d++) = *c;

            if (d - data == MBEDTLS_X509_MAX_DN_NAME_SIZE) {
                ret = MBEDTLS_ERR_X509_INVALID_NAME;
                goto exit;
            }
        }

        c++;
    }

exit:

    return ret;
}
*/

// x509write_crt.c
void mbedtls_x509write_crt_init(mbedtls_x509write_cert *ctx)
{
    memset(ctx, 0, sizeof(mbedtls_x509write_cert));

    ctx->version = MBEDTLS_X509_CRT_VERSION_3;
}
/*
int mbedtls_x509write_crt_set_subject_name(mbedtls_x509write_cert *ctx,
                                           const char *subject_name)
{
    return mbedtls_x509_string_to_names(&ctx->subject, subject_name);
}
*/
/*
int mbedtls_x509write_crt_set_issuer_name(mbedtls_x509write_cert *ctx,
                                        const char *issuer_name)
{
  return mbedtls_x509_string_to_names(&ctx->issuer, issuer_name);
}
*/

void mbedtls_x509write_crt_set_subject_key(mbedtls_x509write_cert *ctx,
                                           mbedtls_pk_context *key)
{
    ctx->subject_key = key;
}

void mbedtls_x509write_crt_set_issuer_key(mbedtls_x509write_cert *ctx,
                                          mbedtls_pk_context *key)
{
    ctx->issuer_key = key;
}