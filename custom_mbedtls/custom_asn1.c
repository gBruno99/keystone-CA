#include "custom_functions.h"
#include "custom_string.h"

// asn1parse.c
/*
void mbedtls_asn1_free_named_data_list(mbedtls_asn1_named_data **head)
{
    mbedtls_asn1_named_data *cur;

    while ((cur = *head) != NULL) {
        *head = cur->next;
        mbedtls_free(cur->oid.p);
        mbedtls_free(cur->val.p);
        mbedtls_free(cur);
    }
}
*/
// asn1write.c
/*
mbedtls_asn1_named_data *mbedtls_asn1_store_named_data(
    mbedtls_asn1_named_data **head,
    const char *oid, size_t oid_len,
    const unsigned char *val,
    size_t val_len)
{
    mbedtls_asn1_named_data *cur;

    if ((cur = asn1_find_named_data(*head, oid, oid_len)) == NULL) {
        // Add new entry if not present yet based on OID
        //
        cur = (mbedtls_asn1_named_data *) mbedtls_calloc(1,
                                                         sizeof(mbedtls_asn1_named_data));
        if (cur == NULL) {
            return NULL;
        }

        cur->oid.len = oid_len;
        cur->oid.p = mbedtls_calloc(1, oid_len);
        if (cur->oid.p == NULL) {
            mbedtls_free(cur);
            return NULL;
        }

        memcpy(cur->oid.p, oid, oid_len);

        cur->val.len = val_len;
        if (val_len != 0) {
            cur->val.p = mbedtls_calloc(1, val_len);
            if (cur->val.p == NULL) {
                mbedtls_free(cur->oid.p);
                mbedtls_free(cur);
                return NULL;
            }
        }

        cur->next = *head;
        *head = cur;
    } else if (val_len == 0) {
        mbedtls_free(cur->val.p);
        cur->val.p = NULL;
    } else if (cur->val.len != val_len) {

         //* Enlarge existing value buffer if needed
         //* Preserve old data until the allocation succeeded, to leave list in
         //* a consistent state in case allocation fails.
        void *p = mbedtls_calloc(1, val_len);
        if (p == NULL) {
            return NULL;
        }

        mbedtls_free(cur->val.p);
        cur->val.p = p;
        cur->val.len = val_len;
    }

    if (val != NULL && val_len != 0) {
        memcpy(cur->val.p, val, val_len);
    }

    return cur;
}
*/
mbedtls_asn1_named_data *asn1_find_named_data(
    mbedtls_asn1_named_data *list,
    const char *oid, size_t len)
{
    while (list != NULL)
    {
        if (list->oid.len == len &&
            memcmp(list->oid.p, oid, len) == 0)
        {
            break;
        }

        list = list->next;
    }

    return list;
}