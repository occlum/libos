#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sgx_quote_3.h"
#include "dcap_quote.h"

void main() {
    void *handle;
    uint32_t quote_size, supplemental_size;
    uint8_t *p_quote_buffer, *p_supplemental_buffer;
    sgx_quote3_t *p_quote;
    sgx_report_body_t *p_rep_body;
    sgx_report_data_t *p_rep_data;
    sgx_ql_auth_data_t *p_auth_data;
    sgx_ql_ecdsa_sig_data_t *p_sig_data;
    sgx_ql_certification_data_t *p_cert_data;
    int32_t ret;
    
    handle = dcap_quote_open();
    quote_size = dcap_get_quote_size(handle);
    printf("quote size = %d\n", quote_size);

    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        goto CLEANUP;
    }
    memset(p_quote_buffer, 0, quote_size);

    sgx_report_data_t report_data = { 0 };
    char *data = "ioctl DCAP report data example";
    memcpy(report_data.d, data, strlen(data));

    // Get the Quote
    ret = dcap_generate_quote(handle, p_quote_buffer, &report_data);
    if (0 != ret) {
        printf( "Error in dcap_generate_quote.\n");
        goto CLEANUP;
    }

    printf("DCAP generate quote successfully\n");

    p_quote = (sgx_quote3_t *)p_quote_buffer;
    p_rep_body = (sgx_report_body_t *)(&p_quote->report_body);
    p_rep_data = (sgx_report_data_t *)(&p_rep_body->report_data);
    p_sig_data = (sgx_ql_ecdsa_sig_data_t *)p_quote->signature_data;
    p_auth_data = (sgx_ql_auth_data_t*)p_sig_data->auth_certification_data;
    p_cert_data = (sgx_ql_certification_data_t *)((uint8_t *)p_auth_data + sizeof(*p_auth_data) + p_auth_data->size);

    if (memcmp((void *)p_rep_data, (void *)&report_data, sizeof(sgx_report_data_t)) != 0) {
        printf("mismathced report data\n");
        goto CLEANUP;
    }

    printf("cert_key_type = 0x%x\n", p_cert_data->cert_key_type);

    supplemental_size = dcap_get_supplemental_data_size(handle);
    printf("supplemental_size size = %d\n", supplemental_size);
    p_supplemental_buffer = (uint8_t *)malloc(supplemental_size);
    if (NULL == p_supplemental_buffer) {
        printf("Couldn't allocate supplemental buffer\n");
        goto CLEANUP;
    }
    memset(p_supplemental_buffer, 0, supplemental_size);

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    ret = dcap_verify_quote(
        handle,
        p_quote_buffer,
        quote_size,
        &collateral_expiration_status,
        &quote_verification_result,
        supplemental_size,
        p_supplemental_buffer
        );
    
    if (0 != ret) {
        printf( "Error in dcap_verify_quote.\n");
        goto CLEANUP;
    }

    if (collateral_expiration_status != 0) {
        printf("the verification collateral has expired\n");
    }

    switch (quote_verification_result) {
        case SGX_QL_QV_RESULT_OK:
            printf("Succeed to verify the quote!\n");
            break;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("WARN: App: Verification completed with Non-terminal result: %x\n",
                   quote_verification_result);
            break;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            printf("\tError: App: Verification completed with Terminal result: %x\n",
                   quote_verification_result);
            goto CLEANUP;
    }

    printf("DCAP verify quote successfully\n");

CLEANUP:
    if (NULL != p_quote_buffer) {
        free(p_quote_buffer);
    }

    if (NULL != p_supplemental_buffer) {
        free(p_supplemental_buffer);
    }

    dcap_quote_close(handle);
}
