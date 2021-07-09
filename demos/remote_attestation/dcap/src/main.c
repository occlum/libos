#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include "quote_generation.h"
#include "quote_verification.h"

int main() {
    int sgx_fd;
    if ((sgx_fd = open("/dev/sgx", O_RDONLY)) < 0) {
        printf("failed to open /dev/sgx\n");
        return -1;
    }

    uint32_t quote_size = get_quote_size(sgx_fd);

    uint8_t *quote_buffer = (uint8_t *)malloc(quote_size);
    if (NULL == quote_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        close(sgx_fd);
        return -1;
    }
    memset(quote_buffer, 0, quote_size);

    sgx_report_data_t report_data = { 0 };
    char *data = "ioctl DCAP report data example";
    memcpy(report_data.d, data, strlen(data));

    sgxioc_gen_dcap_quote_arg_t gen_quote_arg = {
        .report_data = &report_data,
        .quote_len = &quote_size,
        .quote_buf = quote_buffer
    };

    if (generate_quote(sgx_fd, &gen_quote_arg) != 0) {
        printf("failed to generate quote\n");
        close(sgx_fd);
        return -1;
    }

    printf("Succeed to generate the quote!\n");

    uint32_t supplemental_size = get_supplemental_data_size(sgx_fd);

    uint8_t *supplemental_buffer = (uint8_t *)malloc(supplemental_size);
    if (NULL == supplemental_buffer) {
        printf("Couldn't allocate quote_buffer\n");
        close(sgx_fd);
        return -1;
    }
    memset(supplemental_buffer, 0, supplemental_size);

    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;

    sgxioc_ver_dcap_quote_arg_t ver_quote_arg = {
        .quote_buf = quote_buffer,
        .quote_size = quote_size,
        .collateral_expiration_status = &collateral_expiration_status,
        .quote_verification_result = &quote_verification_result,
        .supplemental_data_size = supplemental_size,
        .supplemental_data = supplemental_buffer
    };

    if (verify_quote(sgx_fd, &ver_quote_arg) != 0 ) {
        printf("failed to verify quote\n");
        close(sgx_fd);
        return -1;
    }

    close(sgx_fd);

    if (collateral_expiration_status != 0) {
        printf("the verification collateral has expired\n");
    }

    switch (quote_verification_result) {
        case SGX_QL_QV_RESULT_OK:
            printf("Succeed to verify the quote!\n");
            return 0;
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("WARN: App: Verification completed with Non-terminal result: %x\n",
                   quote_verification_result);
            return 0;
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
        case SGX_QL_QV_RESULT_REVOKED:
        case SGX_QL_QV_RESULT_UNSPECIFIED:
        default:
            printf("\tError: App: Verification completed with Terminal result: %x\n",
                   quote_verification_result);
    }

    return 0;
}
