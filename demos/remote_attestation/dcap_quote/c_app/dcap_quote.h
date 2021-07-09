#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "sgx_urts.h"
#include "sgx_report.h"
#include "sgx_qve_header.h"
#include "sgx_dcap_ql_wrapper.h"
#include "sgx_pce.h"
#include "sgx_error.h"

void *dcap_quote_open(void);

uint32_t dcap_get_quote_size(void *handle);

int32_t dcap_generate_quote(void *handle, uint8_t *quote_buf, const sgx_report_data_t *report_data);

uint32_t dcap_get_supplemental_data_size(void *handle);

int32_t dcap_verify_quote(void *handle,
                          const uint8_t *quote_buf,
                          uint32_t quote_size,
                          uint32_t *collateral_expiration_status,
                          sgx_ql_qv_result_t *quote_verification_result,
                          uint32_t supplemental_data_size,
                          uint8_t *supplemental_data);


void dcap_quote_close(void *handle);
