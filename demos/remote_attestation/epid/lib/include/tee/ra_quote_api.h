/**
 * @brief This header file provides the C APIs to use /dev/sgx device directly.
 *
 * As a C++ language developer, you can also use the C++ classes declared
 * in ra_quote.h file. The C++ classes provide more convenient metheds.
 */

#ifndef REMOTE_ATTESTATION_LIB_INCLUDE_RA_QUOTE_API_H_
#define REMOTE_ATTESTATION_LIB_INCLUDE_RA_QUOTE_API_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/type.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialization for getting enclave quote
 * @param gid   return GID for getting SigRL from attestation server
 * @return Function run successfully or failed
 *   @retval 0 on success
 *   @retval Others when failed
 */
TeeErrorCode InitializeQuote(sgx_epid_group_id_t* gid);

/**
 * @brief Get enclave quote for remote attestation
 * @param quote_args    All the input parameters required by get quote function.
 *                      The output buffer is also in this structure. Please
 *                      refer to the description of it in type.h header file.
 * @return Function run successfully or failed
 *   @retval 0 on success
 *   @retval Others when failed
 */
TeeErrorCode GetQuote(EnclaveQuoteArgs* quote_args);

#ifdef __cplusplus
}
#endif

#endif  // REMOTE_ATTESTATION_LIB_INCLUDE_RA_MANAGER_API_H_
