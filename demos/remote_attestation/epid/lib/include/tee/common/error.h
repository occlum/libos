#ifndef REMOTE_ATTESTATION_LIB_INCLUDE_TEE_COMMON_ERROR_H_
#define REMOTE_ATTESTATION_LIB_INCLUDE_TEE_COMMON_ERROR_H_

/* clang-format off */

/* Define TeeErrorCode to include the error code
 * from both Intel SDK and ourself code */
typedef int TeeErrorCode;

#define TEE_MK_ERROR(x)                          (0xFFFF0000&((x) << 16))

#define TEE_SUCCESS                              (0x00000000)

#define TEE_ERROR_GENERIC                        TEE_MK_ERROR(0x0001)
#define TEE_ERROR_PARAMETERS                     TEE_MK_ERROR(0x0002)
#define TEE_ERROR_MALLOC                         TEE_MK_ERROR(0x0003)
#define TEE_ERROR_ENCLAVE_NOTINITIALIZED         TEE_MK_ERROR(0x0004)
#define TEE_ERROR_REPORT_DATA_SIZE               TEE_MK_ERROR(0x0005)
#define TEE_ERROR_PARSE_CONFIGURATIONS           TEE_MK_ERROR(0x0006)
#define TEE_ERROR_PARSE_COMMANDLINE              TEE_MK_ERROR(0x0007)

#define TEE_ERROR_FILE_OPEN                      TEE_MK_ERROR(0x0101)
#define TEE_ERROR_FILE_READ                      TEE_MK_ERROR(0x0102)
#define TEE_ERROR_FILE_WRITE                     TEE_MK_ERROR(0x0103)

#define TEE_ERROR_CONF_LOAD                      TEE_MK_ERROR(0x0201)
#define TEE_ERROR_CONF_NOTEXIST                  TEE_MK_ERROR(0x0202)

#define TEE_ERROR_IAS_CLIENT_INIT                TEE_MK_ERROR(0x0501)
#define TEE_ERROR_IAS_CLIENT_CONNECT             TEE_MK_ERROR(0x0502)
#define TEE_ERROR_IAS_CLIENT_GETSIGRL            TEE_MK_ERROR(0x0503)
#define TEE_ERROR_IAS_CLIENT_GETREPORT           TEE_MK_ERROR(0x0504)
#define TEE_ERROR_IAS_CLIENT_UNESCAPE            TEE_MK_ERROR(0x0505)
#define TEE_ERROR_IAS_LOAD_CACHED_REPORT         TEE_MK_ERROR(0x0506)

#define TEE_ERROR_SDK_UNEXPECTED                 TEE_MK_ERROR(0x0FFF)

#define TEE_ERROR_CODE(rc) (rc)
#define TEE_ERROR_MERGE(ecallcode, retcode) ((ecallcode) | (retcode))

/* clang-format on */

#endif  // REMOTE_ATTESTATION_LIB_INCLUDE_TEE_COMMON_ERROR_H_
