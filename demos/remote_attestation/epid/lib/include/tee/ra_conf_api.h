#ifndef REMOTE_ATTESTATION_LIB_INCLUDE_TEE_RA_CONF_API_H_
#define REMOTE_ATTESTATION_LIB_INCLUDE_TEE_RA_CONF_API_H_

#include <string>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

/// Get the string type option in configuration file
std::string TeeConfGetStr(const std::string& conf_file, const char* name,
                          const std::string& default_value = "");

/// If the value of option is filename in the configuration file,
/// use the function to read the file content and return it as string.
std::string TeeConfGetFileStr(const std::string& conf_file, const char* name,
                              const std::string& default_value = "");

/// Get the array type option in configuration file
TeeErrorCode TeeConfGetStrArray(const std::string& conf_file, const char* name,
                                std::vector<std::string>* values);

/// Get the integer type option in configuration file
TeeErrorCode TeeConfGetInt(const std::string& conf_file, const char* name,
                           int* value);

#ifdef __cplusplus
}
#endif

#endif  // REMOTE_ATTESTATION_LIB_INCLUDE_TEE_RA_CONF_API_H_
