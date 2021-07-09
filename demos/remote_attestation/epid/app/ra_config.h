#ifndef REMOTE_ATTESTATION_RA_CONFIG_H_
#define REMOTE_ATTESTATION_RA_CONFIG_H_

#include <string>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/ra_conf_api.h"

constexpr char kRaConf[] = "ra_config.json";

constexpr char kConfIasServer[] = "ias_url";
constexpr char kConfIasCert[] = "ias_sp_cert_file";
constexpr char kConfIasKey[] = "ias_sp_key_file";
constexpr char kConfIasAccessKey[] = "ias_access_key";
constexpr char kConfSPID[] = "enclave_spid";

#define RA_CONF_STR(name) TeeConfGetStr(kRaConf, name)
#define RA_CONF_FILE(name) TeeConfGetStr(kRaConf, name)

#endif  // REMOTE_ATTESTATION_RA_CONFIG_H_
