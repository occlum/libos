#ifndef REMOTE_ATTESTATION_LIB_INCLUDE_RA_QUOTE_H_
#define REMOTE_ATTESTATION_LIB_INCLUDE_RA_QUOTE_H_

#include <string>
#include <vector>

#include "./sgx_quote.h"
#include "./sgx_report.h"
#include "./sgx_tseal.h"
#include "./sgx_urts.h"

#include "tee/common/error.h"
#include "tee/common/type.h"

#include "tee/ra_ias.h"

namespace ra {
namespace occlum {

class RaEnclaveQuote {
 public:
  // The methods that warp the ioctl device interfaces
  static TeeErrorCode SgxDeviceInitQuote(sgx_epid_group_id_t* gid);
  static TeeErrorCode SgxDeviceGetQuote(EnclaveQuoteArgs* quote_args);

  // The methods which are higher wrapper of quote and IasClient together.
  TeeErrorCode GetEnclaveQuoteB64(const RaIasServerCfg& ias_server,
                                  const std::string& spid,
                                  const sgx_report_data_t& report_data,
                                  std::string* quote_b64);
  TeeErrorCode GetEnclaveIasReport(const RaIasServerCfg& ias_server,
                                   const std::string& spid,
                                   const sgx_report_data_t& report_data,
                                   RaIasReport* ias_report);

 private:
  uint8_t Hex2Dec(const char hex);
  TeeErrorCode GetSpidFromHexStr(const std::string& spid_str);
  TeeErrorCode GetIasSigRL(const RaIasServerCfg& ias_server);
  TeeErrorCode GetEnclaveQuote(const RaIasServerCfg& ias_server,
                               const std::string& spid,
                               const sgx_report_data_t& report_data);

  std::vector<uint8_t> quote_buf_;
  EnclaveQuoteArgs quote_args_;
};

}  // namespace occlum
}  // namespace ra

#endif  // REMOTE_ATTESTATION_LIB_INCLUDE_RA_QUOTE_H_
