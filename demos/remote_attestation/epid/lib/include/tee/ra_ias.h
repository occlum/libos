#ifndef REMOTE_ATTESTATION_LIB_INCLUDE_RA_IAS_H_
#define REMOTE_ATTESTATION_LIB_INCLUDE_RA_IAS_H_

#include <mutex>
#include <string>

#include "./sgx_uae_epid.h"
#include "./sgx_urts.h"
#include "./sgx_utils.h"

#include "curl/curl.h"

#include "tee/common/error.h"
#include "tee/common/type.h"

#define IAS_REPORT_CLASS_MEMBER(x)               \
 public:                                         \
  std::string& x() {                             \
    return x##_;                                 \
  }                                              \
  const std::string& x() const {                 \
    return x##_;                                 \
  }                                              \
  std::string* mutable_##x() {                   \
    return &x##_;                                \
  }                                              \
  void set_##x(const std::string& value) {       \
    x##_ = value;                                \
  }                                              \
  void set_##x(const char* value) {              \
    x##_ = value;                                \
  }                                              \
  void set_##x(const char* value, size_t size) { \
    x##_ = value;                                \
  }                                              \
                                                 \
 private:                                        \
  std::string x##_

namespace ra {
namespace occlum {

/// Data structure to hold the IAS sigrl API response
typedef struct {
  std::string b64_sigrl;
} RaIasSigrl;

/// Data structure to hold the IAS sigrl API response
/// Use this class to simulate the protobuf class
/// don't need to introduce the protobuf dependency
class RaIasReport {
  IAS_REPORT_CLASS_MEMBER(b64_signature);
  IAS_REPORT_CLASS_MEMBER(signing_cert);
  IAS_REPORT_CLASS_MEMBER(advisory_url);
  IAS_REPORT_CLASS_MEMBER(advisory_ids);
  IAS_REPORT_CLASS_MEMBER(response_body);
  IAS_REPORT_CLASS_MEMBER(epid_pseudonym);
  IAS_REPORT_CLASS_MEMBER(quote_status);
  IAS_REPORT_CLASS_MEMBER(b16_platform_info_blob);
  IAS_REPORT_CLASS_MEMBER(b64_quote_body);
};

/// HTTPS client for connecting to IAS
class RaIasClient {
 public:
  explicit RaIasClient(const RaIasServerCfg& ias_server);
  ~RaIasClient();

  /// api: /sigrl/<gid>
  TeeErrorCode GetSigRL(const sgx_epid_group_id_t& gid, std::string* sigrl);

  /// api: /report
  TeeErrorCode FetchReport(const std::string& quote, RaIasReport* ias_report);

 private:
  void InitIasConnection(const std::string& url);

  CURL* curl_ = NULL;
  curl_slist* headers_ = NULL;
  std::string server_endpoint_;

  static std::mutex init_mutex_;
};

}  // namespace occlum
}  // namespace ra

#endif  // REMOTE_ATTESTATION_LIB_INCLUDE_RA_IAS_H_
