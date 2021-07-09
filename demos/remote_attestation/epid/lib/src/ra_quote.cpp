#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

#include "tee/common/log.h"

#include "tee/ra_ias.h"
#include "tee/ra_quote.h"

#include "cppcodec/base64_rfc4648.hpp"
#include "openssl/rand.h"
using base64 = cppcodec::base64_rfc4648;

#define SGXIOC_GET_EPID_GROUP_ID _IOR('s', 1, sgx_epid_group_id_t)
#define SGXIOC_GEN_QUOTE _IOWR('s', 2, EnclaveQuoteArgs)

constexpr char kSgxDeviceName[] = "/dev/sgx";

namespace ra {
namespace occlum {

TeeErrorCode RaEnclaveQuote::SgxDeviceInitQuote(sgx_epid_group_id_t* gid) {
  int sgx_fd;
  if ((sgx_fd = open(kSgxDeviceName, O_RDONLY)) < 0) {
    TEE_LOG_ERROR("Fail to open %s", kSgxDeviceName);
    return TEE_ERROR_FILE_OPEN;
  }

  TeeErrorCode ret = TEE_SUCCESS;
  if (ioctl(sgx_fd, SGXIOC_GET_EPID_GROUP_ID, gid) < 0) {
    TEE_LOG_ERROR("Fail to get group id from  %s", kSgxDeviceName);
    ret = TEE_ERROR_SDK_UNEXPECTED;
  }

  close(sgx_fd);
  return ret;
}

TeeErrorCode RaEnclaveQuote::SgxDeviceGetQuote(EnclaveQuoteArgs* quote_args) {
  if (!quote_args->quote.as_buf || (quote_args->quote_buf_len == 0)) {
    TEE_LOG_ERROR("Invalid quote buffer or len");
    return TEE_ERROR_PARAMETERS;
  }

  int sgx_fd;
  if ((sgx_fd = open(kSgxDeviceName, O_RDONLY)) < 0) {
    TEE_LOG_ERROR("Fail to open %s", kSgxDeviceName);
    return TEE_ERROR_FILE_OPEN;
  }

  TeeErrorCode ret = TEE_SUCCESS;
  int count = 3;
  while (count--) {
    if (ioctl(sgx_fd, SGXIOC_GEN_QUOTE, quote_args) == 0) {
      uint32_t signature_len = quote_args->quote.as_quote->signature_len;
      TEE_LOG_DEBUG("SgxDeviceGetQuote length=%ld", signature_len);
      if (signature_len == 0) {
        TEE_LOG_ERROR("Invalid quote from %s", kSgxDeviceName);
        ret = TEE_ERROR_SDK_UNEXPECTED;
      }
      break;
    } else if (errno != EAGAIN) {
      TEE_LOG_ERROR("Fail to get quote from %s", kSgxDeviceName);
      ret = TEE_ERROR_SDK_UNEXPECTED;
      break;
    } else {
      TEE_LOG_WARN("/dev/sgx is temporarily busy. Try again after 1s.");
      sleep(1);
    }
  }

  close(sgx_fd);
  return ret;
}

uint8_t RaEnclaveQuote::Hex2Dec(const char hex) {
  if (('0' <= hex) && (hex <= '9')) {
    return hex - '0';
  } else if (('a' <= hex) && (hex <= 'f')) {
    return hex - 'a' + 10;
  } else if (('A' <= hex) && (hex <= 'F')) {
    return hex - 'A' + 10;
  } else {
    // Otherwise return zero for none HEX charactor
    return 0;
  }
}

TeeErrorCode RaEnclaveQuote::GetSpidFromHexStr(const std::string& spid_str) {
  const char* src = spid_str.data();
  const int len = sizeof(sgx_spid_t);
  uint8_t* dst = RCAST(uint8_t*, quote_args_.spid.id);

  if ((spid_str.empty()) || ((len * 2) != spid_str.length())) {
    TEE_LOG_ERROR("Empty SPID or Invalid SPID hexstring length!\n");
    return TEE_ERROR_PARAMETERS;
  }

  for (int i = 0; i < len; i++) {
    dst[i] =
        (Hex2Dec(src[i * 2] & 0xFF) << 4) + (Hex2Dec(src[i * 2 + 1] & 0xFF));
  }
  return TEE_SUCCESS;
}

TeeErrorCode RaEnclaveQuote::GetIasSigRL(const RaIasServerCfg& ias_server) {
  // Initialize the quote firstly
  sgx_epid_group_id_t gid = {0};
  TEE_CHECK_RETURN(SgxDeviceInitQuote(&gid));

  // Try to Get the IAS SigRL, do nothing if failed
  RaIasClient ias_client(ias_server);
  std::string sigrl_str;
  TEE_CHECK_RETURN(ias_client.GetSigRL(gid, &sigrl_str));

  // If there is valid SigRL
  if (!sigrl_str.empty()) {
    TEE_LOG_DEBUG("Set the SigRL, length=%ld", sigrl_str.size());
    quote_args_.sigrl_ptr = RCAST(const uint8_t*, sigrl_str.data());
    quote_args_.sigrl_len = sigrl_str.size();
  }
  return TEE_SUCCESS;
}

TeeErrorCode RaEnclaveQuote::GetEnclaveQuote(
    const RaIasServerCfg& ias_server, const std::string& spid,
    const sgx_report_data_t& report_data) {
  // Firstly, eset all the data
  constexpr int kMaxQuoteLen = 4096;
  quote_buf_.resize(kMaxQuoteLen, 0);
  memset(RCAST(void*, &quote_args_), 0, sizeof(EnclaveQuoteArgs));

  // Initialize the arguments
  quote_args_.quote.as_buf = quote_buf_.data();
  quote_args_.quote_buf_len = quote_buf_.size();
  quote_args_.quote_type = SGX_LINKABLE_SIGNATURE;
  std::memcpy(RCAST(void*, quote_args_.report_data.d),
              RCAST(const void*, report_data.d), sizeof(sgx_report_data_t));
  RAND_bytes(quote_args_.nonce.rand, sizeof(sgx_quote_nonce_t));
  TEE_CHECK_RETURN(GetSpidFromHexStr(spid));
  TEE_CHECK_RETURN(GetIasSigRL(ias_server));

  // Finally, get quote via ioctl device
  TEE_CHECK_RETURN(SgxDeviceGetQuote(&quote_args_));

  return TEE_SUCCESS;
}

TeeErrorCode RaEnclaveQuote::GetEnclaveQuoteB64(
    const RaIasServerCfg& ias_server, const std::string& spid,
    const sgx_report_data_t& report_data, std::string* quote_b64) {
  // Get the enclave quote
  TEE_CHECK_RETURN(GetEnclaveQuote(ias_server, spid, report_data));

  // Convert the quote data to base64 format
  char* quote_ptr = RCAST(char*, quote_args_.quote.as_quote);
  size_t quote_len =
      sizeof(sgx_quote_t) + quote_args_.quote.as_quote->signature_len;
  std::string tmp_quote_b64 = base64::encode(quote_ptr, quote_len);
  quote_b64->assign(tmp_quote_b64);
  TEE_LOG_DEBUG("QuoteB64[%lu]: %s", quote_b64->length(), quote_b64->c_str());

  return TEE_SUCCESS;
}

TeeErrorCode RaEnclaveQuote::GetEnclaveIasReport(
    const RaIasServerCfg& ias_server, const std::string& spid,
    const sgx_report_data_t& report_data, RaIasReport* ias_report) {
  // Get the enclave quote
  TEE_CHECK_RETURN(GetEnclaveQuote(ias_server, spid, report_data));

  // Convert the quote data to a new string for calling IAS client method
  ra::occlum::RaIasClient ias_client(ias_server);
  size_t quote_len =
      sizeof(sgx_quote_t) + quote_args_.quote.as_quote->signature_len;
  std::string quote_str(RCAST(char*, quote_args_.quote.as_quote), quote_len);
  TEE_CHECK_RETURN(ias_client.FetchReport(quote_str, ias_report));

  return TEE_SUCCESS;
}

}  // namespace occlum
}  // namespace ra

#ifdef __cplusplus
extern "C" {
#endif

TeeErrorCode InitializeQuote(sgx_epid_group_id_t* gid) {
  return ra::occlum::RaEnclaveQuote::SgxDeviceInitQuote(gid);
}

TeeErrorCode GetQuote(EnclaveQuoteArgs* quote_args) {
  return ra::occlum::RaEnclaveQuote::SgxDeviceGetQuote(quote_args);
}

#ifdef __cplusplus
}
#endif
