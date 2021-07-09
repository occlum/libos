#include <string>

#include "app/ra_config.h"
#include "tee/ra_quote.h"

int main() {
  printf("Remote attestation testing ...\n");

  // Don't need to set IAS key/cert when we used accesskey authentication
  RaIasServerCfg ias_server;
  ias_server.endpoint = RA_CONF_STR(kConfIasServer);
  ias_server.accesskey = RA_CONF_STR(kConfIasAccessKey);
  std::string spid = RA_CONF_STR(kConfSPID);

  // 64Byts report data for adding some project special things if necessary
  sgx_report_data_t report_data = {0};

  ra::occlum::RaEnclaveQuote ra;
  ra::occlum::RaIasReport ias_report;
  int ret = ra.GetEnclaveIasReport(ias_server, spid, report_data, &ias_report);
  if (ret) {
    printf("Fail to get quote or fetch report, error code is %x!\n", ret);
  } else {
    printf("Test getting quote and fetching report successfully!\n");
  }

  return ret;
}
