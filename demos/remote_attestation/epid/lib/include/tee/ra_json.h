#ifndef REMOTE_ATTESTATION_LIB_INCLUDE_TEE_RA_JSON_H_
#define REMOTE_ATTESTATION_LIB_INCLUDE_TEE_RA_JSON_H_

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "rapidjson/document.h"

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/common/type.h"

namespace ra {
namespace occlum {

typedef std::shared_ptr<rapidjson::Document> TeeJsonDocPtr;
typedef std::map<std::string, TeeJsonDocPtr> TeeJsonConfMap;

class JsonConfig {
 public:
  // Gets the singleton Unit Test object.
  static JsonConfig* GetInstance();

  // To support both rapidjson::Document and rapidjson::Value
  template <typename T>
  static bool CheckString(const T& conf, const char* name);
  template <typename T>
  static bool CheckArray(const T& conf, const char* name);
  template <typename T>
  static bool CheckInt(const T& conf, const char* name);
  template <typename T>
  static bool CheckObj(const T& conf, const char* name);
  template <typename T>
  static std::string GetStr(const T& conf, const char* name,
                            const std::string& default_val = "");
  template <typename T>
  static TeeErrorCode GetStrArray(const T& conf, const char* name,
                                  std::vector<std::string>* values);
  template <typename T>
  static TeeErrorCode GetInt(const T& conf, const char* name, int* value);

  // Load configuration files and then parse and get value(s)
  std::string ConfGetStr(const std::string& conf_file, const char* name,
                         const std::string& default_val = "");
  std::string ConfGetFileStr(const std::string& conf_file, const char* name,
                             const std::string& default_val = "");
  TeeErrorCode ConfGetStrArray(const std::string& conf_file, const char* name,
                               std::vector<std::string>* values);
  TeeErrorCode ConfGetInt(const std::string& conf_file, const char* name,
                          int* value);

 private:
  // Hide construction functions
  JsonConfig() {}
  JsonConfig(const JsonConfig&);
  void operator=(JsonConfig const&);

  std::string ReadStringFile(const std::string& filename);
  bool ConfigFileExists(const std::string& filename);

  std::string GetConfigFilename(const std::string& filename);
  TeeErrorCode LoadConfiguration(const std::string& filename);

  TeeJsonConfMap cfgs_;
};

}  // namespace occlum
}  // namespace ra

#endif  // REMOTE_ATTESTATION_LIB_INCLUDE_TEE_RA_JSON_H_
