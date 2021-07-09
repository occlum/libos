#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "tee/common/error.h"
#include "tee/common/log.h"
#include "tee/ra_json.h"

namespace ra {
namespace occlum {

std::string JsonConfig::ReadStringFile(const std::string& filename) {
  std::string str;

  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  if (!ifs) {
    TEE_LOG_ERROR("Fail to open file \"%s\"\n", filename.c_str());
    return str;
  }

  ifs.seekg(0, std::ios::end);
  int length = ifs.tellg();
  ifs.seekg(0, std::ios::beg);

  std::vector<char> buf(length);
  ifs.read(buf.data(), length);
  if (ifs.fail()) {
    TEE_LOG_ERROR("Fail to read file \"%s\"\n", filename.c_str());
    return str;
  }

  str.assign(buf.data(), length);
  return str;
}

bool JsonConfig::ConfigFileExists(const std::string& filename) {
  std::ifstream ifs(filename, std::ios::binary | std::ios::in);
  return ifs.good();
}

JsonConfig* JsonConfig::GetInstance() {
  static JsonConfig instance;
  return &instance;
}

template <typename T>
bool JsonConfig::CheckString(const T& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsString()) {
    TEE_LOG_DEBUG("%s is missed or not string in config file", name);
    return false;
  }
  return true;
}

template <typename T>
bool JsonConfig::CheckArray(const T& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsArray()) {
    TEE_LOG_DEBUG("%s is missed or not array in config file", name);
    return false;
  }
  return true;
}

template <typename T>
bool JsonConfig::CheckInt(const T& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsInt()) {
    TEE_LOG_DEBUG("%s is missed or not integer in config file", name);
    return false;
  }
  return true;
}

template <typename T>
bool JsonConfig::CheckObj(const T& conf, const char* name) {
  if (!conf.HasMember(name) || !conf[name].IsObject()) {
    TEE_LOG_DEBUG("%s is missed or not object in config file", name);
    return false;
  }
  return true;
}

template <typename T>
std::string JsonConfig::GetStr(const T& conf, const char* name,
                               const std::string& default_val) {
  if (CheckString(conf, name)) {
    std::string value = conf[name].GetString();
    TEE_LOG_DEBUG("%s=%s", name, value.c_str());
    return value;
  } else {
    TEE_LOG_DEBUG("Not string type, %s=%s[default]", name, default_val);
    return default_val;
  }
}

template <typename T>
TeeErrorCode JsonConfig::GetStrArray(const T& conf, const char* name,
                                     std::vector<std::string>* values) {
  if (CheckArray(conf, name)) {
    const rapidjson::Value& val_array = conf[name];
    size_t count = val_array.Size();
    for (size_t i = 0; i < count; i++) {
      if (val_array[i].IsString()) {
        std::string val_str = val_array[i].GetString();
        TEE_LOG_DEBUG("%s[%ld]=%s", name, i, val_str.c_str());
        values->push_back(val_str);
      } else {
        TEE_LOG_ERROR("Invalid string type in Array");
        return TEE_ERROR_PARSE_CONFIGURATIONS;
      }
    }
  } else {
    TEE_LOG_DEBUG("Invalid Array type");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }
  return TEE_SUCCESS;
}

template <typename T>
TeeErrorCode JsonConfig::GetInt(const T& conf, const char* name, int* value) {
  if (!CheckInt(conf, name)) {
    TEE_LOG_ERROR("Not integer type: %s", name);
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  *value = conf[name].GetInt();
  TEE_LOG_DEBUG("%s=%d", name, *value);
  return TEE_SUCCESS;
}

std::string JsonConfig::GetConfigFilename(const std::string& filename) {
  // First priority, the absolute path filename or file in current directory
  if (ConfigFileExists(filename)) {
    TEE_LOG_DEBUG("Configuration file: %s", filename.c_str());
    return filename;
  }

  // Finally, try to find configuration file in /etc directory
  std::string etcpath = "/etc/";
  etcpath += filename;
  if (ConfigFileExists(etcpath)) {
    TEE_LOG_DEBUG("Configuration file: %s", etcpath.c_str());
    return etcpath;
  }

  // If cannot find configuration file, return empty string
  TEE_LOG_ERROR("Cannot find configuration file: %s", filename.c_str());
  return "";
}

TeeErrorCode JsonConfig::LoadConfiguration(const std::string& filename) {
  if (filename.empty()) {
    TEE_LOG_ERROR("Empty configuration file name");
    return TEE_ERROR_CONF_NOTEXIST;
  }

  std::string config_file = GetConfigFilename(filename);
  if (config_file.empty()) {
    TEE_LOG_ERROR("Fail to find configuration file");
    return TEE_ERROR_CONF_NOTEXIST;
  }

  std::string config_str = ReadStringFile(config_file);
  if (config_str.empty()) {
    TEE_LOG_ERROR("Fail to read configuration file");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  TeeJsonDocPtr doc(new rapidjson::Document);
  if (doc.get()->Parse(config_str.data()).HasParseError()) {
    TEE_LOG_ERROR("Fail to parse json configration file");
    return TEE_ERROR_PARSE_CONFIGURATIONS;
  }

  cfgs_.emplace(filename, doc);
  TEE_LOG_DEBUG("Load configuration file %s successfully", filename.c_str());
  return TEE_SUCCESS;
}

std::string JsonConfig::ConfGetStr(const std::string& conf_file,
                                   const char* name,
                                   const std::string& default_val) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_DEBUG("Load config failed, %s=%s[default]", name, default_val);
      return default_val;
    }
  }

  return GetStr(*cfgs_[conf_file].get(), name, default_val);
}

std::string JsonConfig::ConfGetFileStr(const std::string& conf_file,
                                       const char* name,
                                       const std::string& default_val) {
  TEE_LOG_DEBUG("Get string from %s", name);
  std::string filename = ConfGetStr(conf_file, name, default_val);
  return ReadStringFile(filename);
}

TeeErrorCode JsonConfig::ConfGetStrArray(const std::string& conf_file,
                                         const char* name,
                                         std::vector<std::string>* values) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_DEBUG("Fail to load configuration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
  }

  return GetStrArray(*cfgs_[conf_file].get(), name, values);
}

TeeErrorCode JsonConfig::ConfGetInt(const std::string& conf_file,
                                    const char* name, int* value) {
  TEE_LOG_DEBUG("Get %s from %s", name, conf_file.c_str());

  if (cfgs_.find(conf_file) == cfgs_.end()) {
    if (LoadConfiguration(conf_file) != TEE_SUCCESS) {
      TEE_LOG_ERROR("Fail to load configuration file");
      return TEE_ERROR_PARSE_CONFIGURATIONS;
    }
  }

  return GetInt(*cfgs_[conf_file].get(), name, value);
}

}  // namespace occlum
}  // namespace ra

#ifdef __cplusplus
extern "C" {
#endif

std::string TeeConfGetStr(const std::string& conf_file, const char* name,
                          const std::string& default_val) {
  return ra::occlum::JsonConfig::GetInstance()->ConfGetStr(conf_file, name,
                                                           default_val);
}

std::string TeeConfGetFileStr(const std::string& conf_file, const char* name,
                              const std::string& default_val) {
  return ra::occlum::JsonConfig::GetInstance()->ConfGetFileStr(conf_file, name,
                                                               default_val);
}

TeeErrorCode TeeConfGetStrArray(const std::string& conf_file, const char* name,
                                std::vector<std::string>* values) {
  return ra::occlum::JsonConfig::GetInstance()->ConfGetStrArray(conf_file, name,
                                                                values);
}

TeeErrorCode TeeConfGetInt(const std::string& conf_file, const char* name,
                           int* value) {
  return ra::occlum::JsonConfig::GetInstance()->ConfGetInt(conf_file, name,
                                                           value);
}

#ifdef __cplusplus
}
#endif
