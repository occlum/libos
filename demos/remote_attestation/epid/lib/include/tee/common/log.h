#ifndef REMOTE_ATTESTATION_LIB_INCLUDE_TEE_COMMON_LOG_H_
#define REMOTE_ATTESTATION_LIB_INCLUDE_TEE_COMMON_LOG_H_

#include <string>

extern "C" int printf(const char* fmt, ...);

#ifdef DEBUG
#define TEE_LOG_DEBUG(fmt, ...) \
  printf("[DEBUG][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define TEE_LOG_BUFFER(name, ptr, size)                                    \
  do {                                                                     \
    const uint8_t* buffer = reinterpret_cast<const uint8_t*>(ptr);         \
    int len = static_cast<int>((size));                                    \
    printf("Buffer %s[%p], length: %d(0x%x)\n", (name), buffer, len, len); \
    for (int i = 0; i < len; i++) {                                        \
      if (i && (0 == i % 16)) printf("\n");                                \
      printf("%02x ", buffer[i]);                                          \
    }                                                                      \
    printf("\n");                                                          \
  } while (0)

#else
#define TEE_LOG_DEBUG(fmt, ...)
#define TEE_LOG_BUFFER(name, ptr, size)
#endif

#define TEE_LOG_INFO(fmt, ...) \
  printf("[INFO][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define TEE_LOG_WARN(fmt, ...) \
  printf("[WARN][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define TEE_LOG_ERROR(fmt, ...) \
  printf("[ERROR][%s:%d] " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define TEE_LOG_ERROR_TRACE() TEE_LOG_ERROR("[Function] %s", __FUNCTION__)

#define TEE_CHECK_RETURN(r)  \
  do {                       \
    int ret = (r);           \
    if (ret != 0) {          \
      TEE_LOG_ERROR_TRACE(); \
      return ret;            \
    }                        \
  } while (0)

#endif  // REMOTE_ATTESTATION_LIB_INCLUDE_TEE_COMMON_LOG_H_
