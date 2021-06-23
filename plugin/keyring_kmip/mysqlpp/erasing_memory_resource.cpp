#include "mysqlpp/erasing_memory_resource.hpp"

namespace mysqlpp {

/*static*/ void erasing_memory_resource::secure_erase(
    void *p, std::size_t bytes) noexcept {
#if defined(_WIN32)
  SecureZeroMemory(p, bytes);
#elif defined(HAVE_MEMSET_S)
  memset_s(p, bytes, 0, bytes);
#else
  std::size_t n = bytes;
  volatile unsigned char *ptr = static_cast<unsigned char *>(p);
  while (n--) *ptr++ = 0;
#endif
}

}  // namespace mysqlpp
