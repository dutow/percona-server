
#ifndef GLOBAL_DEFAULT_MR_INCLUDED
#define GLOBAL_DEFAULT_MR_INCLUDED

// Temporal fix for boost workaround.hpp 1.73.0 warnings
// See https://github.com/boostorg/config/pull/383/files
#ifndef __clang_major__
#define __clang_major___WORKAROUND_GUARD 1
#else
#define __clang_major___WORKAROUND_GUARD 0
#endif

#include <string>

#include "psi_memory_resource.hpp"

/*inline std::pmr::memory_resource* std::pmr::get_default_resource() noexcept {
  psi_memory_resource *global_default_mr = new psi_memory_resource{};
  return global_default_mr;
}*/

// using erasing_psi_memory_resource = erasing_memory_resource;
using pmr_string =
    std::pmr::string;

#endif  // GLOBAL_DEFAULT_MR_INCLUDED
