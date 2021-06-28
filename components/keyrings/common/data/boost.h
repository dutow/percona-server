
#pragma once

#include <boost/container/pmr/polymorphic_allocator.hpp>

#include <boost/container_hash/hash.hpp>

#include "psi_memory_resource.hpp"

extern psi_memory_resource global_default_mr;

inline ::boost::container::pmr::memory_resource
    * ::boost::container::pmr::get_default_resource() {
  return &global_default_mr;
}

//using erasing_psi_memory_resource = erasing_memory_resource;
using pmr_string =
    std::basic_string<char, std::char_traits<char>,
                      boost::container::pmr::polymorphic_allocator<char>>;
