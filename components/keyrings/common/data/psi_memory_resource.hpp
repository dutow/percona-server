#ifndef MYSQLPP_PSI_MEMORY_RESOURCE_HPP
#define MYSQLPP_PSI_MEMORY_RESOURCE_HPP

#include "psi_memory_resource_fwd.hpp"

#include <mysql/components/services/psi_memory.h>
#if __has_include(<memory_resource>)
#include <memory_resource>
#else
#include <experimental/memory_resource>
namespace std {
  namespace pmr = std::experimental::pmr;
}
#endif

class psi_memory_resource : public std::pmr::memory_resource {
 protected:
  virtual void *do_allocate(std::size_t bytes,
                            std::size_t /*alignment*/) override;

  virtual void do_deallocate(void *p, std::size_t bytes,
                             std::size_t /*alignment*/) override;

  virtual bool do_is_equal(const std::pmr::memory_resource &other)
      const noexcept override {
    return &other == this;
  }
};

#endif
