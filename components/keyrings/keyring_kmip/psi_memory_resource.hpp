#ifndef MYSQLPP_PSI_MEMORY_RESOURCE_HPP
#define MYSQLPP_PSI_MEMORY_RESOURCE_HPP

#include "mysqlpp/psi_memory_resource_fwd.hpp"

#include <boost/container/pmr/memory_resource.hpp>

namespace mysqlpp {

// TODO: implement with "psi_memory_service.h"
class psi_memory_resource : public boost::container::pmr::memory_resource {
 protected:
  virtual void *do_allocate(std::size_t bytes,
                            std::size_t /*alignment*/) override {
    return new char[bytes];
  }

  virtual void do_deallocate(void *p, std::size_t /*bytes*/,
                             std::size_t /*alignment*/) override {
    delete[] static_cast<char *>(p);
  }

  virtual bool do_is_equal(const boost::container::pmr::memory_resource &other)
      const noexcept override {
    return &other == this;
  }
};

}  // namespace mysqlpp

#endif
