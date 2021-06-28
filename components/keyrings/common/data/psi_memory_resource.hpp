#ifndef MYSQLPP_PSI_MEMORY_RESOURCE_HPP
#define MYSQLPP_PSI_MEMORY_RESOURCE_HPP

#include "psi_memory_resource_fwd.hpp"

#include <boost/container/pmr/memory_resource.hpp>
#include <mysql/components/services/psi_memory.h>
#include "sql/current_thd.h"
#include "sql/sql_class.h"

extern PSI_memory_key KEY_mem_keyring;

// TODO: implement with "psi_memory_service.h"
class psi_memory_resource : public boost::container::pmr::memory_resource {
 protected:
  virtual void *do_allocate(std::size_t bytes,
                            std::size_t /*alignment*/) override {
    if(current_thd) {
      PSI_thread *owner = thd_get_psi(current_thd);
      psi_memory_service->memory_alloc(KEY_mem_keyring, bytes, &owner);
    }
    return new char[bytes];
  }

  virtual void do_deallocate(void *p, std::size_t bytes,
                             std::size_t /*alignment*/) override {
    if(current_thd) {
    PSI_thread *owner = thd_get_psi(current_thd);
    psi_memory_service->memory_free(KEY_mem_keyring, bytes, owner);
    }
    delete[] static_cast<char *>(p);
  }

  virtual bool do_is_equal(const boost::container::pmr::memory_resource &other)
      const noexcept override {
    return &other == this;
  }
};

#endif
