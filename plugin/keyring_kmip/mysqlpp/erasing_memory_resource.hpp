#ifndef MYSQLPP_ERASING_MEMORY_RESOURCE_HPP
#define MYSQLPP_ERASING_MEMORY_RESOURCE_HPP

#include "mysqlpp/erasing_memory_resource_fwd.hpp"

#include <boost/container/pmr/memory_resource.hpp>

namespace mysqlpp {

class erasing_memory_resource : public boost::container::pmr::memory_resource {
 public:
  explicit erasing_memory_resource(
      boost::container::pmr::memory_resource &parent) noexcept
      : parent_{&parent} {}

 protected:
  virtual void *do_allocate(std::size_t bytes, std::size_t alignment) override {
    return parent_->allocate(bytes, alignment);
  }

  virtual void do_deallocate(void *p, std::size_t bytes,
                             std::size_t alignment) override {
    secure_erase(p, bytes);
    return parent_->deallocate(p, bytes, alignment);
  }

  virtual bool do_is_equal(const boost::container::pmr::memory_resource &other)
      const noexcept override {
    return &other == this;
  }

 private:
  boost::container::pmr::memory_resource *parent_;
  static void secure_erase(void *p, std::size_t bytes) noexcept;
};

}  // namespace mysqlpp

#endif
