#ifndef MYSQLPP_SERVICE_GUARD_HPP
#define MYSQLPP_SERVICE_GUARD_HPP

#include "mysqlpp/service_guard_fwd.hpp"

#include <memory>
#include <type_traits>

#include <mysql/components/services/registry.h>

#include "mysqlpp/plugin_registry_guard_fwd.hpp"
#include "mysqlpp/service_traits.hpp"

namespace mysqlpp {

class service_guard_base {
 protected:
  service_guard_base(mysqlpp::plugin_registry_guard &plugin_registry,
                     const char *service_name);

  my_h_service get_service_internal() const noexcept { return impl_.get(); }

 private:
  struct releaser {
    SERVICE_TYPE(registry) * parent;
    void operator()(my_h_service srv) const noexcept;
  };

  using my_h_service_raw = std::remove_pointer_t<my_h_service>;
  using service_ptr = std::unique_ptr<my_h_service_raw, releaser>;
  service_ptr impl_;
};

template <typename Service>
class service_guard : private service_guard_base {
 public:
  service_guard(mysqlpp::plugin_registry_guard &plugin_registry)
      : service_guard_base{plugin_registry,
                           service_traits<Service>::get_service_name()} {}

  Service &get_service() const noexcept {
    return *reinterpret_cast<Service *>(get_service_internal());
  }
};

}  // namespace mysqlpp

#endif
