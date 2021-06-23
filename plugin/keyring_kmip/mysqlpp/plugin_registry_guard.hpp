#ifndef MYSQLPP_PLUGIN_REGISTRY_GUARD_HPP
#define MYSQLPP_PLUGIN_REGISTRY_GUARD_HPP

#include <memory>

#include <mysql/components/services/registry.h>

#include "mysqlpp/plugin_registry_guard_fwd.hpp"

namespace mysqlpp {

class plugin_registry_guard {
 public:
  plugin_registry_guard();

  SERVICE_TYPE(registry) & get_service() const noexcept { return *impl_; }

 private:
  struct releaser {
    void operator()(SERVICE_TYPE(registry) * srv) const noexcept;
  };

  using plugin_registry_registry_ptr =
      std::unique_ptr<SERVICE_TYPE(registry), releaser>;
  plugin_registry_registry_ptr impl_;
};

}  // namespace mysqlpp

#endif
