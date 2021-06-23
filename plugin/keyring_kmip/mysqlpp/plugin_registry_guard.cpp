#include "mysqlpp/plugin_registry_guard.hpp"

#include <stdexcept>

#include <mysql/service_plugin_registry.h>

namespace mysqlpp {

plugin_registry_guard::plugin_registry_guard()
    : impl_{mysql_plugin_registry_acquire()} {
  if (!impl_) throw std::runtime_error{"unable to acquire plugin regisrty"};
}

void plugin_registry_guard::releaser::operator()(SERVICE_TYPE(registry) *
                                                 srv) const noexcept {
  if (srv != nullptr) mysql_plugin_registry_release(srv);
}

}  // namespace mysqlpp
