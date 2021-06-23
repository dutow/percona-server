#include "mysqlpp/service_guard.hpp"

#include <cassert>
#include <stdexcept>

#include "mysqlpp/plugin_registry_guard.hpp"

namespace mysqlpp {

service_guard_base::service_guard_base(
    mysqlpp::plugin_registry_guard &plugin_registry, const char *service_name)
    : impl_{nullptr, {&plugin_registry.get_service()}} {
  my_h_service acquired_service{nullptr};
  if (plugin_registry.get_service().acquire(service_name, &acquired_service) ||
      acquired_service == nullptr)
    throw std::runtime_error{"unable to acquire service from the registry"};
  impl_.reset(acquired_service);
}

void service_guard_base::releaser::operator()(my_h_service srv) const noexcept {
  assert(parent != nullptr);
  if (srv != nullptr) parent->release(srv);
}

}  // namespace mysqlpp
