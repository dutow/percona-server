#ifndef MYSQLPP_SERVICE_TRAITS_HPP
#define MYSQLPP_SERVICE_TRAITS_HPP

#include "mysqlpp/service_traits_fwd.hpp"

#include <mysql/components/service.h>
#include <mysql/components/services/log_builtins.h>

namespace mysqlpp {

#define DECLARE_SERVICE_TRAITS_SPECIALIZATION(SERVICE, NAME)        \
  template <>                                                       \
  struct service_traits<SERVICE_TYPE(SERVICE)> {                    \
    static const char *get_service_name() noexcept { return NAME; } \
  };

DECLARE_SERVICE_TRAITS_SPECIALIZATION(log_builtins_string,
                                      "log_builtins_string.mysql_server")
DECLARE_SERVICE_TRAITS_SPECIALIZATION(log_builtins, "log_builtins.mysql_server")

#undef DECLARE_SERVICE_TRAITS_SPECIALIZATION

}  // namespace mysqlpp

#endif
