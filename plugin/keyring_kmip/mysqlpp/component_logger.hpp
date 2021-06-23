#ifndef MYSQLPP_COMPONENT_LOGGER_HPP
#define MYSQLPP_COMPONENT_LOGGER_HPP

#include "mysqlpp/component_logger_fwd.hpp"

#include <string>

#include "ext/string_view.hpp"

#include "mysqlpp/plugin_registry_guard_fwd.hpp"
#include "mysqlpp/service_guard.hpp"

namespace mysqlpp {

class component_logger {
 public:
  component_logger(mysqlpp::plugin_registry_guard &plugin_registry,
                   ext::string_view component_name,
                   ext::string_view message_prefix);

  void log(longlong severity, longlong errcode, const char *subsys,
           longlong source_line, const char *source_file, const char *function,
           const std::string &message) const noexcept;

 private:
  using log_builtins_service_guard =
      mysqlpp::service_guard<SERVICE_TYPE(log_builtins)>;
  log_builtins_service_guard log_builtins_service_;
  std::string component_name_;
  std::string message_prefix_;
};

}  // namespace mysqlpp

#define KEYRING_LOG_MESSAGE(LOGGER, SEVERITY, ECODE, MESSAGE)             \
  (LOGGER).log(SEVERITY, ECODE, LOG_SUBSYSTEM_TAG, __LINE__, MY_BASENAME, \
               __FUNCTION__, MESSAGE)

#ifndef NDEBUG
#define KEYRING_LOG_MESSAGE_DEBUG(LOGGER, SEVERITY, ECODE, MESSAGE) \
  KEYRING_LOG_MESSAGE(LOGGER, SEVERITY, ECODE, MESSAGE)
#else
#define KEYRING_LOG_MESSAGE_DEBUG(LOGGER, SEVERITY, ECODE, MESSAGE)
#endif

#endif
