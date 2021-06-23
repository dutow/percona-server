#include "mysqlpp/component_logger.hpp"

#include <memory>
#include <string>

namespace mysqlpp {

component_logger::component_logger(
    mysqlpp::plugin_registry_guard &plugin_registry,
    ext::string_view component_name, ext::string_view message_prefix)
    : log_builtins_service_{plugin_registry},
      component_name_{component_name.data(), component_name.size()},
      message_prefix_{message_prefix.data(), message_prefix.size()} {}

void component_logger::log(longlong severity, longlong errcode,
                           const char *subsys, longlong source_line,
                           const char *source_file, const char *function,
                           const std::string &message) const noexcept {
  auto &log_builtins_service_raw = log_builtins_service_.get_service();
  auto log_line_deleter = [&log_builtins_service_raw](log_line *ll) {
    if (ll != nullptr) log_builtins_service_raw.line_exit(ll);
  };
  using log_line_ptr = std::unique_ptr<log_line, decltype(log_line_deleter)>;
  log_line_ptr ll{log_builtins_service_raw.line_init(), log_line_deleter};
  if (!ll) return;

  // log severity (INT)
  auto *log_prio_item =
      log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_LOG_PRIO);
  log_builtins_service_raw.item_set_int(log_prio_item, severity);

  // SQL error code (INT)
  auto *sql_errcode_item =
      log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_SQL_ERRCODE);
  log_builtins_service_raw.item_set_int(sql_errcode_item, errcode);

  // subsystem (CSTRING)
  if (subsys != nullptr) {
    auto *srv_subsys_item =
        log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_SRV_SUBSYS);
    log_builtins_service_raw.item_set_cstring(srv_subsys_item, subsys);
  }

  // Component (CSTRING)
  if (!component_name_.empty()) {
    auto *srv_component_item = log_builtins_service_raw.line_item_set(
        ll.get(), LOG_ITEM_SRV_COMPONENT);
    log_builtins_service_raw.item_set_lexstring(
        srv_component_item, component_name_.c_str(), component_name_.size());
  }

  // source line number (INT)
  auto *src_line_item =
      log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_SRC_LINE);
  log_builtins_service_raw.item_set_int(src_line_item, source_line);

  // source file name (CSTRING)
  if (source_file != nullptr) {
    auto *src_file_item =
        log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_SRC_FILE);
    log_builtins_service_raw.item_set_cstring(src_file_item, source_file);
  }

  // function name (CSTRING)
  if (function != nullptr) {
    auto *src_func_item =
        log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_SRC_FUNC);
    log_builtins_service_raw.item_set_cstring(src_func_item, function);
  }

  // log message
  std::string full_message;
  full_message.reserve(message_prefix_.size() + message.size());
  full_message = message_prefix_;
  full_message += message;

  auto *log_message_item =
      log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_LOG_MESSAGE);
  log_builtins_service_raw.item_set_lexstring(
      log_message_item, full_message.c_str(), full_message.size());

  // submitting the log line
  log_builtins_service_raw.line_submit(ll.get());
}

}  // namespace mysqlpp
