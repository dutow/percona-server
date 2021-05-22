/* Copyright (c) 2021 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#include <cassert>
#include <memory>
#include <random>
#include <shared_mutex>
#include <string>
#include <type_traits>
#include <unordered_map>

#include <boost/container_hash/hash.hpp>

#include <map_helpers.h>
#include <mysqld_error.h>

#include <mysql/plugin_keyring.h>

#include <mysql/components/minimal_chassis.h>

#include <mysql/components/services/log_builtins.h>

class plugin_registry_guard {
 public:
  plugin_registry_guard() : impl_{mysql_plugin_registry_acquire()} {
    if (!impl_) throw std::runtime_error{"unable to acquire plugin regisrty"};
  }

  SERVICE_TYPE(registry) & get_service() const noexcept { return *impl_; }

 private:
  struct releaser {
    void operator()(SERVICE_TYPE(registry) * srv) const noexcept {
      if (srv != nullptr) mysql_plugin_registry_release(srv);
    }
  };

  using plugin_registry_registry_ptr =
      std::unique_ptr<SERVICE_TYPE(registry), releaser>;
  plugin_registry_registry_ptr impl_;
};

class service_guard_base {
 protected:
  service_guard_base(plugin_registry_guard &plugin_registry,
                     const char *service_name)
      : impl_{nullptr, {&plugin_registry.get_service()}} {
    my_h_service acquired_service{nullptr};
    if (plugin_registry.get_service().acquire(service_name,
                                              &acquired_service) ||
        acquired_service == nullptr)
      throw std::runtime_error{"unable to acquire service from the registry"};
    impl_.reset(acquired_service);
  }

  my_h_service get_service_internal() const noexcept { return impl_.get(); }

 private:
  struct releaser {
    SERVICE_TYPE(registry) * parent;
    void operator()(my_h_service srv) const noexcept {
      assert(parent != nullptr);
      if (srv != nullptr) parent->release(srv);
    }
  };

  using my_h_service_raw = std::remove_pointer_t<my_h_service>;
  using service_ptr = std::unique_ptr<my_h_service_raw, releaser>;
  service_ptr impl_;
};

template <typename Service>
struct service_traits;

#define DECLARE_SERVICE_TRAITS_SPECIALIZATION(SERVICE, NAME)        \
  template <>                                                       \
  struct service_traits<SERVICE_TYPE(SERVICE)> {                    \
    static const char *get_service_name() noexcept { return NAME; } \
  };

// DECLARE_SERVICE_TRAITS_SPECIALIZATION(log_builtins_string,
//                                      "log_builtins_string.mysql_server")
DECLARE_SERVICE_TRAITS_SPECIALIZATION(log_builtins, "log_builtins.mysql_server")

#undef DECLARE_SERVICE_TRAITS_SPECIALIZATION

template <typename Service>
class service_guard : private service_guard_base {
 public:
  service_guard(plugin_registry_guard &plugin_registry)
      : service_guard_base{plugin_registry,
                           service_traits<Service>::get_service_name()} {}

  Service &get_service() const noexcept {
    return *reinterpret_cast<Service *>(get_service_internal());
  }
};

// using log_builtins_string_service_guard =
//    service_guard<SERVICE_TYPE(log_builtins_string)>;
using log_builtins_service_guard = service_guard<SERVICE_TYPE(log_builtins)>;

class keyring_logger {
 public:
  keyring_logger(plugin_registry_guard &plugin_registry)
      : log_builtins_service_{plugin_registry} {}

  void log(longlong severity, longlong errcode, const char *subsys,
           const char *component, longlong source_line, const char *source_file,
           const char *function, const std::string &message) const noexcept {
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
    if (component != nullptr) {
      auto *srv_component_item = log_builtins_service_raw.line_item_set(
          ll.get(), LOG_ITEM_SRV_COMPONENT);
      log_builtins_service_raw.item_set_cstring(srv_component_item, component);
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
    auto *log_message_item =
        log_builtins_service_raw.line_item_set(ll.get(), LOG_ITEM_LOG_MESSAGE);
    log_builtins_service_raw.item_set_lexstring(
        log_message_item, message.c_str(), message.size());

    // submitting the log line
    log_builtins_service_raw.line_submit(ll.get());
  }

 private:
  log_builtins_service_guard log_builtins_service_;
};

#define KEYRING_LOG_MESSAGE(LOGGER, SEVERITY, ECODE, MESSAGE)          \
  (LOGGER).log(                                                        \
      SEVERITY, ECODE, LOG_SUBSYSTEM_TAG, "plugin:" LOG_COMPONENT_TAG, \
      __LINE__, MY_BASENAME, __FUNCTION__,                             \
      (std::string("Plugin " LOG_COMPONENT_TAG " reported: ") + (MESSAGE)))

#ifndef NDEBUG
#define KEYRING_LOG_MESSAGE_DEBUG(LOGGER, SEVERITY, ECODE, MESSAGE) \
  KEYRING_LOG_MESSAGE(LOGGER, SEVERITY, ECODE, MESSAGE)
#else
#define KEYRING_LOG_MESSAGE_DEBUG(LOGGER, SEVERITY, ECODE, MESSAGE)
#endif

struct composite_key_id {
  std::string user_id;
  std::string key_id;

  std::string to_str() const {
    return "{\"" + user_id + "\":\"" + key_id + "\"}";
  }

  friend bool operator==(const composite_key_id &obj1,
                         const composite_key_id &obj2) noexcept {
    return obj1.user_id == obj2.user_id && obj1.key_id == obj2.key_id;
  }
};

struct composite_key_value {
  std::string key_type;
  std::string key_data;

  std::string to_str() const {
    return "{\"" + key_type + "\":\"" + std::to_string(key_data.size()) + "\"}";
  }
};

class kmip_context {
 private:
  struct instance_guard {};

  struct composite_key_id_hasher {
    std::size_t operator()(const composite_key_id &obj) const noexcept {
      std::size_t seed = 0;
      boost::hash_combine(seed, obj.user_id);
      boost::hash_combine(seed, obj.key_id);
      return seed;
    }
  };

  using key_container =
      std::unordered_map<composite_key_id, composite_key_value,
                         composite_key_id_hasher>;
  using raw_const_key_iterator = key_container::const_iterator;

  // TODO: change to std::shared_mutex when switching to c++17
  using key_container_mutex = std::shared_timed_mutex;
  using key_container_shared_lock = std::shared_lock<key_container_mutex>;
  using key_container_unique_lock = std::unique_lock<key_container_mutex>;

 public:
  class const_enumerator {
    friend class kmip_context;

   public:
    ~const_enumerator() {
      try {
        KEYRING_LOG_MESSAGE_DEBUG(*logger_, INFORMATION_LEVEL,
                                  ER_KEYRING_LOGGER_ERROR_MSG,
                                  "Enumerator destroyed");
      } catch (...) {
      }
    }

    const_enumerator(const const_enumerator &) = delete;
    const_enumerator(const_enumerator &&) = default;

    const_enumerator &operator=(const const_enumerator &) = delete;
    const_enumerator &operator=(const_enumerator &&) = default;

    bool has_value() const noexcept {
      bool result = underlying_it_ != underlying_en_;
      KEYRING_LOG_MESSAGE_DEBUG(*logger_, INFORMATION_LEVEL,
                                ER_KEYRING_LOGGER_ERROR_MSG,
                                result ? "Enumerator still has data"
                                       : "Enumerator has no data anymore");
      return result;
    }
    const composite_key_id &get_value() const noexcept {
      KEYRING_LOG_MESSAGE_DEBUG(*logger_, INFORMATION_LEVEL,
                                ER_KEYRING_LOGGER_ERROR_MSG,
                                "Value extracted from the enumerator " +
                                    underlying_it_->first.to_str());
      return underlying_it_->first;
    }
    void operator++() noexcept {
      KEYRING_LOG_MESSAGE_DEBUG(*logger_, INFORMATION_LEVEL,
                                ER_KEYRING_LOGGER_ERROR_MSG,
                                "Enumerator incremented");
      ++underlying_it_;
    }

   private:
    const keyring_logger *logger_;
    raw_const_key_iterator underlying_it_;
    raw_const_key_iterator underlying_en_;
    key_container_shared_lock lock_;

    const_enumerator(const keyring_logger &logger, const key_container &keys,
                     key_container_mutex &mutex)
        : logger_{&logger},
          underlying_it_{std::cbegin(keys)},
          underlying_en_{std::cend(keys)},
          lock_{mutex} {
      KEYRING_LOG_MESSAGE_DEBUG(*logger_, INFORMATION_LEVEL,
                                ER_KEYRING_LOGGER_ERROR_MSG,
                                "Enumerator created");
    }
  };

 public:
  kmip_context(instance_guard)
      : plugin_registry_{},
        logger_{plugin_registry_},
        mutex_{},
        keys_{},
        random_engine_{std::random_device{}()},
        distribution_{'a', 'z'} {
    KEYRING_LOG_MESSAGE_DEBUG(logger_, INFORMATION_LEVEL,
                              ER_KEYRING_LOGGER_ERROR_MSG,
                              "Plugin context created");
  }
  ~kmip_context() {
    try {
      KEYRING_LOG_MESSAGE_DEBUG(logger_, INFORMATION_LEVEL,
                                ER_KEYRING_LOGGER_ERROR_MSG,
                                "Plugin context destroyed");
    } catch (...) {
    }
  }

  static void init_instance() {
    if (instance_)
      throw std::logic_error{
          "cannot initialize kmip_context instance  as it has already been "
          "initialized"};
    instance_ = std::make_unique<kmip_context>(instance_guard{});
  }
  static void deinit_instance() {
    if (!instance_)
      throw std::logic_error{
          "cannot deinitialize kmip_context instance as it has not been "
          "initialized"};
    instance_.reset();
  }
  static kmip_context &get_instance() {
    if (!instance_)
      throw std::logic_error{
          "cannot get kmip_context instance as it has not been initialized"};
    return *instance_;
  }

  void store(const composite_key_id &comp_key_id,
             const composite_key_value &comp_key_value) {
    key_container_unique_lock lock{mutex_};
    auto result = keys_.emplace(comp_key_id, comp_key_value);
    if (!result.second) {
      KEYRING_LOG_MESSAGE(logger_, ERROR_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
                          "could not store key " + comp_key_id.to_str() + ' ' +
                              comp_key_value.to_str());
      throw std::invalid_argument{"cannot store key"};
    }
    KEYRING_LOG_MESSAGE_DEBUG(
        logger_, INFORMATION_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
        "successfully stored key " + comp_key_id.to_str() + ' ' +
            comp_key_value.to_str());
  }

  composite_key_value fetch(const composite_key_id &comp_key_id) const {
    // Returning by value here to avoid concurrency problems
    key_container_shared_lock lock{mutex_};
    auto fnd = keys_.find(comp_key_id);
    if (fnd == std::cend(keys_)) {
      KEYRING_LOG_MESSAGE(logger_, ERROR_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
                          "could not fetch key " + comp_key_id.to_str());
      throw std::invalid_argument{"key not found"};
    }

    KEYRING_LOG_MESSAGE_DEBUG(
        logger_, INFORMATION_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
        "successfully fetched key " + comp_key_id.to_str() + ' ' +
            fnd->second.to_str());
    return fnd->second;
  }

  void remove(const composite_key_id &comp_key_id) {
    key_container_unique_lock lock{mutex_};
    if (keys_.erase(comp_key_id) == 0) {
      KEYRING_LOG_MESSAGE(logger_, ERROR_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
                          "could not remove key " + comp_key_id.to_str());
      throw std::invalid_argument{"cannot remove key"};
    }
    KEYRING_LOG_MESSAGE_DEBUG(
        logger_, INFORMATION_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
        "successfully removed key " + comp_key_id.to_str());
  }

  void generate(const composite_key_id &comp_key_id,
                const std::string &key_type, std::size_t key_length) {
    std::string generated_key_data(key_length, '-');
    std::generate_n(std::begin(generated_key_data), key_length,
                    [this]() { return distribution_(random_engine_); });
    composite_key_value ck{key_type, std::move(generated_key_data)};

    key_container_unique_lock lock{mutex_};
    auto result = keys_.emplace(comp_key_id, std::move(ck));
    if (!result.second) {
      KEYRING_LOG_MESSAGE(logger_, ERROR_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
                          "could not generate key " + comp_key_id.to_str() +
                              " {\"" + key_type + "\":\"" +
                              std::to_string(key_length) + "\"}");
      throw std::invalid_argument{"cannot insert generated key"};
    }
    KEYRING_LOG_MESSAGE_DEBUG(
        logger_, INFORMATION_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
        "successfully generated key " + comp_key_id.to_str() + ' ' +
            result.first->second.to_str());
  }

  const_enumerator get_const_enumerator() const noexcept {
    return {logger_, keys_, mutex_};
  }

 private:
  plugin_registry_guard plugin_registry_;

  keyring_logger logger_;

  mutable std::shared_timed_mutex mutex_;
  key_container keys_;

  std::mt19937 random_engine_;
  using alpha_character_distribution = std::uniform_int_distribution<char>;
  alpha_character_distribution distribution_;

  using instance_type = std::unique_ptr<kmip_context>;
  static instance_type instance_;
};

/*static*/
kmip_context::instance_type kmip_context::instance_{};

static std::string construct_string(const char *ptr,
                                    std::size_t length = std::string::npos) {
  if (ptr == nullptr) return {};
  if (length == std::string::npos) return {ptr};
  return {ptr, length};
}

using guarded_raw_string = unique_ptr_my_free<char>;

static int keyring_kmip_init(MYSQL_PLUGIN /*plugin_info*/) {
  bool result = 1;
  try {
    kmip_context::init_instance();
    result = 0;
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }
  return result;
}

static int keyring_kmip_deinit(MYSQL_PLUGIN /*plugin_info*/) {
  bool result = 1;
  try {
    kmip_context::deinit_instance();
    result = 0;
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }
  return result;
}

static bool keyring_kmip_key_store(const char *key_id, const char *key_type,
                                   const char *user_id, const void *key,
                                   std::size_t key_length) {
  bool result = true;
  try {
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
    composite_key_value comp_key_value{
        construct_string(key_type),
        construct_string(static_cast<const char *>(key), key_length)};
    kmip_context::get_instance().store(comp_key_id, comp_key_value);

    result = false;
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }
  return result;
}

static bool keyring_kmip_key_fetch(const char *key_id, char **key_type,
                                   const char *user_id, void **key,
                                   std::size_t *key_length) {
  assert(key_type != nullptr);
  assert(key != nullptr);
  assert(key_length != nullptr);

  bool result = true;
  try {
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
    auto comp_key_value = kmip_context::get_instance().fetch(comp_key_id);

    guarded_raw_string safe_key_type{my_strdup(
        PSI_NOT_INSTRUMENTED, comp_key_value.key_type.c_str(), MYF(0))};
    if (!safe_key_type) throw std::bad_alloc{};
    guarded_raw_string safe_key_data{
        my_strndup(PSI_NOT_INSTRUMENTED, comp_key_value.key_data.c_str(),
                   comp_key_value.key_data.size(), MYF(0))};
    if (!safe_key_data) throw std::bad_alloc{};
    *key_type = safe_key_type.release();
    *key = safe_key_data.release();
    *key_length = comp_key_value.key_data.size();

    result = false;
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }
  return result;
}

static bool keyring_kmip_key_remove(const char *key_id, const char *user_id) {
  bool result = true;
  try {
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
    kmip_context::get_instance().remove(comp_key_id);

    result = false;
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }
  return result;
}

static bool keyring_kmip_key_generate(const char *key_id, const char *key_type,
                                      const char *user_id,
                                      std::size_t key_length) {
  bool result = true;
  try {
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
    kmip_context::get_instance().generate(
        comp_key_id, construct_string(key_type), key_length);

    result = false;
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }
  return result;
}

static void keyring_kmip_key_iterator_init(void **key_iterator) {
  assert(key_iterator != nullptr);

  kmip_context::const_enumerator *result = nullptr;
  try {
    result = new kmip_context::const_enumerator(
        kmip_context::get_instance().get_const_enumerator());
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }
  *key_iterator = result;
}

static void keyring_kmip_key_iterator_deinit(void *key_iterator) {
  delete static_cast<kmip_context::const_enumerator *>(key_iterator);
}

static bool keyring_kmip_key_iterator_get_key(void *key_iterator, char *key_id,
                                              char *user_id) {
  auto casted_key_enumerator_ptr =
      static_cast<kmip_context::const_enumerator *>(key_iterator);
  if (casted_key_enumerator_ptr == nullptr) return true;
  if (!casted_key_enumerator_ptr->has_value()) return true;
  // TODO: change strcpy() to strncpy() using max lengths for key_id / user_id
  auto &comp_key_id = casted_key_enumerator_ptr->get_value();
  std::strcpy(key_id, comp_key_id.key_id.c_str());
  std::strcpy(user_id, comp_key_id.user_id.c_str());
  ++*casted_key_enumerator_ptr;
  return false;
}

/* Plugin type-specific descriptor */
static struct st_mysql_keyring keyring_kmip_descriptor = {
    MYSQL_KEYRING_INTERFACE_VERSION,  keyring_kmip_key_store,
    keyring_kmip_key_fetch,           keyring_kmip_key_remove,
    keyring_kmip_key_generate,        keyring_kmip_key_iterator_init,
    keyring_kmip_key_iterator_deinit, keyring_kmip_key_iterator_get_key};

mysql_declare_plugin(keyring_kmip){
    MYSQL_KEYRING_PLUGIN,                                  /* type       */
    &keyring_kmip_descriptor,                              /* descriptor */
    "keyring_kmip",                                        /* name       */
    "Percona",                                             /* author     */
    "store/fetch authentication data to/from KMIP server", /* description */
    PLUGIN_LICENSE_GPL,                                    /* licence type */
    keyring_kmip_init,      /* init function (when loaded)                 */
    nullptr,                /* check_uninstall function (when uninstalled) */
    keyring_kmip_deinit,    /* deinit function (when unloaded)             */
    0x0100,                 /* version          */
    nullptr,                /* status variables */
    nullptr,                /* system variables */
    nullptr,                /* reserved         */
    PLUGIN_OPT_ALLOW_EARLY, /* plugin options*/
} mysql_declare_plugin_end;
