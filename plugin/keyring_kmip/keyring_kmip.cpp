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
#include <unordered_map>

#include <boost/container/pmr/polymorphic_allocator.hpp>

#include <boost/container_hash/hash.hpp>

#include <mysqld_error.h>

#include <ext/string_view.hpp>

#include <mysql/plugin_keyring.h>

#include <mysql/components/minimal_chassis.h>

#include "mysqlpp/component_logger.hpp"
#include "mysqlpp/erasing_memory_resource.hpp"
#include "mysqlpp/plugin_registry_guard.hpp"
#include "mysqlpp/psi_memory_resource.hpp"
#include "mysqlpp/service_guard.hpp"

// a workaround to allow 'boost::container::pmr::polymorphic_allocator' to be
// used without building corresponding boost library
mysqlpp::psi_memory_resource global_default_mr{};
::boost::container::pmr::memory_resource
    * ::boost::container::pmr::get_default_resource() {
  return &global_default_mr;
}

using erasing_psi_memory_resource = mysqlpp::erasing_memory_resource;
using pmr_string =
    std::basic_string<char, std::char_traits<char>,
                      boost::container::pmr::polymorphic_allocator<char>>;
using erasing_string = pmr_string;

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
  erasing_string key_data;

  std::string to_str() const {
    return "{\"" + key_type + "\":\"" + std::to_string(key_data.size()) + "\"}";
  }
};

static inline ext::string_view construct_sv(
    const char *ptr, std::size_t size = std::string::npos) {
  if (ptr == nullptr) return {};
  if (size == std::string::npos) return {ptr};
  return {ptr, size};
}

static inline std::string construct_string(ext::string_view sv) {
  if (sv.data() == nullptr) return {};
  return {sv.data(), sv.size()};
}

static inline pmr_string construct_pmr_string(
    boost::container::pmr::memory_resource &mr, ext::string_view sv) {
  if (sv.data() == nullptr) return pmr_string{&mr};
  return pmr_string{sv.data(), sv.size(), &mr};
}

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
    const mysqlpp::component_logger *logger_;
    raw_const_key_iterator underlying_it_;
    raw_const_key_iterator underlying_en_;
    key_container_shared_lock lock_;

    const_enumerator(const mysqlpp::component_logger &logger,
                     const key_container &keys, key_container_mutex &mutex)
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
        logger_{plugin_registry_, "Plugin " LOG_COMPONENT_TAG,
                "Plugin " LOG_COMPONENT_TAG ": "},
        primary_mr_{},
        erasing_mr_{primary_mr_},
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
          "cannot initialize kmip_context instance as it has already been "
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

  void store(ext::string_view user_id, ext::string_view key_id,
             ext::string_view key_type, ext::string_view key_data) {
    key_container_unique_lock lock{mutex_};
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
    composite_key_value comp_key_value{
        construct_string(key_type),
        construct_pmr_string(erasing_mr_, key_data)};
    auto result =
        keys_.emplace(std::move(comp_key_id), std::move(comp_key_value));
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

  composite_key_value fetch(ext::string_view user_id,
                            ext::string_view key_id) const {
    // Returning by value here to avoid concurrency problems
    key_container_shared_lock lock{mutex_};
    // TODO: avoid key copying here
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
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

  void remove(ext::string_view user_id, ext::string_view key_id) {
    key_container_unique_lock lock{mutex_};
    // TODO: avoid key copying here
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
    if (keys_.erase(comp_key_id) == 0) {
      KEYRING_LOG_MESSAGE(logger_, ERROR_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
                          "could not remove key " + comp_key_id.to_str());
      throw std::invalid_argument{"cannot remove key"};
    }
    KEYRING_LOG_MESSAGE_DEBUG(
        logger_, INFORMATION_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
        "successfully removed key " + comp_key_id.to_str());
  }

  void generate(ext::string_view user_id, ext::string_view key_id,
                ext::string_view key_type, std::size_t key_length) {
    erasing_string generated_key_data(key_length, '-', &erasing_mr_);
    std::generate_n(std::begin(generated_key_data), key_length,
                    [this]() { return distribution_(random_engine_); });
    composite_key_value ck{construct_string(key_type),
                           std::move(generated_key_data)};

    key_container_unique_lock lock{mutex_};
    composite_key_id comp_key_id{construct_string(user_id),
                                 construct_string(key_id)};
    auto result = keys_.emplace(std::move(comp_key_id), std::move(ck));
    if (!result.second) {
      KEYRING_LOG_MESSAGE(
          logger_, ERROR_LEVEL, ER_KEYRING_LOGGER_ERROR_MSG,
          "could not generate key " + comp_key_id.to_str() + " {\"" +
              (key_type.data() == nullptr ? "" : key_type.data()) + "\":\"" +
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
  mysqlpp::plugin_registry_guard plugin_registry_;

  mysqlpp::component_logger logger_;

  mysqlpp::psi_memory_resource primary_mr_;
  erasing_psi_memory_resource erasing_mr_;
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
    kmip_context::get_instance().store(
        construct_sv(key_id), construct_sv(key_type), construct_sv(user_id),
        construct_sv(static_cast<const char *>(key), key_length));

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
    auto comp_key_value = kmip_context::get_instance().fetch(
        construct_sv(user_id), construct_sv(key_id));

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
    kmip_context::get_instance().remove(construct_sv(user_id),
                                        construct_sv(key_id));

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
    kmip_context::get_instance().generate(construct_sv(user_id),
                                          construct_sv(key_id),
                                          construct_sv(key_type), key_length);

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
