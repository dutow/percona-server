/* Copyright (c) 2021, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include <cassert>
#include <fstream>
#include <memory>

#include "backend.h"
#include "my_dbug.h"

#include <mysql/components/minimal_chassis.h>

//#include <components/keyrings/common/data_kmip/reader.h>
//#ibnclude <components/keyrings/common/data_kmip/writer.h>
//#include <components/keyrings/common/json_data/json_reader.h>
//#include <components/keyrings/common/json_data/json_writer.h>
#include <components/keyrings/common/memstore/cache.h>
#include <components/keyrings/common/memstore/iterator.h>
#include <components/keyrings/common/utils/utils.h>

namespace keyring_kmip {

namespace backend {

using keyring_common::data::Data;
using keyring_common::meta::Metadata;
using keyring_common::utils::get_random_data;

Keyring_kmip_backend::Keyring_kmip_backend(config::Config_pod config)
    : valid_(false), config_(config) {
  fprintf(stderr, "kmip_constructor\n");
  // TODO: check configuration
  DBUG_TRACE;
  valid_ = true;
}

bool Keyring_kmip_backend::load_cache(
    keyring_common::operations::Keyring_operations<Keyring_kmip_backend>
        &operations) {
  // TODO: this loads all keys from the server that have a name
  // do we really want all of them to be visible, or can a single server be used for multiple mysqlds for example?
  fprintf(stderr, "kmip_load_cache\n");
  DBUG_TRACE;
  try {
    auto ctx = kmip_ctx();

    auto keys = ctx.op_all();

    for (auto id : keys) {
      auto key = ctx.op_get(id);
      auto key_name = ctx.op_get_name_attr(id);

      if (key_name == "") continue;

      Metadata metadata(key_name, "");

      Data data(keyring_common::data::Sensitive_data(
                    reinterpret_cast<char *>(key.data()), key.size()),
                "AES");

      if (operations.insert(metadata, data) == true) return true;

      return false; // TODO:  limiting cached keys to 1 for now
    }

  } catch (...) {
    mysql_components_handle_std_exception(__func__);
  }

  return false;
}

bool Keyring_kmip_backend::get(const Metadata &, Data &) const {
  /* Shouldn't have reached here if we cache things. */
  assert(0);
  fprintf(stderr, "kmip_get\n");
  DBUG_TRACE;
  return false;
}

bool Keyring_kmip_backend::store(const Metadata &metadata, Data &data) {
  DBUG_TRACE;
  fprintf(stderr, "kmip_store\n");
  if (!metadata.valid() || !data.valid()) return true;
  try {
    auto ctx = kmip_ctx();
    auto key = data.data().decode();
    kmippp::context::key_t keyv(key.begin(), key.end());
    ctx.op_register(metadata.key_id(), keyv);
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
    return true;
  }
  /*if (json_writer_.add_element(metadata, data, ext)) return true;
  if (write_to_file()) {
    (void)json_writer_.remove_element(metadata, ext);
    return true;
  }*/
  return false;
}

size_t Keyring_kmip_backend::size() const {
  // TODO: if this returns a different number of what we actually have (load in load_cache), we crash
  // and it is possible that load_cache discardes some entries, e.g. the server doesn't require names to be unique,
  // or to be present at all.
  // unfortunately we also have to specify this number BEFORE load_cache, because if we return 0, load_cache isn't called
  // maybe we should add a group (tag) in kmip and assume that all of the keys that have that are correct?
  return 1;
  try {
    auto ctx = kmip_ctx();

    auto keys = ctx.op_all();

    return keys.size();
  } catch (...) {
    mysql_components_handle_std_exception(__func__);
    return 0;
  }
}

bool Keyring_kmip_backend::erase(const Metadata &metadata, Data &data) {
  DBUG_TRACE;
  fprintf(stderr, "kmip_erase\n");
  if (!metadata.valid()) return true;
  /*
  if (json_writer_.remove_element(metadata, ext)) return true;
  if (write_to_file()) {
    (void)json_writer_.add_element(metadata, data, ext);
    return true;
  }
  */
  return false;
}

bool Keyring_kmip_backend::generate(const Metadata &metadata, Data &data,
                                    size_t length) {
  DBUG_TRACE;
  fprintf(stderr, "kmip_generate\n");
  if (!metadata.valid()) return true;

  std::unique_ptr<unsigned char[]> key(new unsigned char[length]);
  if (!key) return true;
  if (!get_random_data(key, length)) return true;

  pmr_string key_str;
  key_str.assign(reinterpret_cast<const char *>(key.get()), length);
  data.set_data(keyring_common::data::Sensitive_data{key_str});

  return store(metadata, data);
}

kmippp::context Keyring_kmip_backend::kmip_ctx() const {
  return kmippp::context(config_.server_addr, config_.server_port,
                         config_.client_ca, config_.client_key,
                         config_.server_ca);
}

}  // namespace backend

}  // namespace keyring_kmip
