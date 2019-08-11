#ifndef _MPAL_CONNECTION_H
/* Copyright (c) 2019 Francisco Miguel Biete Banon. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */
#define _MPAL_CONNECTION_H

#include <ctime>
#include <list>
#include <mutex>
#include <string>

#include <ldap.h>

namespace mysql {
namespace plugin {
namespace auth_ldap {
class Connection {
 public:
  static const int ZombieAfterSeconds = 120;

 public:
  Connection(unsigned int idx, const std::string &ldap_host,
             unsigned int ldap_port, bool use_ssl, bool use_tls,
             const std::string &ca_path);
  ~Connection();

 public:
  Connection(const Connection &) = delete;  // non construction-copyable
  Connection &operator=(const Connection &) = delete;  // non copyable

 public:
  void configure(const std::string &ldap_host, unsigned int ldap_port,
                 bool use_ssl, bool use_tls, const std::string &ca_path);
  bool connect(const std::string &bind_dn, const std::string &bind_pwd);
  int get_idx_pool();
  bool is_snipped();
  bool is_zombie();
  void mark_as_busy();
  void mark_as_free();
  void mark_as_snipped();
  std::string search_dn(const std::string &user_name,
                        const std::string &user_search_attr,
                        const std::string &base_dn);
  std::list<std::string> search_groups(const std::string &user_name,
                                       const std::string &bind_user,
                                       const std::string &group_search_attr,
                                       const std::string &group_search_filter,
                                       const std::string &base_dn);

 private:
  std::string _get_ldap_uri();
  void _log_error(const std::string &str, int ldap_err);
  void _log_warning(const std::string &str, int ldap_err);

 private:
  bool _available;
  unsigned int _index;
  bool _snipped;
  std::string _ldap_host;
  unsigned int _ldap_port;
  bool _use_ssl;
  bool _use_tls;
  std::string _ca_path;

 private:
  std::time_t _borrowed_ts;
  std::mutex _conn_mutex;
  LDAP *_ldap;
};
}  // namespace auth_ldap
}  // namespace plugin
}  // namespace mysql
#endif  // _MPAL_CONNECTION_H
