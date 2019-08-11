#ifndef _MPAL_POOL_H
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
#define _MPAL_POOL_H

#include <boost/dynamic_bitset.hpp>
#include <mutex>
#include <vector>

#include "plugin/auth_ldap/include/connection.h"

namespace mysql {
namespace plugin {
namespace auth_ldap {
class Pool {
 public:
  Pool(unsigned int pool_initial_size, unsigned int pool_max_size,
       const std::string &ldap_host, unsigned int ldap_port, bool use_ssl,
       bool use_tls, const std::string &ca_path, const std::string &bind_dn,
       const std::string &bind_pwd);
  ~Pool();

 public:
  Pool(const Pool &) = delete;             // non construction-copyable
  Pool &operator=(const Pool &) = delete;  // non copyable
 public:
  std::shared_ptr<Connection> borrow_connection(bool default_connect = true);
  void debug_info();
  void return_connection(std::shared_ptr<Connection> conn);
  void reconfigure(unsigned int new_pool_initial_size,
                   unsigned int new_pool_max_size, const std::string &ldap_host,
                   unsigned int ldap_port, bool use_ssl, bool use_tls,
                   const std::string &ca_path, const std::string &bind_dn,
                   const std::string &bind_pwd);
  void zombie_control();

 private:
  int _find_first_free();
  std::shared_ptr<Connection> _get_connection(int idx, bool default_connect);
  void _mark_as_busy(int idx);
  void _mark_as_free(int idx);

 private:
  unsigned int _pool_initial_size;
  unsigned int _pool_max_size;
  std::string _ldap_host;
  unsigned int _ldap_port;
  bool _use_ssl;
  bool _use_tls;
  std::string _ca_path;
  std::string _bind_dn;
  std::string _bind_pwd;
  boost::dynamic_bitset<> _bs_used;
  std::vector<std::shared_ptr<Connection>> _v_connections;
  std::mutex _pool_mutex;
};
}  // namespace auth_ldap
}  // namespace plugin
}  // namespace mysql
#endif  // _MPAL_POOL_H
