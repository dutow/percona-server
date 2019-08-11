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

#include "plugin/auth_ldap/include/auth_ldap_impl.h"
#include "plugin/auth_ldap/include/connection.h"
#include "plugin/auth_ldap/include/plugin_log.h"

#include <algorithm>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>

namespace mysql {
namespace plugin {
namespace auth_ldap {

AuthLDAPImpl::AuthLDAPImpl(const std::string &user_name,
                           const std::string &auth_string,
                           const std::string &user_search_attr,
                           const std::string &group_search_filter,
                           const std::string &group_search_attr,
                           const std::string &bind_base_dn, Pool *pool)
    : _pool(pool),
      _user_search_attr(user_search_attr),
      _group_search_attr(group_search_attr),
      _group_search_filter(group_search_filter),
      _bind_base_dn(bind_base_dn),
      _user_name(user_name) {
  std::vector<std::string> parts;
  boost::algorithm::split(parts, auth_string, boost::is_any_of("#"));
  _user_auth_string = boost::algorithm::trim_copy(parts[0]);
  if (parts.size() == 2) {
    std::string raw_group_mappings = boost::algorithm::trim_copy(parts[1]);
    if (!raw_group_mappings.empty()) _calc_mappings(raw_group_mappings);
  }
}

AuthLDAPImpl::~AuthLDAPImpl() {}

bool AuthLDAPImpl::bind(const std::string &user_dn,
                        const std::string &password) {
  log_srv_dbg("AuthLDAPImpl::bind()");
  bool success = false;
  std::stringstream log_stream;

  std::shared_ptr<Connection> conn = _pool->borrow_connection(false);
  if (conn == nullptr) return false;

  if (conn->connect(user_dn, password)) {
    log_stream << "User authentication success: [" << user_dn << "]";
    success = true;
  } else {
    log_stream << "User authentication failed: [" << user_dn << "]";
  }
  log_srv_dbg(log_stream.str());

  _pool->return_connection(conn);

  return success;
}

bool AuthLDAPImpl::get_ldap_uid(std::string *user_dn) {
  log_srv_dbg("AuthLDAPImpl::get_ldap_uid()");

  if (_user_auth_string.empty()) {
    *user_dn = _search_ldap_uid();
  } else {
    *user_dn = _calc_ldap_uid();
  }

  if (user_dn->empty()) {
    std::stringstream log_stream;
    log_stream << "User not found for user_name: [" << _user_name
               << "] user_search_attr: [" << _user_search_attr
               << "] bind_base_dn: [" << _bind_base_dn << "]";
    log_srv_warn(log_stream.str());
  }

  return !user_dn->empty();
}

bool AuthLDAPImpl::get_mysql_uid(std::string *user_mysql,
                                 const std::string &user_dn) {
  log_srv_dbg("AuthLDAPImpl::get_mysql_uid()");
  if (user_dn.empty()) return false;

  std::list<std::string> ldap_groups = _search_ldap_groups(user_dn);
  if (ldap_groups.size() == 0) return false;

  *user_mysql = _calc_mysql_user(ldap_groups);
  if (user_mysql->empty()) return false;

  return true;
}

const std::string AuthLDAPImpl::_calc_ldap_uid() {
  log_srv_dbg("AuthLDAPImpl::_calc_ldap_uid()");
  std::string uid;
  std::stringstream log_stream;

  if (_user_auth_string[0] == '+') {
    uid = _user_search_attr + "=" + _user_name + "," +
          _user_auth_string.substr(1);
    log_stream << "Calculated user_dn: ";
  } else {
    uid = _user_auth_string;
    log_stream << "Full user_dn specified: ";
  }
  log_stream << uid;
  log_srv_dbg(log_stream.str());

  return uid;
}

void AuthLDAPImpl::_calc_mappings(const std::string &group_str) {
  std::vector<std::string> parts2;
  boost::algorithm::split(parts2, group_str, boost::is_any_of(","));
  for (std::string const &s : parts2) {
    t_group_mapping map;
    if (s.find("=") != std::string::npos) {
      std::vector<std::string> parts3;
      boost::algorithm::split(parts3, s, boost::is_any_of("="));
      map.mysql_user = parts3[1];
      if (parts3[0].find("+") != std::string::npos) {
        std::vector<std::string> parts4;
        boost::algorithm::split(parts4, parts3[0], boost::is_any_of("+"));
        map.ldap_groups = parts4;
      } else {
        map.ldap_groups.push_back(parts3[0]);
      }
    } else {
      map.mysql_user = s;
      map.ldap_groups.push_back(s);
    }
    _mappings.push_back(map);
  }
}

const std::string AuthLDAPImpl::_calc_mysql_user(
    const std::list<std::string> &groups) {
  log_srv_dbg("AuthLDAPImpl::_calc_mysql_user()");
  for (const t_group_mapping &map : _mappings) {
    if (_matched_map(map, groups)) {
      return map.mysql_user;
    }
  }
  log_srv_dbg("MySQL mapping not found for existing LDAP groups");
  return "";
}

/**
 * All the groups in a map are present in ldap: MATCH!
 */
bool AuthLDAPImpl::_matched_map(const t_group_mapping &map,
                                const std::list<std::string> &groups) {
  log_srv_dbg("AuthLDAPImpl::_matched_map()");
  bool matched = true;
  std::stringstream log_stream;

  log_stream << "Check map ";
  std::copy(map.ldap_groups.begin(), map.ldap_groups.end(),
            std::ostream_iterator<std::string>(log_stream, ","));
  log_stream << " in AD ";
  std::copy(groups.begin(), groups.end(),
            std::ostream_iterator<std::string>(log_stream, ","));
  log_stream << " -> " << map.mysql_user;
  log_srv_dbg(log_stream.str());

  for (const std::string &s : map.ldap_groups) {
    if (std::find(groups.begin(), groups.end(), s) == std::end(groups))
      matched = false;
  }

  return matched;
}

std::list<std::string> AuthLDAPImpl::_search_ldap_groups(
    const std::string &user_dn) {
  log_srv_dbg("AuthLDAPImpl::_search_ldap_groups");
  std::list<std::string> list;

  std::shared_ptr<Connection> conn = _pool->borrow_connection();
  if (conn == nullptr) return list;

  list = conn->search_groups(_user_name, user_dn, _group_search_attr,
                             _group_search_filter, _bind_base_dn);

  _pool->return_connection(conn);

  return list;
}

const std::string AuthLDAPImpl::_search_ldap_uid() {
  log_srv_dbg("AuthLDAPImpl::_search_ldap_uid()");
  std::string uid;

  std::shared_ptr<Connection> conn = _pool->borrow_connection();
  if (conn == nullptr) return uid;

  uid = conn->search_dn(_user_name, _user_search_attr, _bind_base_dn);

  _pool->return_connection(conn);

  if (uid.empty()) {
    std::stringstream log_stream;
    log_stream << "User not found in LDAP user_name: [" << _user_name
               << "] user_search_attr: [" << _user_search_attr
               << "] bind_base_dn: [" << _bind_base_dn << "]";
    log_srv_dbg(log_stream.str());
  }
  return uid;
}

}  // namespace auth_ldap
}  // namespace plugin
}  // namespace mysql
