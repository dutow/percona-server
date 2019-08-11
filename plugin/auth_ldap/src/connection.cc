#include "plugin/auth_ldap/include/connection.h"

#include <iostream>
#include <regex>

#include "plugin/auth_ldap/include/plugin_log.h"

namespace mysql {
namespace plugin {
namespace auth_ldap {
Connection::Connection(unsigned int idx, const std::string &ldap_host,
                       unsigned int ldap_port, bool use_ssl, bool use_tls,
                       const std::string &ca_path)
    : _available(true),
      _index(idx),
      _snipped(false),
      _ldap_host(ldap_host),
      _ldap_port(ldap_port),
      _use_ssl(use_ssl),
      _use_tls(use_tls),
      _ca_path(ca_path) {}

Connection::~Connection() {}

void Connection::configure(const std::string &ldap_host, unsigned int ldap_port,
                           bool use_ssl, bool use_tls,
                           const std::string &ca_path) {
  _ldap_host = ldap_host;
  _ldap_port = ldap_port;
  _use_ssl = use_ssl;
  _use_tls = use_tls;
  _ca_path = ca_path;
}

bool Connection::connect(const std::string &bind_dn,
                         const std::string &bind_pwd) {
  std::lock_guard<std::mutex> lock(_conn_mutex);

  if (!(_ldap_host.empty() || bind_dn.empty())) {
    log_srv_dbg("Connecting to ldap server as " + bind_dn);

    int err = ldap_initialize(&(_ldap), _get_ldap_uri().c_str());
    if (err != LDAP_SUCCESS) {
      _log_error("ldap_initialize", err);
      return false;
    }

    int version = LDAP_VERSION3;
    err = ldap_set_option(_ldap, LDAP_OPT_PROTOCOL_VERSION, &version);
    if (err != LDAP_OPT_SUCCESS) {
      _log_error("ldap_set_option(LDAP_OPT_PROTOCOL_VERSION)", err);
      return false;
    }

    // Optional; log warning if the server doesn't support it, but continue
    err = ldap_set_option(_ldap, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    if (err != LDAP_OPT_SUCCESS) {
      _log_warning("ldap_set_option(LDAP_OPT_REFERRALS, LDAP_OPT_OFF)", err);
    }

    // Optional; log warning if the server doesn't support it, but continue
    err = ldap_set_option(_ldap, LDAP_OPT_RESTART, LDAP_OPT_ON);
    if (err != LDAP_OPT_SUCCESS) {
      _log_warning("ldap_set_option(LDAP_OPT_RESTART, LDAP_OPT_ON)", err);
    }

    err = ldap_set_option(_ldap, LDAP_OPT_X_TLS_NEWCTX, LDAP_OPT_ON);
    if (err != LDAP_OPT_SUCCESS) {
      _log_error("ldap_set_option(LDAP_OPT_X_TLS_NEWCTX)", err);
      return false;
    }

    if (_ca_path.size() == 0) {
      int reqCert = LDAP_OPT_X_TLS_NEVER;
      err = ldap_set_option(_ldap, LDAP_OPT_X_TLS_REQUIRE_CERT, &reqCert);
      if (err != LDAP_OPT_SUCCESS) {
        _log_error("ldap_set_option(LDAP_OPT_X_TLS_REQUIRE_CERT)", err);
        return false;
      }
    } else {
      char *cca_path = strdup(_ca_path.c_str());
      err = ldap_set_option(_ldap, LDAP_OPT_X_TLS_CACERTFILE,
                            static_cast<void *>(cca_path));
      free(cca_path);
      if (err != LDAP_OPT_SUCCESS) {
        _log_error("ldap_set_option(LDAP_OPT_X_TLS_CACERTFILE)", err);
        return false;
      }
    }

    if (_use_tls) {
      err = ldap_start_tls_s(_ldap, nullptr, nullptr);
      if (err != LDAP_SUCCESS) {
        _log_error("ldap_start_tls_s", err);
        return false;
      }
    }

    struct berval *serverCreds;
    struct berval *userCreds =
        ber_str2bv(strdup(bind_pwd.c_str()), 0, 0, nullptr);

    err = ldap_sasl_bind_s(_ldap, bind_dn.c_str(), LDAP_SASL_SIMPLE, userCreds,
                           nullptr, nullptr, &serverCreds);
    if (err != LDAP_SUCCESS) {
      _log_warning("Unsuccesful bind: ldap_sasl_bind_s(" + bind_dn + ")", err);
      return false;
    }

    return true;
  }

  return false;
}

int Connection::get_idx_pool() { return _index; }

bool Connection::is_snipped() { return _snipped; };

bool Connection::is_zombie() {
  return _available ? false
                    : (std::time(nullptr) - _borrowed_ts) >
                          Connection::ZombieAfterSeconds;
}

void Connection::mark_as_busy() {
  std::lock_guard<std::mutex> lock(_conn_mutex);
  _available = false;
  _borrowed_ts = std::time(nullptr);
}

void Connection::mark_as_free() {
  std::lock_guard<std::mutex> lock(_conn_mutex);
  _available = true;
}

void Connection::mark_as_snipped() {
  std::lock_guard<std::mutex> lock(_conn_mutex);
  _snipped = true;
}

std::string Connection::search_dn(const std::string &user_name,
                                  const std::string &user_search_attr,
                                  const std::string &base_dn) {
  std::lock_guard<std::mutex> lock(_conn_mutex);

  std::string str;
  std::stringstream log_stream;
  std::string filter = user_search_attr + "=" + user_name;

  log_stream << "search_dn(" << base_dn << ", " << filter << ")";
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  LDAPMessage *l_result;
  char *attrs[] = {(char *)"dn", nullptr};
  struct timeval search_timeout = {5, 0};
  const int searchlimit = 1;
  int err = ldap_search_ext_s(
      _ldap, base_dn.c_str() /* base */, LDAP_SCOPE_SUBTREE /*scope*/,
      filter.c_str() /*filter*/, attrs /*attrs*/, 0 /*attrsonly*/,
      nullptr /*serverctrls*/, nullptr /*clientctrls*/,
      &search_timeout /*timeout*/, searchlimit /*searchlimit*/,
      &l_result /*ldapmessage*/);
  if (err == LDAP_SUCCESS) {
    // Verify an entry was found
    if (ldap_count_entries(_ldap, l_result) == 0) {
      log_stream << "ldap_search_ext_s(" << base_dn << ", " << filter
                 << ") returned no matching entries";
      log_srv_warn(log_stream.str());
      log_stream.str("");
    } else {
      // entry and dn are pointers to l_result components; don't cleanup them or
      // this segfault when cleaning up l_result
      LDAPMessage *entry = ldap_first_entry(_ldap, l_result);
      char *dn = ldap_get_dn(_ldap, entry);
      log_stream << "ldap_search_ext_s(" << base_dn << ", " << filter
                 << "): " << dn;
      log_srv_dbg(log_stream.str());
      log_stream.str("");
      str = dn;
    }
    ldap_msgfree(l_result);
    l_result = nullptr;
  } else {
    log_stream << "ldap_search_ext_s(" << base_dn << ", " << filter << ") "
               << ldap_err2string(err);
    log_srv_error(log_stream.str());
    log_stream.str("");
  }

  log_stream << "search_dn(" << base_dn << ", " << filter << ") = " << str;
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  return str;
}

std::list<std::string> Connection::search_groups(
    const std::string &user_name, const std::string &user_dn,
    const std::string &group_search_attr,
    const std::string &group_search_filter, const std::string &base_dn) {
  std::lock_guard<std::mutex> lock(_conn_mutex);

  std::list<std::string> list;
  std::stringstream log_stream;
  std::string filter = std::regex_replace(group_search_filter,
                                          std::regex("\\{UA\\}"), user_name);
  filter = std::regex_replace(filter, std::regex("\\{UD\\}"), user_dn);

  LDAPMessage *l_result;
  char *attrs[] = {(char *)group_search_attr.c_str(), nullptr};
  struct timeval search_timeout = {5, 0};
  int err = ldap_search_ext_s(
      _ldap, base_dn.c_str() /* base */, LDAP_SCOPE_SUBTREE /*scope*/,
      filter.c_str() /*filter*/, attrs /*attrs*/, 0 /*attrsonly*/,
      nullptr /*serverctrls*/, nullptr /*clientctrls*/,
      &search_timeout /*timeout*/, 0 /*searchlimit*/,
      &l_result /*ldapmessage*/);
  if (err == LDAP_SUCCESS) {
    // Verify an entry was found
    if (ldap_count_entries(_ldap, l_result) == 0) {
      log_stream << "ldap_search_ext_s(" << base_dn << ", " << filter
                 << ") returned no matching entries";
      log_srv_warn(log_stream.str());
      log_stream.str("");
    } else {
      char *attribute;
      BerElement *ber;
      BerValue **vals;
      LDAPMessage *entry = ldap_first_entry(_ldap, l_result);
      while (entry) {
        // Don't cleanup entry, attribute, ber or vals because they will be
        // cleaned up with l_result
        attribute = ldap_first_attribute(_ldap, entry, &ber);
        while (attribute) {
          vals = ldap_get_values_len(_ldap, entry, attribute);
          for (int pos = 0; pos < ldap_count_values_len(vals); pos++) {
            list.push_back(std::string(vals[pos]->bv_val));
          }
          attribute = ldap_next_attribute(_ldap, entry, ber);
        }
        entry = ldap_next_entry(_ldap, entry);
      }
    }
    ldap_msgfree(l_result);
    l_result = nullptr;
  } else {
    log_stream << "ldap_search_ext_s('" << base_dn << "', '" << filter << "') "
               << ldap_err2string(err);
    log_srv_error(log_stream.str());
    log_stream.str("");
  }

  log_stream << "search_groups() = ";
  std::copy(list.begin(), list.end(),
            std::ostream_iterator<std::string>(log_stream, ","));
  log_srv_dbg(log_stream.str());
  log_stream.str("");

  return list;
}

std::string Connection::_get_ldap_uri() {
  std::stringstream str_stream;
  str_stream << (_use_ssl || _use_tls ? "ldaps://" : "ldap://") << _ldap_host
             << ":" << _ldap_port;
  return str_stream.str();
}

void Connection::_log_error(const std::string &str, int ldap_err) {
  std::stringstream log_stream;
  log_stream << str << " " << ldap_err2string(ldap_err);
  log_srv_error(log_stream.str());
}
void Connection::_log_warning(const std::string &str, int ldap_err) {
  std::stringstream log_stream;
  log_stream << str << " " << ldap_err2string(ldap_err);
  log_srv_warn(log_stream.str());
}

}  // namespace auth_ldap
}  // namespace plugin
}  // namespace mysql
