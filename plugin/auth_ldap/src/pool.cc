#include "plugin/auth_ldap/include/pool.h"

#include <cmath>
#include <iostream>
#include <thread>

#include "plugin/auth_ldap/include/plugin_log.h"

namespace mysql {
namespace plugin {
namespace auth_ldap {

Pool::Pool(unsigned int pool_initial_size, unsigned int pool_max_size,
           const std::string &ldap_host, unsigned int ldap_port, bool use_ssl,
           bool use_tls, const std::string &ca_path, const std::string &bind_dn,
           const std::string &bind_pwd)
    : _pool_initial_size(pool_initial_size),
      _pool_max_size(pool_max_size),
      _ldap_host(ldap_host),
      _ldap_port(ldap_port),
      _use_ssl(use_ssl),
      _use_tls(use_tls),
      _ca_path(ca_path),
      _bind_dn(bind_dn),
      _bind_pwd(bind_pwd) {
  std::lock_guard<std::mutex> lock(_pool_mutex);

  _bs_used.resize(_pool_max_size);
  _v_connections.resize(_pool_max_size);
  for (unsigned int i = 0; i < _pool_max_size; i++) {
    _v_connections[i] = std::make_shared<Connection>(i, ldap_host, ldap_port,
                                                     use_ssl, use_tls, ca_path);
    if (i < _pool_initial_size) {
      _v_connections[i]->connect(_bind_dn, _bind_pwd);
    }
  }
}

Pool::~Pool() {
  std::lock_guard<std::mutex> lock(_pool_mutex);

  _v_connections.clear();
}

/**
 * Obtains a connection
 **/
std::shared_ptr<Connection> Pool::borrow_connection(bool default_connect) {
  int idx = -1;
  // Find a free connection - scope
  {
    std::lock_guard<std::mutex> lock(_pool_mutex);

    idx = _find_first_free();
    if (idx == -1) {
      log_srv_warn("WARNING: No available connections in the pool");
    } else {
      _mark_as_busy(idx);
    }
  }

  // No available connection - exit
  if (idx == -1) {
    std::thread t(&Pool::zombie_control, this);
    return nullptr;
  }

  // Get connection object and connect [slow]
  std::shared_ptr<Connection> conn =
      this->_get_connection(idx, default_connect);
  // If we don't have a valid connection, free up the pool element
  if (conn == nullptr) {
    std::lock_guard<std::mutex> lock(_pool_mutex);
    _mark_as_free(idx);
  }

  return conn;
}

void Pool::debug_info() {
  std::stringstream log_stream;
  log_stream << "conn_init [" << _pool_initial_size << "] conn_max ["
             << _pool_max_size << "] conn_in_use [" << _bs_used.count() << "]";
  log_srv_dbg(log_stream.str());
}

/**
 * Returns a connection to the pool
 **/
void Pool::return_connection(std::shared_ptr<Connection> conn) {
  // Mark the connection as free
  int idx = conn->get_idx_pool();
  conn->mark_as_free();

  // if connection was snipped because the pool was resized...
  if (conn->is_snipped()) {
    conn.reset();
  } else {
    // Mark the element as free in the pool - scope
    {
      std::lock_guard<std::mutex> lock(_pool_mutex);
      _mark_as_free(idx);
    }

    // Launch a detached thread for zombie control if used > 90%
    if (_bs_used.count() >= std::ceil(_pool_max_size * 0.9)) {
      std::thread t(&Pool::zombie_control, this);
    }
  }
}

void Pool::reconfigure(unsigned int new_pool_initial_size,
                       unsigned int new_pool_max_size,
                       const std::string &ldap_host, unsigned int ldap_port,
                       bool use_ssl, bool use_tls, const std::string &ca_path,
                       const std::string &bind_dn,
                       const std::string &bind_pwd) {
  log_srv_dbg("Pool::reconfigure()");
  // Force zombie control
  zombie_control();

  std::lock_guard<std::mutex> lock(_pool_mutex);

  // Resize pool
  if (new_pool_max_size != _pool_max_size) {
    _bs_used.resize(new_pool_max_size);
    // If new size is smaller -> mark new_pool_max_size to pool_max_size for
    // deletion
    if (new_pool_max_size < _pool_max_size) {
      log_srv_dbg("reducing max pool size");
      for (unsigned int i = new_pool_max_size; i < _pool_max_size; i++) {
        _v_connections[i]->mark_as_snipped();
      }
    }
    _v_connections.resize(new_pool_max_size);

    if (new_pool_max_size > _pool_max_size) {
      log_srv_dbg("extending max pool size");
      for (unsigned int i = _pool_max_size; i < new_pool_max_size; i++) {
        _v_connections[i] = std::make_shared<Connection>(
            i, ldap_host, ldap_port, use_ssl, use_tls, ca_path);
      }
    }

    _pool_max_size = new_pool_max_size;
  }

  // Reconnect pool
  _ldap_host = ldap_host;
  _ldap_port = ldap_port;
  _use_ssl = use_ssl;
  _use_tls = use_tls;
  _ca_path = ca_path;
  _pool_initial_size = new_pool_initial_size;
  _bind_dn = bind_dn;
  _bind_pwd = bind_pwd;

  for (unsigned int i = 0; i < _pool_max_size; i++) {
    _v_connections[i]->configure(_ldap_host, _ldap_port, _use_ssl, _use_tls,
                                 _ca_path);
    if (i < _pool_initial_size) {
      _v_connections[i]->connect(_bind_dn, _bind_pwd);
    }
  }

  for (unsigned int i = 0; i < new_pool_initial_size; i++) {
    _v_connections[i]->connect(_bind_dn, _bind_pwd);
  }
}

void Pool::zombie_control() {
  std::lock_guard<std::mutex> lock(_pool_mutex);

  for (unsigned int i = 0; i < _pool_max_size; i++) {
    if (_bs_used.test(i) && _v_connections[i]->is_zombie()) {
      _v_connections[i]->mark_as_free();
      _mark_as_free(i);
    }
  }
}

int Pool::_find_first_free() {
  int idx = -1;

  // If everything is in use, fast-exit
  if (!_bs_used.all()) {
    for (unsigned int i = 0; i < _pool_max_size; i++) {
      if (!_bs_used.test(i)) {
        idx = i;
        break;  // exit for
      }
    }
  }

  return idx;
}

std::shared_ptr<Connection> Pool::_get_connection(int idx,
                                                  bool default_connect) {
  std::shared_ptr<Connection> conn = _v_connections[idx];
  if (default_connect && !conn->connect(_bind_dn, _bind_pwd)) {
    log_srv_error("Connection to LDAP backend failed");
    conn = nullptr;
  } else {
    conn->mark_as_busy();
  }

  return conn;
}

void Pool::_mark_as_busy(int idx) { _bs_used.set(idx, true); }

void Pool::_mark_as_free(int idx) { _bs_used.set(idx, false); }

}  // namespace auth_ldap
}  // namespace plugin
}  // namespace mysql
