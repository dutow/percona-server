/*
   Copyright (c) 2013, 2022, Oracle and/or its affiliates.

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA
*/

#ifndef CONNECTION_HANDLER_IMPL_INCLUDED
#define CONNECTION_HANDLER_IMPL_INCLUDED

#include "my_global.h"
#include "mysql/psi/mysql_thread.h" // mysql_mutex_t
#include "connection_handler.h"     // Connection_handler
#include "threadpool.h"

#include <list>

class Channel_info;
class THD;

/**
  This class represents the connection handling functionality
  that each connection is being handled in a single thread
*/
class Per_thread_connection_handler : public Connection_handler
{
  Per_thread_connection_handler(const Per_thread_connection_handler&);
  Per_thread_connection_handler&
    operator=(const Per_thread_connection_handler&);

  /**
    Check if idle threads to handle connection in
    thread cache. If so enqueue the new connection
    to be picked by the idle thread in thread cache.

    @retval false if idle pthread was found, else true.
  */
  bool check_idle_thread_and_enqueue_connection(Channel_info* channel_info);

  /**
    List of pending channel info objects to be picked by idle
    threads. Protected by LOCK_thread_cache.
  */
  static std::list<Channel_info*> *waiting_channel_info_list;

  static mysql_mutex_t LOCK_thread_cache;
  static mysql_cond_t COND_thread_cache;
  static mysql_cond_t COND_flush_thread_cache;

public:
  // Status variables related to Per_thread_connection_handler
  static ulong blocked_pthread_count;    // Protected by LOCK_thread_cache.
  static ulong slow_launch_threads;
  // System variable
  static ulong max_blocked_pthreads;

  static void init();
  static void destroy();

  /**
    Wake blocked pthreads and wait until they have terminated.
  */
  static void kill_blocked_pthreads();

  /**
    Block until a new connection arrives.
  */
  static Channel_info* block_until_new_connection();

  Per_thread_connection_handler() {}
  virtual ~Per_thread_connection_handler() { }

protected:
  virtual bool add_connection(Channel_info* channel_info);

  virtual uint get_max_threads() const;
};


/**
  This class represents the connection handling functionality
  of all connections being handled in a single worker thread.
*/
class One_thread_connection_handler : public Connection_handler
{
  One_thread_connection_handler(const One_thread_connection_handler&);
  One_thread_connection_handler&
    operator=(const One_thread_connection_handler&);

public:
  One_thread_connection_handler() {}
  virtual ~One_thread_connection_handler() {}

protected:
  virtual bool add_connection(Channel_info* channel_info);

  virtual uint get_max_threads() const { return 1; }
};

class Thread_pool_connection_handler : public Connection_handler
{
  Thread_pool_connection_handler(const Thread_pool_connection_handler&);
  Thread_pool_connection_handler&
    operator=(const Thread_pool_connection_handler&);

 public:
  Thread_pool_connection_handler()
  {
    tp_init();
  }

  virtual ~Thread_pool_connection_handler()
  {
    tp_end();
  }

 protected:
  virtual bool add_connection(Channel_info* channel_info);

  virtual uint get_max_threads() const
  {
    return threadpool_max_threads;
  }

};

#endif // CONNECTION_HANDLER_IMPL_INCLUDED
