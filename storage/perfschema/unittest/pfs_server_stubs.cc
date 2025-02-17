/* Copyright (c) 2010, 2022, Oracle and/or its affiliates. All rights
   reserved.

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
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA */

/*
  Minimal code to be able to link a unit test.
*/

#include "my_global.h"
#include "m_ctype.h"
#include "sql_class.h"
#include "sql_show.h"

my_bool show_compatibility_56= FALSE;
struct system_status_var global_status_var;
struct sql_digest_storage;
volatile bool ready_to_exit= false;

uint lower_case_table_names= 0;
CHARSET_INFO *files_charset_info= NULL;
CHARSET_INFO *system_charset_info= NULL;

void compute_digest_md5(const sql_digest_storage *, unsigned char *)
{
}

void reset_status_vars()
{
}

void sql_print_warning(const char *format, ...)
{
  /* Do not pollute the unit test output with annoying messages. */
}

my_bool
acl_is_utility_user(const char *, const char *, const char *)
{
  return FALSE;
}
