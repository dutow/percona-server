/* Copyright (c) 2016, 2022, Oracle and/or its affiliates.

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

#ifndef IKEYRINGIO_INCLUDED
#define IKEYRINGIO_INCLUDED

#include <my_global.h>
#include "keyring_key.h"
#include "i_serializer.h"

namespace keyring {


class IKeyring_io : public Keyring_alloc
{
public:
 virtual my_bool init(const std::string *keyring_storage_url)= 0;
 virtual my_bool flush_to_backup(ISerialized_object *serialized_object)= 0;
 virtual my_bool flush_to_storage(ISerialized_object *serialized_object)= 0;

 virtual ISerializer *get_serializer()= 0;
 virtual my_bool      get_serialized_object(
          ISerialized_object **serialized_object)= 0;
 virtual my_bool has_next_serialized_object()= 0;

 virtual ~IKeyring_io() {}
};

} //namespace keyring

#endif //IKEYRINGIO_INCLUDED
