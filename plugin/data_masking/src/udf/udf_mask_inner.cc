/* Copyright (c) 2018, 2019 Francisco Miguel Biete Banon. All rights reserved.

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

#include <my_global.h>
#include "../../include/plugin.h"
#include "../../include/udf/udf_utils.h"
#include "../../include/udf/udf_utils_string.h"

extern "C" {
  my_bool mask_inner_init(UDF_INIT *initid, UDF_ARGS *args, char *message);
  void mask_inner_deinit(UDF_INIT *initid);
  const char *mask_inner(UDF_INIT *initid, UDF_ARGS *args, char *result,
                         unsigned long *length, char *is_null, char *);
}

my_bool mask_inner_init(UDF_INIT *initid, UDF_ARGS *args, char *message) {
  DBUG_ENTER("mask_inner_init");

  if (!data_masking_is_inited(message, MYSQL_ERRMSG_SIZE)) {
    DBUG_RETURN(true);
  }

  if (args->arg_count < 3 || args->arg_count > 4) {
    std::snprintf(message, MYSQL_ERRMSG_SIZE,
                  "Wrong argument list: MASK_INNER(string, marging left, "
                  "margin right, [masking character])");
    DBUG_RETURN(true);
  }

  if (args->arg_type[0] != STRING_RESULT || args->arg_type[1] != INT_RESULT ||
      args->arg_type[2] != INT_RESULT ||
      (args->arg_count == 4 &&
       (args->arg_type[3] != STRING_RESULT || args->lengths[3] != 1))) {
    std::snprintf(message, MYSQL_ERRMSG_SIZE,
                  "Wrong argument type: MASK_INNER(string, int, int, [char])");
    DBUG_RETURN(true);
  }

  initid->maybe_null = 1;
  initid->ptr = NULL;

  DBUG_RETURN(false);
}

void mask_inner_deinit(UDF_INIT *initid) {
  DBUG_ENTER("mask_inner_deinit");

  if (initid->ptr) delete[] initid->ptr;

  DBUG_VOID_RETURN;
}

/**
 * Masks the interior part of a string, leaving the ends untouched, and returns
 * the result. An optional masking character can be specified.
 * @param str: The string to mask.
 * @param str_length: The length of the string to mask
 * @param margin1: A nonnegative integer that specifies the number of characters
 * on the left end of the string to remain unmasked. If the value is 0, no left
 * end characters remain unmasked.
 * @param margin2: A nonnegative integer that specifies the number of characters
 * on the right end of the string to remain unmasked. If the value is 0, no
 * right end characters remain unmasked.
 * @param mask_char: (Optional) The single character to use for masking. The
 * default is 'X' if mask_char is not given.
 *
 * @returns The masked string, or NULL if either margin is negative. If the sum
 * of the margin values is larger than the argument length, no masking occurs
 * and the argument is returned unchanged.
 */
const char *mask_inner(UDF_INIT *initid, UDF_ARGS *args,
                       char *result   MY_ATTRIBUTE((unused)),
                       unsigned long *length, char *is_null, char *) {
  DBUG_ENTER("mask_inner");

  if (args->args[0] == NULL) {
    *is_null = 1;
  } else {
    char masking_char = 'X';
    if (args->arg_count == 4) {
      masking_char = args->args[3][0];
    }
    std::string s = mysql::plugins::mask_inner(
        args->args[0], args->lengths[0], *(int *)args->args[1],
        *(int *)args->args[2], masking_char);
    if ((*length = s.length()) > 0) {
      initid->ptr = new char[*length + 1];
      strcpy(initid->ptr, s.c_str());
    }
  }

  DBUG_RETURN(initid->ptr);
}
