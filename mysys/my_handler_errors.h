#ifndef MYSYS_MY_HANDLER_ERRORS_INCLUDED
#define MYSYS_MY_HANDLER_ERRORS_INCLUDED

/* Copyright (c) 2008, 2022, Oracle and/or its affiliates.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   Without limiting anything contained in the foregoing, this file,
   which is part of C Driver for MySQL (Connector/C), is also subject to the
   Universal FOSS Exception, version 1.0, a copy of which can be found at
   http://oss.oracle.com/licenses/universal-foss-exception.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA */

/*
  Errors a handler can give you
*/

static const char *handler_error_messages[]=
{
  "Didn't find key on read or update",
  "Duplicate key on write or update",
  "Internal (unspecified) error in handler",
  "Someone has changed the row since it was read (while the table was locked to prevent it)",
  "Wrong index given to function",
  "Undefined handler error 125",
  "Index file is crashed",
  "Record file is crashed",
  "Out of memory in engine",
  "Undefined handler error 129",
  "Incorrect file format",
  "Command not supported by database",
  "Old database file",
  "No record read before update",
  "Record was already deleted (or record file crashed)",
  "No more room in record file",
  "No more room in index file",
  "No more records (read after end of file)",
  "Unsupported extension used for table",
  "Too big row",
  "Wrong create options",
  "Duplicate unique key or constraint on write or update",
  "Unknown character set used in table",
  "Conflicting table definitions in sub-tables of MERGE table",
  "Table is crashed and last repair failed",
  "Table was marked as crashed and should be repaired",
  "Lock timed out; Retry transaction",
  "Lock table is full;  Restart program with a larger locktable",
  "Updates are not allowed under a read only transactions",
  "Lock deadlock; Retry transaction",
  "Foreign key constraint is incorrectly formed",
  "Cannot add a child row",
  "Cannot delete a parent row",
  "No savepoint with that name",
  "Non unique key block size",
  "The table does not exist in engine",
  "The table already existed in storage engine",
  "Could not connect to storage engine",
  "Unexpected null pointer found when using spatial index",
  "The table changed in storage engine",
  "There's no partition in table for the given value",
  "Row-based binlogging of row failed",
  "Index needed in foreign key constraint",
  ("Upholding foreign key constraints would lead to a duplicate key error in "
   "some other table"),
  "Table needs to be upgraded before it can be used",
  "Table is read only",
  "Failed to get next auto increment value",
  "Failed to set row auto increment value",
  "Unknown (generic) error from engine",
  "Record is the same",
  "It is not possible to log this statement",
  "The event was corrupt, leading to illegal data being read",
  "The table is of a new format not supported by this version",
  "The event could not be processed no other hanlder error happened",
  "Got a fatal error during initialzaction of handler",
  "File to short; Expected more data in file",
  "Read page with wrong checksum",
  "Too many active concurrent transactions",
  "Record not matching the given partition set",
  "Index column length exceeds limit",
  "Index corrupted",
  "Undo record too big",
  "Invalid InnoDB FTS Doc ID",
  "Table is being used in foreign key check",
  "Tablespace already exists",
  "Too many columns",
  "Row in wrong partition",
  "InnoDB is in read only mode",
  "FTS query exceeds result cache memory limit",
  "Temporary file write failure",
  "Operation not allowed when innodb_forced_recovery > 0",
  "Too many words in a FTS phrase or proximity search",
  "Foreign key cascade delete/update exceeds max depth",
  "Required Create option missing",
  "Out of memory in storage engine",
  "Table corrupted",
  "Query interrupted",
  "Tablespace cannot be accessed",
  "Tablespace is not empty",
  "Incorrect file name",
  "Operation is not allowed",
  "Compute generate value failed",
  "Destination schema does not exist",
  "Partitioning can't be initialized",
  "Too many nested sub-expressions in a full-text search"
};

extern void my_handler_error_register(void);
extern void my_handler_error_unregister(void);


#endif /* MYSYS_MY_HANDLER_ERRORS_INCLUDED */
