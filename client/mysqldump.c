/*
   Copyright (c) 2000, 2022, Oracle and/or its affiliates.

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
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
*/

/* mysqldump.c  - Dump a tables contents and format to an ASCII file
**
** The author's original notes follow :-
**
** AUTHOR: Igor Romanenko (igor@frog.kiev.ua)
** DATE:   December 3, 1994
** WARRANTY: None, expressed, impressed, implied
**          or other
** STATUS: Public domain
** Adapted and optimized for MySQL by
** Michael Widenius, Sinisa Milivojevic, Jani Tolonen
** -w --where added 9/10/98 by Jim Faucette
** slave code by David Saez Padros <david@ols.es>
** master/autocommit code by Brian Aker <brian@tangent.org>
** SSL by
** Andrei Errapart <andreie@no.spam.ee>
** TÃµnu Samuel  <tonu@please.do.not.remove.this.spam.ee>
** XML by Gary Huntress <ghuntress@mediaone.net> 10/10/01, cleaned up
** and adapted to mysqldump 05/11/01 by Jani Tolonen
** Added --single-transaction option 06/06/2002 by Peter Zaitsev
** 10 Jun 2003: SET NAMES and --no-set-names by Alexander Barkov
*/

#define DUMP_VERSION "10.13"

#include <my_global.h>
#include <my_sys.h>
#include <my_user.h>
#include <m_string.h>
#include <m_ctype.h>
#include <hash.h>
#include <stdarg.h>
#include <my_list.h>

#include "client_priv.h"
#include "my_default.h"
#include "mysql.h"
#include "mysql_version.h"
#include "mysqld_error.h"

#include <welcome_copyright_notice.h> /* ORACLE_WELCOME_COPYRIGHT_NOTICE */

/* Exit codes */

#define EX_USAGE 1
#define EX_MYSQLERR 2
#define EX_CONSCHECK 3
#define EX_EOM 4
#define EX_EOF 5 /* ferror for output file was got */
#define EX_ILLEGAL_TABLE 6

/* index into 'show fields from table' */

#define SHOW_FIELDNAME  0
#define SHOW_TYPE  1
#define SHOW_NULL  2
#define SHOW_DEFAULT  4
#define SHOW_EXTRA  5

/* Size of buffer for dump's select query */
#define QUERY_LENGTH 1536

/* Size of comment buffer. */
#define COMMENT_LENGTH 2048

/* ignore table flags */
#define IGNORE_NONE 0x00 /* no ignore */
#define IGNORE_DATA 0x01 /* don't dump data for this table */

/* Chars needed to store LONGLONG, excluding trailing '\0'. */
#define LONGLONG_LEN 20

typedef enum {
  KEY_TYPE_NONE,
  KEY_TYPE_PRIMARY,
  KEY_TYPE_UNIQUE,
  KEY_TYPE_NON_UNIQUE,
  KEY_TYPE_CONSTRAINT
} key_type_t;

/* Maximum number of fields per table */
#define MAX_FIELDS 4000

static void add_load_option(DYNAMIC_STRING *str, const char *option,
                             const char *option_value);
static ulong find_set(TYPELIB *lib, const char *x, size_t length,
                      char **err_pos, uint *err_len);
static char *alloc_query_str(size_t size);

static void field_escape(DYNAMIC_STRING* in, const char *from);
static my_bool  verbose= 0, opt_no_create_info= 0, opt_no_data= 0,
                quick= 1, extended_insert= 1,
                lock_tables= 1, opt_force= 0, flush_logs= 0,
                flush_privileges= 0,
                opt_drop=1,opt_keywords=0,opt_lock=1,opt_compress=0,
                create_options=1,opt_quoted=0,opt_databases=0,
                opt_alldbs=0,opt_create_db=0,opt_lock_all_tables=0,
                opt_set_charset=0, opt_dump_date=1,
                opt_autocommit=0,opt_disable_keys=1,opt_xml=0,
                opt_delete_master_logs=0, tty_password=0,
                opt_single_transaction=0, opt_comments= 0, opt_compact= 0,
                opt_hex_blob=0, opt_order_by_primary=0, opt_ignore=0,
                opt_complete_insert= 0, opt_drop_database= 0,
                opt_replace_into= 0,
                opt_dump_triggers= 0, opt_routines=0, opt_tz_utc=1,
                opt_slave_apply= 0, 
                opt_include_master_host_port= 0,
                opt_events= 0, opt_comments_used= 0,
                opt_alltspcs=0, opt_notspcs= 0, opt_drop_trigger= 0,
                opt_compressed_columns= 0,
                opt_compressed_columns_with_dictionaries= 0,
                opt_drop_compression_dictionary= 1,
                opt_order_by_primary_desc= 0,
                opt_skip_mysql_schema=0, opt_secure_auth= TRUE;
static my_bool insert_pat_inited= 0, debug_info_flag= 0, debug_check_flag= 0;
static ulong opt_max_allowed_packet, opt_net_buffer_length;
static MYSQL mysql_connection,*mysql=0;
static DYNAMIC_STRING insert_pat;
static char  *opt_password=0,*current_user=0,
             *current_host=0,*path=0,*fields_terminated=0,
             *lines_terminated=0, *enclosed=0, *opt_enclosed=0, *escaped=0,
             *where=0, *order_by=0,
             *opt_compatible_mode_str= 0,
             *err_ptr= 0, *opt_ignore_error= 0,
             *log_error_file= NULL;
#ifndef NDEBUG
static char  *start_sql_file= NULL, *finish_sql_file= NULL;
#endif
static char **defaults_argv= 0;
static char compatible_mode_normal_str[255];
/* Server supports character_set_results session variable? */
static my_bool server_supports_switching_charsets= TRUE;
static ulong opt_compatible_mode= 0;
#define MYSQL_OPT_MASTER_DATA_EFFECTIVE_SQL 1
#define MYSQL_OPT_MASTER_DATA_COMMENTED_SQL 2
#define MYSQL_OPT_SLAVE_DATA_EFFECTIVE_SQL 1
#define MYSQL_OPT_SLAVE_DATA_COMMENTED_SQL 2
static uint opt_enable_cleartext_plugin= 0;
static my_bool using_opt_enable_cleartext_plugin= 0;
static uint opt_mysql_port= 0, opt_master_data;
static uint opt_slave_data;
static uint my_end_arg;
static char * opt_mysql_unix_port=0;
static char *opt_bind_addr = NULL;
static int   first_error=0;
static uint opt_lock_for_backup= 0;
#include <sslopt-vars.h>
#include <caching_sha2_passwordopt-vars.h>
FILE *md_result_file= 0;
FILE *stderror_file=0;

const char *set_gtid_purged_mode_names[]=
{"OFF", "AUTO", "ON", NullS};
static TYPELIB set_gtid_purged_mode_typelib=
               {array_elements(set_gtid_purged_mode_names) -1, "",
                set_gtid_purged_mode_names, NULL};
static enum enum_set_gtid_purged_mode {
  SET_GTID_PURGED_OFF= 0,
  SET_GTID_PURGED_AUTO =1,
  SET_GTID_PURGED_ON=2
} opt_set_gtid_purged_mode= SET_GTID_PURGED_AUTO;

#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
static char *shared_memory_base_name=0;
#endif
static uint opt_protocol= 0;
static char *opt_plugin_dir= 0, *opt_default_auth= 0;

DYNAMIC_ARRAY ignore_error;
static int parse_ignore_error();

static my_bool opt_innodb_optimize_keys= FALSE;

/*
Dynamic_string wrapper functions. In this file use these
wrappers, they will terminate the process if there is
an allocation failure.
*/
static void init_dynamic_string_checked(DYNAMIC_STRING *str, const char *init_str,
			    size_t init_alloc, size_t alloc_increment);
static void dynstr_append_checked(DYNAMIC_STRING* dest, const char* src);
static void dynstr_set_checked(DYNAMIC_STRING *str, const char *init_str);
static void dynstr_append_mem_checked(DYNAMIC_STRING *str, const char *append,
			  size_t length);
static void dynstr_realloc_checked(DYNAMIC_STRING *str, size_t additional_size);
/*
  Constant for detection of default value of default_charset.
  If default_charset is equal to mysql_universal_client_charset, then
  it is the default value which assigned at the very beginning of main().
*/
static const char *mysql_universal_client_charset=
  MYSQL_UNIVERSAL_CLIENT_CHARSET;
static char *default_charset;
static CHARSET_INFO *charset_info= &my_charset_latin1;
const char *default_dbug_option="d:t:o,/tmp/mysqldump.trace";
/* have we seen any VIEWs during table scanning? */
my_bool seen_views= 0;
static DYNAMIC_STRING gtid_executed_buffer;
static my_bool gtid_executed_buffer_inited= 0;
const char *compatible_mode_names[]=
{
  "MYSQL323", "MYSQL40", "POSTGRESQL", "ORACLE", "MSSQL", "DB2",
  "MAXDB", "NO_KEY_OPTIONS", "NO_TABLE_OPTIONS", "NO_FIELD_OPTIONS",
  "ANSI",
  NullS
};
#define MASK_ANSI_QUOTES \
(\
 (1<<2)  | /* POSTGRESQL */\
 (1<<3)  | /* ORACLE     */\
 (1<<4)  | /* MSSQL      */\
 (1<<5)  | /* DB2        */\
 (1<<6)  | /* MAXDB      */\
 (1<<10)   /* ANSI       */\
)
TYPELIB compatible_mode_typelib= {array_elements(compatible_mode_names) - 1,
                                  "", compatible_mode_names, NULL};

HASH ignore_table;
static HASH processed_compression_dictionaries;

static LIST *skipped_keys_list = NULL;
static LIST *alter_constraints_list = NULL;

static struct my_option my_long_options[] =
{
  {"all-databases", 'A',
   "Dump all the databases. This will be same as --databases with all databases selected.",
   &opt_alldbs, &opt_alldbs, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"all-tablespaces", 'Y',
   "Dump all the tablespaces.",
   &opt_alltspcs, &opt_alltspcs, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"no-tablespaces", 'y',
   "Do not dump any tablespace information.",
   &opt_notspcs, &opt_notspcs, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"add-drop-database", OPT_DROP_DATABASE, "Add a DROP DATABASE before each create.",
   &opt_drop_database, &opt_drop_database, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0,
   0},
  {"add-drop-table", OPT_DROP, "Add a DROP TABLE before each create.",
   &opt_drop, &opt_drop, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0,
   0},
  {"add-drop-trigger", 0, "Add a DROP TRIGGER before each create.",
   &opt_drop_trigger, &opt_drop_trigger, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0,
   0},
  {"add-locks", OPT_LOCKS, "Add locks around INSERT statements.",
   &opt_lock, &opt_lock, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0,
   0},
  {"allow-keywords", OPT_KEYWORDS,
   "Allow creation of column names that are keywords.", &opt_keywords,
   &opt_keywords, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"apply-slave-statements", OPT_MYSQLDUMP_SLAVE_APPLY,
   "Adds 'STOP SLAVE' prior to 'CHANGE MASTER' and 'START SLAVE' to bottom of dump.",
   &opt_slave_apply, &opt_slave_apply, 0, GET_BOOL, NO_ARG,
   0, 0, 0, 0, 0, 0},
  {"lock-for-backup", OPT_LOCK_FOR_BACKUP, "Use lightweight metadata locks "
   "to block updates to non-transactional tables and DDL to all tables. "
   "This works only with --single-transaction, otherwise this option is "
   "automatically converted to --lock-all-tables.", &opt_lock_for_backup,
   &opt_lock_for_backup, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"bind-address", 0, "IP address to bind to.",
   (uchar**) &opt_bind_addr, (uchar**) &opt_bind_addr, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"character-sets-dir", OPT_CHARSETS_DIR,
   "Directory for character set files.", &charsets_dir,
   &charsets_dir, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"comments", 'i', "Write additional information.",
   &opt_comments, &opt_comments, 0, GET_BOOL, NO_ARG,
   1, 0, 0, 0, 0, 0},
  {"compatible", OPT_COMPATIBLE,
   "Change the dump to be compatible with a given mode. By default tables "
   "are dumped in a format optimized for MySQL. Legal modes are: ansi, "
   "mysql323, mysql40, postgresql, oracle, mssql, db2, maxdb, no_key_options, "
   "no_table_options, no_field_options. One can use several modes separated "
   "by commas. Note: Requires MySQL server version 4.1.0 or higher. "
   "This option is ignored with earlier server versions.",
   &opt_compatible_mode_str, &opt_compatible_mode_str, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"compact", OPT_COMPACT,
   "Give less verbose output (useful for debugging). Disables structure "
   "comments and header/footer constructs.  Enables options --skip-add-"
   "drop-table --skip-add-locks --skip-comments --skip-disable-keys "
   "--skip-set-charset.",
   &opt_compact, &opt_compact, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"complete-insert", 'c', "Use complete insert statements.",
   &opt_complete_insert, &opt_complete_insert, 0, GET_BOOL,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {"compress", 'C', "Use compression in server/client protocol.",
   &opt_compress, &opt_compress, 0, GET_BOOL, NO_ARG, 0, 0, 0,
   0, 0, 0},
  {"create-options", 'a',
   "Include all MySQL specific create options.",
   &create_options, &create_options, 0, GET_BOOL, NO_ARG, 1,
   0, 0, 0, 0, 0},
  {"databases", 'B',
   "Dump several databases. Note the difference in usage; in this case no tables are given. All name arguments are regarded as database names. 'USE db_name;' will be included in the output.",
   &opt_databases, &opt_databases, 0, GET_BOOL, NO_ARG, 0, 0,
   0, 0, 0, 0},
#ifdef NDEBUG
  {"debug", '#', "This is a non-debug version. Catch this and exit.",
   0,0, 0, GET_DISABLED, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"debug-check", OPT_DEBUG_CHECK, "This is a non-debug version. Catch this and exit.",
   0, 0, 0,
   GET_DISABLED, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"debug-info", OPT_DEBUG_INFO, "This is a non-debug version. Catch this and exit.", 0,
   0, 0, GET_DISABLED, NO_ARG, 0, 0, 0, 0, 0, 0},
#else
  {"debug", '#', "Output debug log.", &default_dbug_option,
   &default_dbug_option, 0, GET_STR, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"debug-check", OPT_DEBUG_CHECK, "Check memory and open file usage at exit.",
   &debug_check_flag, &debug_check_flag, 0,
   GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"debug-info", OPT_DEBUG_INFO, "Print some debug info at exit.",
   &debug_info_flag, &debug_info_flag,
   0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
#endif
  {"default-character-set", OPT_DEFAULT_CHARSET,
   "Set the default character set.", &default_charset,
   &default_charset, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"delete-master-logs", OPT_DELETE_MASTER_LOGS,
   "Delete logs on master after backup. This automatically enables --master-data.",
   &opt_delete_master_logs, &opt_delete_master_logs, 0,
   GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"disable-keys", 'K',
   "'/*!40000 ALTER TABLE tb_name DISABLE KEYS */; and '/*!40000 ALTER "
   "TABLE tb_name ENABLE KEYS */; will be put in the output.", &opt_disable_keys,
   &opt_disable_keys, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
  {"dump-slave", OPT_MYSQLDUMP_SLAVE_DATA,
   "This causes the binary log position and filename of the master to be "
   "appended to the dumped data output. Setting the value to 1, will print"
   "it as a CHANGE MASTER command in the dumped data output; if equal"
   " to 2, that command will be prefixed with a comment symbol. "
   "This option will turn --lock-all-tables on, unless "
   "--single-transaction is specified too (in which case a "
   "global read lock is only taken a short time at the beginning of the dump "
   "- don't forget to read about --single-transaction below). In all cases "
   "any action on logs will happen at the exact moment of the dump."
   "Option automatically turns --lock-tables off.",
   &opt_slave_data, &opt_slave_data, 0,
   GET_UINT, OPT_ARG, 0, 0, MYSQL_OPT_SLAVE_DATA_COMMENTED_SQL, 0, 0, 0},
  {"events", 'E', "Dump events.",
     &opt_events, &opt_events, 0, GET_BOOL,
     NO_ARG, 0, 0, 0, 0, 0, 0},
  {"extended-insert", 'e',
   "Use multiple-row INSERT syntax that include several VALUES lists.",
   &extended_insert, &extended_insert, 0, GET_BOOL, NO_ARG,
   1, 0, 0, 0, 0, 0},
  {"fields-terminated-by", OPT_FTB,
   "Fields in the output file are terminated by the given string.",
   &fields_terminated, &fields_terminated, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"fields-enclosed-by", OPT_ENC,
   "Fields in the output file are enclosed by the given character.",
   &enclosed, &enclosed, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0 ,0, 0},
  {"fields-optionally-enclosed-by", OPT_O_ENC,
   "Fields in the output file are optionally enclosed by the given character.",
   &opt_enclosed, &opt_enclosed, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0 ,0, 0},
  {"fields-escaped-by", OPT_ESC,
   "Fields in the output file are escaped by the given character.",
   &escaped, &escaped, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"flush-logs", 'F', "Flush logs file in server before starting dump. "
   "Note that if you dump many databases at once (using the option "
   "--databases= or --all-databases), the logs will be flushed for "
   "each database dumped. The exception is when using --lock-all-tables "
   "or --master-data: "
   "in this case the logs will be flushed only once, corresponding "
   "to the moment all tables are locked. So if you want your dump and "
   "the log flush to happen at the same exact moment you should use "
   "--lock-all-tables or --master-data with --flush-logs.",
   &flush_logs, &flush_logs, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"flush-privileges", OPT_ESC, "Emit a FLUSH PRIVILEGES statement "
   "after dumping the mysql database.  This option should be used any "
   "time the dump contains the mysql database and any other database "
   "that depends on the data in the mysql database for proper restore. ",
   &flush_privileges, &flush_privileges, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"force", 'f', "Continue even if we get an SQL error.",
   &opt_force, &opt_force, 0, GET_BOOL, NO_ARG,
   0, 0, 0, 0, 0, 0},
  {"help", '?', "Display this help message and exit.", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {"hex-blob", OPT_HEXBLOB, "Dump binary strings (BINARY, "
    "VARBINARY, BLOB) in hexadecimal format.",
   &opt_hex_blob, &opt_hex_blob, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"host", 'h', "Connect to host.", &current_host,
   &current_host, 0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"ignore-error", OPT_MYSQLDUMP_IGNORE_ERROR, "A comma-separated list of "
   "error numbers to be ignored if encountered during dump.",
   &opt_ignore_error, &opt_ignore_error, 0, GET_STR_ALLOC, REQUIRED_ARG, 0,
   0, 0, 0, 0, 0},
  {"ignore-table", OPT_IGNORE_TABLE,
   "Do not dump the specified table. To specify more than one table to ignore, "
   "use the directive multiple times, once for each table.  Each table must "
   "be specified with both database and table names, e.g., "
   "--ignore-table=database.table.",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"include-master-host-port", OPT_MYSQLDUMP_INCLUDE_MASTER_HOST_PORT,
   "Adds 'MASTER_HOST=<host>, MASTER_PORT=<port>' to 'CHANGE MASTER TO..' "
   "in dump produced with --dump-slave.", &opt_include_master_host_port,
   &opt_include_master_host_port, 0, GET_BOOL, NO_ARG,
   0, 0, 0, 0, 0, 0},
   {"innodb-optimize-keys", OPT_INNODB_OPTIMIZE_KEYS,
    "Use InnoDB fast index creation by creating secondary indexes after "
    "dumping the data.",
    &opt_innodb_optimize_keys, &opt_innodb_optimize_keys, 0, GET_BOOL, NO_ARG,
    0, 0, 0, 0, 0, 0},
  {"insert-ignore", OPT_INSERT_IGNORE, "Insert rows with INSERT IGNORE.",
   &opt_ignore, &opt_ignore, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"lines-terminated-by", OPT_LTB,
   "Lines in the output file are terminated by the given string.",
   &lines_terminated, &lines_terminated, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"lock-all-tables", 'x', "Locks all tables across all databases. This "
   "is achieved by taking a global read lock for the duration of the whole "
   "dump. Automatically turns --single-transaction and --lock-tables off.",
   &opt_lock_all_tables, &opt_lock_all_tables, 0, GET_BOOL, NO_ARG,
   0, 0, 0, 0, 0, 0},
  {"lock-tables", 'l', "Lock all tables for read.", &lock_tables,
   &lock_tables, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
  {"log-error", OPT_ERROR_LOG_FILE, "Append warnings and errors to given file.",
   &log_error_file, &log_error_file, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"master-data", OPT_MASTER_DATA,
   "This causes the binary log position and filename to be appended to the "
   "output. If equal to 1, will print it as a CHANGE MASTER command; if equal"
   " to 2, that command will be prefixed with a comment symbol. "
   "This option will turn --lock-all-tables on, unless --single-transaction "
   "is specified too (on servers that don't provide Binlog_snapshot_file and "
   "Binlog_snapshot_position status variables this will still take a "
   "global read lock for a short time at the beginning of the dump; "
   "don't forget to read about --single-transaction below). In all cases, "
   "any action on logs will happen at the exact moment of the dump. "
   "Option automatically turns --lock-tables off.",
   &opt_master_data, &opt_master_data, 0,
   GET_UINT, OPT_ARG, 0, 0, MYSQL_OPT_MASTER_DATA_COMMENTED_SQL, 0, 0, 0},
  {"max_allowed_packet", OPT_MAX_ALLOWED_PACKET, 
   "The maximum packet length to send to or receive from server.",
    &opt_max_allowed_packet, &opt_max_allowed_packet, 0,
    GET_ULONG, REQUIRED_ARG, 24*1024*1024, 4096,
   (longlong) 2L*1024L*1024L*1024L, MALLOC_OVERHEAD, 1024, 0},
  {"net_buffer_length", OPT_NET_BUFFER_LENGTH, 
   "The buffer size for TCP/IP and socket communication.",
    &opt_net_buffer_length, &opt_net_buffer_length, 0,
    GET_ULONG, REQUIRED_ARG, 1024*1024L-1025, 4096, 16*1024L*1024L,
   MALLOC_OVERHEAD-1024, 1024, 0},
  {"no-autocommit", OPT_AUTOCOMMIT,
   "Wrap tables with autocommit/commit statements.",
   &opt_autocommit, &opt_autocommit, 0, GET_BOOL, NO_ARG,
   0, 0, 0, 0, 0, 0},
  {"no-create-db", 'n',
   "Suppress the CREATE DATABASE ... IF EXISTS statement that normally is "
   "output for each dumped database if --all-databases or --databases is "
   "given.",
   &opt_create_db, &opt_create_db, 0, 
   GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"no-create-info", 't', "Don't write table creation info.",
   &opt_no_create_info, &opt_no_create_info, 0, GET_BOOL,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {"no-data", 'd', "No row information.", &opt_no_data,
   &opt_no_data, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"no-set-names", 'N', "Same as --skip-set-charset.",
   0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"opt", OPT_OPTIMIZE,
   "Same as --add-drop-table, --add-locks, --create-options, --quick, --extended-insert, --lock-tables, --set-charset, and --disable-keys. Enabled by default, disable with --skip-opt.",
   0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"order-by-primary", OPT_ORDER_BY_PRIMARY,
   "Sorts each table's rows by primary key, or first unique key, if such a key exists.  Useful when dumping a MyISAM table to be loaded into an InnoDB table, but will make the dump itself take considerably longer.",
   &opt_order_by_primary, &opt_order_by_primary, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"order-by-primary-desc", OPT_ORDER_BY_PRIMARY_DESC,
   "Taking backup ORDER BY primary key DESC.",
   &opt_order_by_primary_desc, &opt_order_by_primary_desc, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"password", 'p',
   "Password to use when connecting to server. If password is not given it's solicited on the tty.",
   0, 0, 0, GET_PASSWORD, OPT_ARG, 0, 0, 0, 0, 0, 0},
#ifdef _WIN32
  {"pipe", 'W', "Use named pipes to connect to server.", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
#endif
  {"port", 'P', "Port number to use for connection.", &opt_mysql_port,
   &opt_mysql_port, 0, GET_UINT, REQUIRED_ARG, 0, 0, 0, 0, 0,
   0},
  {"protocol", OPT_MYSQL_PROTOCOL, 
   "The protocol to use for connection (tcp, socket, pipe, memory).",
   0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"quick", 'q', "Don't buffer query, dump directly to stdout.",
   &quick, &quick, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
  {"quote-names",'Q', "Quote table and column names with backticks (`).",
   &opt_quoted, &opt_quoted, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0,
   0, 0},
  {"replace", OPT_MYSQL_REPLACE_INTO, "Use REPLACE INTO instead of INSERT INTO.",
   &opt_replace_into, &opt_replace_into, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0,
   0, 0},
  {"result-file", 'r',
   "Direct output to a given file. This option should be used in systems "
   "(e.g., DOS, Windows) that use carriage-return linefeed pairs (\\r\\n) "
   "to separate text lines. This option ensures that only a single newline "
   "is used.", 0, 0, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"routines", 'R', "Dump stored routines (functions and procedures).",
   &opt_routines, &opt_routines, 0, GET_BOOL,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {"set-charset", OPT_SET_CHARSET,
   "Add 'SET NAMES default_character_set' to the output.",
   &opt_set_charset, &opt_set_charset, 0, GET_BOOL, NO_ARG, 1,
   0, 0, 0, 0, 0},
  {"set-gtid-purged", OPT_SET_GTID_PURGED,
    "Add 'SET @@GLOBAL.GTID_PURGED' to the output. Possible values for "
    "this option are ON, OFF and AUTO. If ON is used and GTIDs "
    "are not enabled on the server, an error is generated. If OFF is "
    "used, this option does nothing. If AUTO is used and GTIDs are enabled "
    "on the server, 'SET @@GLOBAL.GTID_PURGED' is added to the output. "
    "If GTIDs are disabled, AUTO does nothing. If no value is supplied "
    "then the default (AUTO) value will be considered.",
    0, 0, 0, GET_STR, OPT_ARG,
    0, 0, 0, 0, 0, 0},
#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  {"shared-memory-base-name", OPT_SHARED_MEMORY_BASE_NAME,
   "Base name of shared memory.", &shared_memory_base_name, &shared_memory_base_name,
   0, GET_STR_ALLOC, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#endif
  /*
    Note that the combination --single-transaction --master-data
    will give bullet-proof binlog position only if server >=4.1.3. That's the
    old "FLUSH TABLES WITH READ LOCK does not block commit" fixed bug.
  */
  {"single-transaction", OPT_TRANSACTION,
   "Creates a consistent snapshot by dumping all tables in a single "
   "transaction. Works ONLY for tables stored in storage engines which "
   "support multiversioning (currently only InnoDB does); the dump is NOT "
   "guaranteed to be consistent for other storage engines. "
   "While a --single-transaction dump is in process, to ensure a valid "
   "dump file (correct table contents and binary log position), no other "
   "connection should use the following statements: ALTER TABLE, DROP "
   "TABLE, RENAME TABLE, TRUNCATE TABLE, as consistent snapshot is not "
   "isolated from them. Option automatically turns off --lock-tables.",
   &opt_single_transaction, &opt_single_transaction, 0,
   GET_BOOL, NO_ARG,  0, 0, 0, 0, 0, 0},
  {"dump-date", OPT_DUMP_DATE, "Put a dump date to the end of the output.",
   &opt_dump_date, &opt_dump_date, 0,
   GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
  {"skip_mysql_schema", OPT_SKIP_MYSQL_SCHEMA, "Skip adding DROP DATABASE for mysql schema.",
   &opt_skip_mysql_schema, &opt_skip_mysql_schema, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0,
   0},
  {"skip-opt", OPT_SKIP_OPTIMIZATION,
   "Disable --opt. Disables --add-drop-table, --add-locks, --create-options, --quick, --extended-insert, --lock-tables, --set-charset, and --disable-keys.",
   0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"socket", 'S', "The socket file to use for connection.",
   &opt_mysql_unix_port, &opt_mysql_unix_port, 0, 
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"secure-auth", OPT_SECURE_AUTH, "Refuse client connecting to server if it"
    " uses old (pre-4.1.1) protocol. Deprecated. Always TRUE",
    &opt_secure_auth, &opt_secure_auth, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
#ifndef NDEBUG
	{"start-sql-file", OPT_START_SQL_FILE, "Execute SQL statements from the file"
    " at the mysqldump start. Each line has to contain one statement terminated"
    " with a semicolon. Line length limit is 1023 characters.",
    &start_sql_file, &start_sql_file, 0, GET_STR,
   REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"finish-sql-file", OPT_FINISH_SQL_FILE, "Execute SQL statements from the file"
    " at the mysqldump finish. Each line has to contain one statement terminated"
    " with a semicolon. Line length limit is 1023 characters.",
    &finish_sql_file, &finish_sql_file, 0, GET_STR,
    REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
#endif  // DEBUF_OFF
#include <sslopt-longopts.h>
#include <caching_sha2_passwordopt-longopts.h>
  {"tab",'T',
   "Create tab-separated textfile for each table to given path. (Create .sql "
   "and .txt files.) NOTE: This only works if mysqldump is run on the same "
   "machine as the mysqld server.",
   &path, &path, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"tables", OPT_TABLES, "Overrides option --databases (-B).",
   0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"triggers", OPT_TRIGGERS, "Dump triggers for each dumped table.",
   &opt_dump_triggers, &opt_dump_triggers, 0, GET_BOOL,
   NO_ARG, 1, 0, 0, 0, 0, 0},
  {"tz-utc", OPT_TZ_UTC,
    "SET TIME_ZONE='+00:00' at top of dump to allow dumping of TIMESTAMP data when a server has data in different time zones or data is being moved between servers with different time zones.",
    &opt_tz_utc, &opt_tz_utc, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0, 0},
  {"user", 'u', "User for login if not current user.",
   &current_user, &current_user, 0, GET_STR, REQUIRED_ARG,
   0, 0, 0, 0, 0, 0},
  {"verbose", 'v', "Print info about the various stages.",
   &verbose, &verbose, 0, GET_BOOL, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"version",'V', "Output version information and exit.", 0, 0, 0,
   GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0},
  {"where", 'w', "Dump only selected records. Quotes are mandatory.",
   &where, &where, 0, GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"xml", 'X', "Dump a database as well formed XML.", 0, 0, 0, GET_NO_ARG,
   NO_ARG, 0, 0, 0, 0, 0, 0},
  {"plugin_dir", OPT_PLUGIN_DIR, "Directory for client-side plugins.",
   &opt_plugin_dir, &opt_plugin_dir, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"default_auth", OPT_DEFAULT_AUTH,
   "Default authentication client-side plugin to use.",
   &opt_default_auth, &opt_default_auth, 0,
   GET_STR, REQUIRED_ARG, 0, 0, 0, 0, 0, 0},
  {"enable_cleartext_plugin", OPT_ENABLE_CLEARTEXT_PLUGIN,
   "Enable/disable the clear text authentication plugin.",
   &opt_enable_cleartext_plugin, &opt_enable_cleartext_plugin,
   0, GET_BOOL, OPT_ARG, 0, 0, 0, 0, 0, 0},
  {"enable-compressed-columns", OPT_ENABLE_COMPRESSED_COLUMNS,
   "Enable compressed columns extensions.",
   &opt_compressed_columns, &opt_compressed_columns, 0, GET_BOOL, NO_ARG,
   0, 0, 0, 0, 0, 0},
  {"enable-compressed-columns-with-dictionaries",
   OPT_ENABLE_COMPRESSED_COLUMNS_WITH_DICTIONARIES,
   "Enable dictionaries for compressed columns extensions.",
   &opt_compressed_columns_with_dictionaries,
   &opt_compressed_columns_with_dictionaries, 0, GET_BOOL, NO_ARG,
   0, 0, 0, 0, 0, 0},
   {"add-drop-compression-dictionary", OPT_DROP_COMPRESSION_DICTIONARY,
    "Add a DROP COMPRESSION_DICTIONARY before each create.",
    &opt_drop_compression_dictionary,
    &opt_drop_compression_dictionary, 0, GET_BOOL, NO_ARG, 1, 0, 0, 0, 0,
    0},
  {0, 0, 0, 0, 0, 0, GET_NO_ARG, NO_ARG, 0, 0, 0, 0, 0, 0}
};

static const char *load_default_groups[]= { "mysqldump","client",0 };

static void maybe_exit(int error);
static void die(int error, const char* reason, ...);
static void maybe_die(int error, const char* reason, ...);
static void write_header(FILE *sql_file, char *db_name);
static void print_value(FILE *file, MYSQL_RES  *result, MYSQL_ROW row,
                        const char *prefix,const char *name,
                        int string_value);
static int dump_selected_tables(char *db, char **table_names, int tables);
static int dump_all_tables_in_db(char *db);
static int init_dumping_views(char *, my_bool);
static int init_dumping_tables(char *, my_bool);
static int init_dumping(char *, int init_func(char*, my_bool));
static int dump_databases(char **);
static int dump_all_databases();
static char *quote_name(const char *name, char *buff, my_bool force);
char check_if_ignore_table(const char *table_name, char *table_type);
static char *primary_key_fields(const char *table_name, const my_bool desc);
static my_bool get_view_structure(char *table, char* db);
static my_bool dump_all_views_in_db(char *database);
static int dump_all_tablespaces();
static int dump_tablespaces_for_tables(char *db, char **table_names, int tables);
static int dump_tablespaces_for_databases(char** databases);
static int dump_tablespaces(char* ts_where);
static void print_comment(FILE *sql_file, my_bool is_error, const char *format,
                          ...);
static char const* fix_identifier_with_newline(char const* object_name,
                                               my_bool* freemem);

/*
  Print the supplied message if in verbose mode

  SYNOPSIS
    verbose_msg()
    fmt   format specifier
    ...   variable number of parameters
*/

static void verbose_msg(const char *fmt, ...)
{
  va_list args;
  DBUG_ENTER("verbose_msg");

  if (!verbose)
    DBUG_VOID_RETURN;

  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);

  fflush(stderr);

  DBUG_VOID_RETURN;
}

/*
  exit with message if ferror(file)

  SYNOPSIS
    check_io()
    file        - checked file
*/

void check_io(FILE *file)
{
  if (ferror(file) || errno == 5)
    die(EX_EOF, "Got errno %d on write", errno);
}

static void print_version(void)
{
  printf("%s  Ver %s Distrib %s, for %s (%s)\n",my_progname,DUMP_VERSION,
         MYSQL_SERVER_VERSION,SYSTEM_TYPE,MACHINE_TYPE);
} /* print_version */


static void short_usage_sub(void)
{
  printf("Usage: %s [OPTIONS] database [tables]\n", my_progname);
  printf("OR     %s [OPTIONS] --databases [OPTIONS] DB1 [DB2 DB3...]\n",
         my_progname);
  printf("OR     %s [OPTIONS] --all-databases [OPTIONS]\n", my_progname);
}


static void usage(void)
{
  struct my_option *optp;
  print_version();
  puts(ORACLE_WELCOME_COPYRIGHT_NOTICE("2000"));
  puts("Dumping structure and contents of MySQL databases and tables.");
  short_usage_sub();
  print_defaults("my",load_default_groups);
  /*
    Turn default for zombies off so that the help on how to 
    turn them off text won't show up.
    This is safe to do since it's followed by a call to exit().
  */
  for (optp= my_long_options; optp->name; optp++)
  {
    if (optp->id == OPT_SECURE_AUTH)
    {
      optp->def_value= 0;
      break;
    }
  }
  my_print_help(my_long_options);
  my_print_variables(my_long_options);
} /* usage */


static void short_usage(void)
{
  short_usage_sub();
  printf("For more options, use %s --help\n", my_progname);
}


static void write_header(FILE *sql_file, char *db_name)
{
  if (opt_xml)
  {
    fputs("<?xml version=\"1.0\"?>\n", sql_file);
    /*
      Schema reference.  Allows use of xsi:nil for NULL values and 
      xsi:type to define an element's data type.
    */
    fputs("<mysqldump ", sql_file);
    fputs("xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"",
          sql_file);
    fputs(">\n", sql_file);
    check_io(sql_file);
  }
  else if (!opt_compact)
  {
    my_bool freemem= FALSE;
    char const* text= fix_identifier_with_newline(db_name, &freemem);

    print_comment(sql_file, 0,
                  "-- MySQL dump %s  Distrib %s, for %s (%s)\n--\n",
                  DUMP_VERSION, MYSQL_SERVER_VERSION, SYSTEM_TYPE,
                  MACHINE_TYPE);
    print_comment(sql_file, 0, "-- Host: %s    Database: %s\n",
                  current_host ? current_host : "localhost",
                  text);

    if (freemem)
      my_free((void*)text);

    print_comment(sql_file, 0,
                  "-- ------------------------------------------------------\n"
                 );
    print_comment(sql_file, 0, "-- Server version\t%s\n",
                  mysql_get_server_info(&mysql_connection));

    if (opt_set_charset)
      fprintf(sql_file,
"\n/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;"
"\n/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;"
"\n/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;"
"\n/*!40101 SET NAMES %s */;\n",default_charset);

    if (opt_tz_utc)
    {
      fprintf(sql_file, "/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;\n");
      fprintf(sql_file, "/*!40103 SET TIME_ZONE='+00:00' */;\n");
    }

    if (!path)
    {
      fprintf(md_result_file,"\
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;\n\
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;\n\
");
    }
    fprintf(sql_file,
            "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='%s%s%s' */;\n"
            "/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;\n",
            path?"":"NO_AUTO_VALUE_ON_ZERO",compatible_mode_normal_str[0]==0?"":",",
            compatible_mode_normal_str);

    // This is specifically to allow MyRocks to bulk load a dump faster
    // We have no interest in anything earlier than 5.7 and 17 being the
    // current release. 5.7.8 and after can only use P_S for session_variables
    // and never I_S. So we first check that P_S is present and the
    // session_variables table exists. If no, we simply skip the optimization
    // assuming that MyRocks isn't present either. If it is, ohh well, bulk
    // loader will not be invoked.
    fprintf(sql_file,
            "/*!50717 SELECT COUNT(*) INTO @rocksdb_has_p_s_session_variables"
            " FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA ="
            " 'performance_schema' AND TABLE_NAME = 'session_variables'"
            " */;\n"
            "/*!50717 SET @rocksdb_get_is_supported = IF"
            " (@rocksdb_has_p_s_session_variables, 'SELECT COUNT(*) INTO"
            " @rocksdb_is_supported FROM performance_schema.session_variables"
            " WHERE VARIABLE_NAME=\\'rocksdb_bulk_load\\'', 'SELECT 0') */;\n"
            "/*!50717 PREPARE s FROM @rocksdb_get_is_supported */;\n"
            "/*!50717 EXECUTE s */;\n"
            "/*!50717 DEALLOCATE PREPARE s */;\n"
            "/*!50717 SET @rocksdb_enable_bulk_load = IF"
            " (@rocksdb_is_supported, 'SET SESSION rocksdb_bulk_load = 1',"
            " 'SET @rocksdb_dummy_bulk_load = 0') */;\n"
            "/*!50717 PREPARE s FROM @rocksdb_enable_bulk_load */;\n"
            "/*!50717 EXECUTE s */;\n"
            "/*!50717 DEALLOCATE PREPARE s */;\n");


    check_io(sql_file);
  }
} /* write_header */


static void write_footer(FILE *sql_file)
{
  if (opt_xml)
  {
    fputs("</mysqldump>\n", sql_file);
    check_io(sql_file);
  }
  else if (!opt_compact)
  {
    fprintf(sql_file,
            "/*!50112 SET @disable_bulk_load = IF (@is_rocksdb_supported,"
            " 'SET SESSION rocksdb_bulk_load = @old_rocksdb_bulk_load',"
            " 'SET @dummy_rocksdb_bulk_load = 0') */;\n"
            "/*!50112 PREPARE s FROM @disable_bulk_load */;\n"
            "/*!50112 EXECUTE s */;\n"
            "/*!50112 DEALLOCATE PREPARE s */;\n");


    if (opt_tz_utc)
      fprintf(sql_file,"/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;\n");

    fprintf(sql_file,"\n/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n");
    if (!path)
    {
      fprintf(md_result_file,"\
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;\n\
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;\n");
    }
    if (opt_set_charset)
      fprintf(sql_file,
"/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
"/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;\n"
"/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;\n");
    fprintf(sql_file,
            "/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n");
    fputs("\n", sql_file);

    if (opt_dump_date)
    {
      char time_str[20];
      get_date(time_str, GETDATE_DATE_TIME, 0);
      print_comment(sql_file, 0, "-- Dump completed on %s\n", time_str);
    }
    else
      print_comment(sql_file, 0, "-- Dump completed\n");

    check_io(sql_file);
  }
} /* write_footer */


uchar* get_table_key(const char *entry, size_t *length,
                     my_bool not_used MY_ATTRIBUTE((unused)))
{
  *length= strlen(entry);
  return (uchar*) entry;
}


static my_bool
get_one_option(int optid, const struct my_option *opt MY_ATTRIBUTE((unused)),
               char *argument)
{
  switch (optid) {
  case 'p':
    if (argument == disabled_my_option)
      argument= (char*) "";                     /* Don't require password */
    if (argument)
    {
      char *start=argument;
      my_free(opt_password);
      opt_password=my_strdup(PSI_NOT_INSTRUMENTED,
                             argument,MYF(MY_FAE));
      while (*argument) *argument++= 'x';               /* Destroy argument */
      if (*start)
        start[1]=0;                             /* Cut length of argument */
      tty_password= 0;
    }
    else
      tty_password=1;
    break;
  case 'r':
    if (!(md_result_file= my_fopen(argument, O_WRONLY | FILE_BINARY,
                                    MYF(MY_WME))))
      exit(1);
    break;
  case 'W':
#ifdef _WIN32
    opt_protocol= MYSQL_PROTOCOL_PIPE;
#endif
    break;
  case 'N':
    opt_set_charset= 0;
    break;
  case 'T':
    opt_disable_keys=0;

    if (strlen(argument) >= FN_REFLEN)
    {
      /*
        This check is made because the some the file functions below
        have FN_REFLEN sized stack allocated buffers and will cause
        a crash even if the input destination buffer is large enough
        to hold the output.
      */
      die(EX_USAGE, "Input filename too long: %s", argument);
    }

    break;
  case '#':
    DBUG_PUSH(argument ? argument : default_dbug_option);
    debug_check_flag= 1;
    break;
#include <sslopt-case.h>
  case 'V': print_version(); exit(0);
  case 'X':
    opt_xml= 1;
    extended_insert= opt_drop= opt_lock=
      opt_disable_keys= opt_autocommit= opt_create_db= 0;
    break;
  case 'i':
    opt_comments_used= 1;
    break;
  case 'I':
  case '?':
    usage();
    exit(0);
  case (int) OPT_MASTER_DATA:
    if (!argument) /* work like in old versions */
      opt_master_data= MYSQL_OPT_MASTER_DATA_EFFECTIVE_SQL;
    break;
  case (int) OPT_MYSQLDUMP_SLAVE_DATA:
    if (!argument) /* work like in old versions */
      opt_slave_data= MYSQL_OPT_SLAVE_DATA_EFFECTIVE_SQL;
    break;
  case (int) OPT_OPTIMIZE:
    extended_insert= opt_drop= opt_lock= quick= create_options=
      opt_disable_keys= lock_tables= opt_set_charset= 1;
    break;
  case (int) OPT_SKIP_OPTIMIZATION:
    extended_insert= opt_drop= opt_lock= quick= create_options=
      opt_disable_keys= lock_tables= opt_set_charset= 0;
    break;
  case (int) OPT_COMPACT:
    if (opt_compact)
    {
       opt_comments= opt_drop= opt_disable_keys= opt_lock= 0;
       opt_set_charset= 0;
    }
    break;
  case (int) OPT_TABLES:
    opt_databases=0;
    break;
  case (int) OPT_IGNORE_TABLE:
  {
    if (!strchr(argument, '.'))
    {
      fprintf(stderr, "Illegal use of option --ignore-table=<database>.<table>\n");
      exit(1);
    }
    if (my_hash_insert(&ignore_table, (uchar*)my_strdup(PSI_NOT_INSTRUMENTED,
                                                        argument, MYF(0))))
      exit(EX_EOM);
    break;
  }
  case (int) OPT_COMPATIBLE:
    {
      char buff[255];
      char *end= compatible_mode_normal_str;
      int i;
      ulong mode;
      uint err_len;

      opt_quoted= 1;
      opt_set_charset= 0;
      opt_compatible_mode_str= argument;
      opt_compatible_mode= find_set(&compatible_mode_typelib,
                                    argument, strlen(argument),
                                    &err_ptr, &err_len);
      if (err_len)
      {
        strmake(buff, err_ptr, MY_MIN(sizeof(buff) - 1, err_len));
        fprintf(stderr, "Invalid mode to --compatible: %s\n", buff);
        exit(1);
      }
#if !defined(NDEBUG)
      {
        size_t size_for_sql_mode= 0;
        const char **ptr;
        for (ptr= compatible_mode_names; *ptr; ptr++)
          size_for_sql_mode+= strlen(*ptr);
        size_for_sql_mode+= sizeof(compatible_mode_names)-1;
        assert(sizeof(compatible_mode_normal_str)>=size_for_sql_mode);
      }
#endif
      mode= opt_compatible_mode;
      for (i= 0, mode= opt_compatible_mode; mode; mode>>= 1, i++)
      {
        if (mode & 1)
        {
          end= my_stpcpy(end, compatible_mode_names[i]);
          end= my_stpcpy(end, ",");
        }
      }
      if (end!=compatible_mode_normal_str)
        end[-1]= 0;
      /*
        Set charset to the default compiled value if it hasn't
        been reset yet by --default-character-set=xxx.
      */
      if (default_charset == mysql_universal_client_charset)
        default_charset= (char*) MYSQL_DEFAULT_CHARSET_NAME;
      break;
    }
  case (int) OPT_ENABLE_CLEARTEXT_PLUGIN:
    using_opt_enable_cleartext_plugin= TRUE;
    break;
  case (int) OPT_MYSQL_PROTOCOL:
    opt_protocol= find_type_or_exit(argument, &sql_protocol_typelib,
                                    opt->name);
    break;
  case (int) OPT_SET_GTID_PURGED:
    {
      if (argument)
        opt_set_gtid_purged_mode= find_type_or_exit(argument,
                                                    &set_gtid_purged_mode_typelib,
                                                    opt->name)-1;
      break;
    }
  case (int) OPT_MYSQLDUMP_IGNORE_ERROR:
    /* Store the supplied list of errors into an array. */
    if (parse_ignore_error())
      exit(EX_EOM);
    break;
  case OPT_SECURE_AUTH:
    /* --secure-auth is a zombie option. */
    if (!opt_secure_auth)
    {
      fprintf(stderr, "mysqldump: [ERROR] --skip-secure-auth is not supported.\n");
      exit(1);
    }
    else
      CLIENT_WARN_DEPRECATED_NO_REPLACEMENT("--secure-auth");
    break;
  }
  return 0;
}

static int get_options(int *argc, char ***argv)
{
  int ho_error;

  if (mysql_get_option(NULL, MYSQL_OPT_MAX_ALLOWED_PACKET, &opt_max_allowed_packet) ||
      mysql_get_option(NULL, MYSQL_OPT_NET_BUFFER_LENGTH, &opt_max_allowed_packet))
  {
    exit(1);
  }

  md_result_file= stdout;
  my_getopt_use_args_separator= TRUE;
  if (load_defaults("my",load_default_groups,argc,argv))
    return 1;
  my_getopt_use_args_separator= FALSE;

  defaults_argv= *argv;

  if (my_hash_init(&ignore_table, charset_info, 16, 0, 0,
                   (my_hash_get_key) get_table_key, my_free, 0,
                   PSI_NOT_INSTRUMENTED))
    return(EX_EOM);
  /* Don't copy internal log tables */
  if (my_hash_insert(&ignore_table,
                     (uchar*) my_strdup(PSI_NOT_INSTRUMENTED,
                                        "mysql.apply_status", MYF(MY_WME))) ||
      my_hash_insert(&ignore_table,
                     (uchar*) my_strdup(PSI_NOT_INSTRUMENTED,
                                        "mysql.schema", MYF(MY_WME))) ||
      my_hash_insert(&ignore_table,
                     (uchar*) my_strdup(PSI_NOT_INSTRUMENTED,
                                        "mysql.general_log", MYF(MY_WME))) ||
      my_hash_insert(&ignore_table,
                     (uchar*) my_strdup(PSI_NOT_INSTRUMENTED,
                                        "mysql.slow_log", MYF(MY_WME))))
    return(EX_EOM);

  if (my_hash_init(&processed_compression_dictionaries, charset_info, 16, 0,
    0, (my_hash_get_key)get_table_key, my_free, 0, PSI_NOT_INSTRUMENTED))
    return(EX_EOM);

  if ((ho_error= handle_options(argc, argv, my_long_options, get_one_option)))
    return(ho_error);

  if (mysql_options(NULL, MYSQL_OPT_MAX_ALLOWED_PACKET, &opt_max_allowed_packet) ||
      mysql_options(NULL, MYSQL_OPT_NET_BUFFER_LENGTH, &opt_net_buffer_length))
  {
    exit(1);
  }

  if (debug_info_flag)
    my_end_arg= MY_CHECK_ERROR | MY_GIVE_INFO;
  if (debug_check_flag)
    my_end_arg= MY_CHECK_ERROR;

  if (!path && (enclosed || opt_enclosed || escaped || lines_terminated ||
                fields_terminated))
  {
    fprintf(stderr,
            "%s: You must use option --tab with --fields-...\n", my_progname);
    return(EX_USAGE);
  }

  if (opt_lock_for_backup && opt_lock_all_tables)
  {
    fprintf(stderr, "%s: You can't use --lock-for-backup and "
            "--lock-all-tables at the same time.\n", my_progname);
    return(EX_USAGE);
  }

  /*
     Convert --lock-for-backup to --lock-all-tables if --single-transaction is
     not specified.
  */
  if (!opt_single_transaction && opt_lock_for_backup)
  {
    opt_lock_all_tables= 1;
    opt_lock_for_backup= 0;
  }

  /* We don't delete master logs if slave data option */
  if (opt_slave_data)
  {
    opt_lock_all_tables= !opt_single_transaction;
    opt_master_data= 0;
    opt_delete_master_logs= 0;
  }

  /* Ensure consistency of the set of binlog & locking options */
  if (opt_delete_master_logs && !opt_master_data)
    opt_master_data= MYSQL_OPT_MASTER_DATA_COMMENTED_SQL;
  if (opt_single_transaction && opt_lock_all_tables)
  {
    fprintf(stderr, "%s: You can't use --single-transaction and "
            "--lock-all-tables at the same time.\n", my_progname);
    return(EX_USAGE);
  }
  if (opt_master_data)
  {
    opt_lock_all_tables= !opt_single_transaction;
    opt_slave_data= 0;
  }
  if (opt_single_transaction || opt_lock_all_tables)
    lock_tables= 0;
  if (enclosed && opt_enclosed)
  {
    fprintf(stderr, "%s: You can't use ..enclosed.. and ..optionally-enclosed.. at the same time.\n", my_progname);
    return(EX_USAGE);
  }
  if ((opt_databases || opt_alldbs) && path)
  {
    fprintf(stderr,
            "%s: --databases or --all-databases can't be used with --tab.\n",
            my_progname);
    return(EX_USAGE);
  }
  if (strcmp(default_charset, charset_info->csname) &&
      !(charset_info= get_charset_by_csname(default_charset,
                                            MY_CS_PRIMARY, MYF(MY_WME))))
    exit(1);
  if ((*argc < 1 && !opt_alldbs) || (*argc > 0 && opt_alldbs))
  {
    short_usage();
    return EX_USAGE;
  }
  if (tty_password)
    opt_password=get_tty_password(NullS);
  return(0);
} /* get_options */


/*
** DB_error -- prints mysql error message and exits the program.
*/
static void DB_error(MYSQL *mysql_arg, const char *when)
{
  DBUG_ENTER("DB_error");
  maybe_die(EX_MYSQLERR, "Got error: %d: %s %s",
          mysql_errno(mysql_arg), mysql_error(mysql_arg), when);
  DBUG_VOID_RETURN;
}



/*
  Prints out an error message and kills the process.

  SYNOPSIS
    die()
    error_num   - process return value
    fmt_reason  - a format string for use by my_vsnprintf.
    ...         - variable arguments for above fmt_reason string
  
  DESCRIPTION
    This call prints out the formatted error message to stderr and then
    terminates the process.
*/
static void die(int error_num, const char* fmt_reason, ...)
{
  char buffer[1000];
  va_list args;
  va_start(args,fmt_reason);
  my_vsnprintf(buffer, sizeof(buffer), fmt_reason, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", my_progname, buffer);
  fflush(stderr);

  /* force the exit */
  opt_force= 0;
  if (opt_ignore_error)
    my_free(opt_ignore_error);
  opt_ignore_error= 0;

  maybe_exit(error_num);
}


/*
  Prints out an error message and maybe kills the process.

  SYNOPSIS
    maybe_die()
    error_num   - process return value
    fmt_reason  - a format string for use by my_vsnprintf.
    ...         - variable arguments for above fmt_reason string
  
  DESCRIPTION
    This call prints out the formatted error message to stderr and then
    terminates the process, unless the --force command line option is used.
    
    This call should be used for non-fatal errors (such as database
    errors) that the code may still be able to continue to the next unit
    of work.
    
*/
static void maybe_die(int error_num, const char* fmt_reason, ...)
{
  char buffer[1000];
  va_list args;
  va_start(args,fmt_reason);
  my_vsnprintf(buffer, sizeof(buffer), fmt_reason, args);
  va_end(args);

  fprintf(stderr, "%s: %s\n", my_progname, buffer);
  fflush(stderr);

  maybe_exit(error_num);
}



/*
  Sends a query to server, optionally reads result, prints error message if
  some.

  SYNOPSIS
    mysql_query_with_error_report()
    mysql_con       connection to use
    res             if non zero, result will be put there with
                    mysql_store_result()
    query           query to send to server

  RETURN VALUES
    0               query sending and (if res!=0) result reading went ok
    1               error
*/

static int mysql_query_with_error_report(MYSQL *mysql_con, MYSQL_RES **res,
                                         const char *query)
{
  if (mysql_query(mysql_con, query) ||
      (res && !((*res)= mysql_store_result(mysql_con))))
  {
    maybe_die(EX_MYSQLERR, "Couldn't execute '%s': %s (%d)",
            query, mysql_error(mysql_con), mysql_errno(mysql_con));
    return 1;
  }
  return 0;
}


static int fetch_db_collation(const char *db_name,
                              char *db_cl_name,
                              int db_cl_size)
{
  my_bool err_status= FALSE;
  char query[QUERY_LENGTH];
  MYSQL_RES *db_cl_res;
  MYSQL_ROW db_cl_row;
  char quoted_database_buf[NAME_LEN*2+3];
  char *qdatabase= quote_name(db_name, quoted_database_buf, 1);

  my_snprintf(query, sizeof (query), "use %s", qdatabase);

  if (mysql_query_with_error_report(mysql, NULL, query))
    return 1;

  if (mysql_query_with_error_report(mysql, &db_cl_res,
                                    "select @@collation_database"))
    return 1;

  do
  {
    if (mysql_num_rows(db_cl_res) != 1)
    {
      err_status= TRUE;
      break;
    }

    if (!(db_cl_row= mysql_fetch_row(db_cl_res)))
    {
      err_status= TRUE;
      break;
    }

    strncpy(db_cl_name, db_cl_row[0], db_cl_size-1);
    db_cl_name[db_cl_size - 1]= 0;

  } while (FALSE);

  mysql_free_result(db_cl_res);

  return err_status ? 1 : 0;
}

/*
  Check if server supports binlog_snapshot_gtid_executed.
  Returns 1 supported, 0 if not.
 */
static int
consistent_gtid_executed_supported(MYSQL *mysql_con)
{
  MYSQL_RES *res;
  MYSQL_ROW row;
  int found = 0;

  if (mysql_query_with_error_report(
		  mysql_con, &res, "SHOW STATUS LIKE 'binlog_snapshot_gtid_executed'"))
    return 0;

  while ((row= mysql_fetch_row(res)))
  {
    if (0 == strcmp(row[0], "Binlog_snapshot_gtid_executed"))
    {
      found= 1;
      break;
    }
  }
  mysql_free_result(res);

  return found;
}

/*
  Check if server supports non-blocking binlog position using the
  binlog_snapshot_file and binlog_snapshot_position status variables. If it
  does, also return the position obtained if output pointers are non-NULL.
  Returns 1 if position available, 0 if not.
*/
static int
check_consistent_binlog_pos(char *binlog_pos_file, char *binlog_pos_offset)
{
  MYSQL_RES *res;
  MYSQL_ROW row;
  int found;

  if (mysql_query_with_error_report(mysql, &res,
                                    "SHOW STATUS LIKE 'binlog_snapshot_%'"))
    return 0;

  found= 0;
  while ((row= mysql_fetch_row(res)))
  {
    if (0 == strcmp(row[0], "Binlog_snapshot_file"))
    {
      if (binlog_pos_file)
        strmake(binlog_pos_file, row[1], FN_REFLEN-1);
      found++;
    }
    else if (0 == strcmp(row[0], "Binlog_snapshot_position"))
    {
      if (binlog_pos_offset)
        strmake(binlog_pos_offset, row[1], LONGLONG_LEN);
      found++;
    }
  }
  mysql_free_result(res);

  return (found == 2);
}

static char *my_case_str(const char *str,
                         size_t str_len,
                         const char *token,
                         size_t token_len)
{
  my_match_t match;

  uint status= my_charset_latin1.coll->instr(&my_charset_latin1,
                                             str, str_len,
                                             token, token_len,
                                             &match, 1);

  return status ? (char *) str + match.end : NULL;
}


static int switch_db_collation(FILE *sql_file,
                               const char *db_name,
                               const char *delimiter,
                               const char *current_db_cl_name,
                               const char *required_db_cl_name,
                               int *db_cl_altered)
{
  if (strcmp(current_db_cl_name, required_db_cl_name) != 0)
  {
    char quoted_db_buf[NAME_LEN * 2 + 3];
    char *quoted_db_name= quote_name(db_name, quoted_db_buf, FALSE);

    CHARSET_INFO *db_cl= get_charset_by_name(required_db_cl_name, MYF(0));

    if (!db_cl)
      return 1;

    fprintf(sql_file,
            "ALTER DATABASE %s CHARACTER SET %s COLLATE %s %s\n",
            (const char *) quoted_db_name,
            (const char *) db_cl->csname,
            (const char *) db_cl->name,
            (const char *) delimiter);

    *db_cl_altered= 1;

    return 0;
  }

  *db_cl_altered= 0;

  return 0;
}


static int restore_db_collation(FILE *sql_file,
                                const char *db_name,
                                const char *delimiter,
                                const char *db_cl_name)
{
  char quoted_db_buf[NAME_LEN * 2 + 3];
  char *quoted_db_name= quote_name(db_name, quoted_db_buf, FALSE);

  CHARSET_INFO *db_cl= get_charset_by_name(db_cl_name, MYF(0));

  if (!db_cl)
    return 1;

  fprintf(sql_file,
          "ALTER DATABASE %s CHARACTER SET %s COLLATE %s %s\n",
          (const char *) quoted_db_name,
          (const char *) db_cl->csname,
          (const char *) db_cl->name,
          (const char *) delimiter);

  return 0;
}


static void switch_cs_variables(FILE *sql_file,
                                const char *delimiter,
                                const char *character_set_client,
                                const char *character_set_results,
                                const char *collation_connection)
{
  fprintf(sql_file,
          "/*!50003 SET @saved_cs_client      = @@character_set_client */ %s\n"
          "/*!50003 SET @saved_cs_results     = @@character_set_results */ %s\n"
          "/*!50003 SET @saved_col_connection = @@collation_connection */ %s\n"
          "/*!50003 SET character_set_client  = %s */ %s\n"
          "/*!50003 SET character_set_results = %s */ %s\n"
          "/*!50003 SET collation_connection  = %s */ %s\n",
          (const char *) delimiter,
          (const char *) delimiter,
          (const char *) delimiter,

          (const char *) character_set_client,
          (const char *) delimiter,

          (const char *) character_set_results,
          (const char *) delimiter,

          (const char *) collation_connection,
          (const char *) delimiter);
}


static void restore_cs_variables(FILE *sql_file,
                                 const char *delimiter)
{
  fprintf(sql_file,
          "/*!50003 SET character_set_client  = @saved_cs_client */ %s\n"
          "/*!50003 SET character_set_results = @saved_cs_results */ %s\n"
          "/*!50003 SET collation_connection  = @saved_col_connection */ %s\n",
          (const char *) delimiter,
          (const char *) delimiter,
          (const char *) delimiter);
}

/*
 This function will remove specific sql mode.

  @param[in]   sql_mode      Original sql mode from where input mode needs to
                             be removed.
  @param[in]   replace_mode  sql mode which needs to be removed from original
                             sql mode.
  @param[in]   replace_len   length of sql mode which needs to be removed.

  @retval  1 replace_mode is not present
           0 replace_mode is removed successfully
*/
static int remove_sql_mode(char* sql_mode, const char* replace_mode,
  size_t replace_len) {
  char *start = strstr(sql_mode, replace_mode);
  /* nothing to replace */
  if (!start)
    return 1;
  /* sql mode to replace is the only sql mode present or the last one */
  if (strlen(start) == replace_len) {
    if (start == sql_mode)
      *start = 0;
    else
      start[-1] = 0;
  }
  else {
    const char *next = start + replace_len + 1;
    memmove(start, next, strlen(next) + 1);
  }
  return 0;
}

static void switch_sql_mode(FILE *sql_file,
                            const char *delimiter,
                            const char *sql_mode)
{
  fprintf(sql_file,
          "/*!50003 SET @saved_sql_mode       = @@sql_mode */ %s\n"
          "/*!50003 SET sql_mode              = '%s' */ %s\n",
          (const char *) delimiter,

          (const char *) sql_mode,
          (const char *) delimiter);
}


static void restore_sql_mode(FILE *sql_file,
                             const char *delimiter)
{
  fprintf(sql_file,
          "/*!50003 SET sql_mode              = @saved_sql_mode */ %s\n",
          (const char *) delimiter);
}


static void switch_time_zone(FILE *sql_file,
                             const char *delimiter,
                             const char *time_zone)
{
  fprintf(sql_file,
          "/*!50003 SET @saved_time_zone      = @@time_zone */ %s\n"
          "/*!50003 SET time_zone             = '%s' */ %s\n",
          (const char *) delimiter,

          (const char *) time_zone,
          (const char *) delimiter);
}


static void restore_time_zone(FILE *sql_file,
                              const char *delimiter)
{
  fprintf(sql_file,
          "/*!50003 SET time_zone             = @saved_time_zone */ %s\n",
          (const char *) delimiter);
}


/**
  Switch charset for results to some specified charset.  If the server does not
  support character_set_results variable, nothing can be done here.  As for
  whether something should be done here, future new callers of this function
  should be aware that the server lacking the facility of switching charsets is
  treated as success.

  @note  If the server lacks support, then nothing is changed and no error
         condition is returned.

  @returns  whether there was an error or not
*/
static int switch_character_set_results(MYSQL *mysql, const char *cs_name)
{
  char query_buffer[QUERY_LENGTH];
  size_t query_length;

  /* Server lacks facility.  This is not an error, by arbitrary decision . */
  if (!server_supports_switching_charsets)
    return FALSE;

  query_length= my_snprintf(query_buffer,
                            sizeof (query_buffer),
                            "SET SESSION character_set_results = '%s'",
                            (const char *) cs_name);

  return mysql_real_query(mysql, query_buffer, (ulong)query_length);
}

/**
  Rewrite statement, enclosing DEFINER clause in version-specific comment.

  This function parses any CREATE statement and encloses DEFINER-clause in
  version-specific comment:
    input query:     CREATE DEFINER=a@b FUNCTION ...
    rewritten query: CREATE * / / *!50020 DEFINER=a@b * / / *!50003 FUNCTION ...

  @note This function will go away when WL#3995 is implemented.

  @param[in] stmt_str                 CREATE statement string.
  @param[in] stmt_length              Length of the stmt_str.
  @param[in] definer_version_str      Minimal MySQL version number when
                                      DEFINER clause is supported in the
                                      given statement.
  @param[in] definer_version_length   Length of definer_version_str.
  @param[in] stmt_version_str         Minimal MySQL version number when the
                                      given statement is supported.
  @param[in] stmt_version_length      Length of stmt_version_str.
  @param[in] keyword_str              Keyword to look for after CREATE.
  @param[in] keyword_length           Length of keyword_str.

  @return pointer to the new allocated query string.
*/

static char *cover_definer_clause(const char *stmt_str,
                                  size_t stmt_length,
                                  const char *definer_version_str,
                                  size_t definer_version_length,
                                  const char *stmt_version_str,
                                  size_t stmt_version_length,
                                  const char *keyword_str,
                                  size_t keyword_length)
{
  char *definer_begin= my_case_str(stmt_str, stmt_length,
                                   C_STRING_WITH_LEN(" DEFINER"));
  char *definer_end= NULL;

  char *query_str= NULL;
  char *query_ptr;
  LEX_CSTRING comment= { C_STRING_WITH_LEN("*/ /*!") };

  if (!definer_begin)
    return NULL;

  definer_end= my_case_str(definer_begin, strlen(definer_begin),
                           keyword_str, keyword_length);

  if (!definer_end)
    return NULL;

  /*
    Allocate memory for new query string: original string
    from SHOW statement and version-specific comments.
  */
  query_str= alloc_query_str(stmt_length + 23);

  query_ptr= my_stpncpy(query_str, stmt_str, definer_begin - stmt_str);
  query_ptr= my_stpncpy(query_ptr, comment.str, comment.length + 1);
  query_ptr= my_stpncpy(query_ptr, definer_version_str, definer_version_length);
  query_ptr= my_stpncpy(query_ptr, definer_begin, definer_end - definer_begin);
  query_ptr= my_stpncpy(query_ptr, comment.str, comment.length + 1);
  query_ptr= my_stpncpy(query_ptr, stmt_version_str, stmt_version_length);
  query_ptr= strxmov(query_ptr, definer_end, NullS);

  return query_str;
}

/*
  Open a new .sql file to dump the table or view into

  SYNOPSIS
    open_sql_file_for_table
    name      name of the table or view
    flags     flags (as per "man 2 open")

  RETURN VALUES
    0        Failed to open file
    > 0      Handle of the open file
*/
static FILE* open_sql_file_for_table(const char* table, int flags)
{
  FILE* res;
  char filename[FN_REFLEN], tmp_path[FN_REFLEN];
  /*
    We need to reset processed compression dictionaries container
    each time a new SQL file is created (for --tab option).
  */
  my_hash_reset(&processed_compression_dictionaries);
  convert_dirname(tmp_path,path,NullS);
  res= my_fopen(fn_format(filename, table, tmp_path, ".sql", 4),
                flags, MYF(MY_WME));
  return res;
}


static void free_resources()
{
  if (md_result_file && md_result_file != stdout)
    my_fclose(md_result_file, MYF(0));
  my_free(opt_password);
  if (my_hash_inited(&ignore_table))
    my_hash_free(&ignore_table);
  if (my_hash_inited(&processed_compression_dictionaries))
    my_hash_free(&processed_compression_dictionaries);
  if (insert_pat_inited)
    dynstr_free(&insert_pat);
  if (defaults_argv)
    free_defaults(defaults_argv);
  if (opt_ignore_error)
    my_free(opt_ignore_error);
  delete_dynamic(&ignore_error);
  if (gtid_executed_buffer_inited)
    dynstr_free(&gtid_executed_buffer);
  my_end(my_end_arg);
}

/**
  Parse the list of error numbers to be ignored and store into a dynamic
  array.

  @return Operation status
      @retval 0    Success
      @retval >0   Failure
*/
static
int parse_ignore_error()
{
  const char *search= ",";
  char *token;
  uint my_err;

  DBUG_ENTER("parse_ignore_error");

  if (my_init_dynamic_array(&ignore_error,
                           PSI_NOT_INSTRUMENTED,
                           sizeof(uint), NULL, 12, 12))
    goto error;

  token= strtok(opt_ignore_error, search);

  while (token != NULL)
  {
    my_err= atoi(token);
    // filter out 0s, if any
    if (my_err != 0)
    {
      if (insert_dynamic(&ignore_error, &my_err))
        goto error;
    }
    token= strtok(NULL, search);
  }
  DBUG_RETURN(0);

error:
  DBUG_RETURN(EX_EOM);
}

/**
  Check if the last error should be ignored.
      @retval 1     yes
              0     no
*/
static my_bool do_ignore_error()
{
  uint i, last_errno, *my_err;
  my_bool found= 0;

  DBUG_ENTER("do_ignore_error");

  last_errno= mysql_errno(mysql);

  if (last_errno == 0)
    goto done;

  for (i= 0; i < ignore_error.elements; i++)
  {
    my_err= dynamic_element(&ignore_error, i, uint *);
    if (last_errno == *my_err)
    {
      found= 1;
      break;
    }
  }
done:
  DBUG_RETURN(found);
}

static void maybe_exit(int error)
{
  if (!first_error)
    first_error= error;

  /*
    Return if --force is used; else return only if the
    last error number is in the list of error numbers
    specified using --ignore-error option.
  */
  if (opt_force || (opt_ignore_error && do_ignore_error()))
    return;
  if (mysql)
    mysql_close(mysql);
  free_resources();
  exit(error);
}


/*
  db_connect -- connects to the host and selects DB.
*/

static int connect_to_db(char *host, char *user,char *passwd)
{
  char buff[20+FN_REFLEN];
  DBUG_ENTER("connect_to_db");

  verbose_msg("-- Connecting to %s...\n", host ? host : "localhost");
  mysql_init(&mysql_connection);
  if (opt_compress)
    mysql_options(&mysql_connection,MYSQL_OPT_COMPRESS,NullS);
  SSL_SET_OPTIONS(&mysql_connection);
  if (opt_protocol)
    mysql_options(&mysql_connection,MYSQL_OPT_PROTOCOL,(char*)&opt_protocol);
  if (opt_bind_addr)
    mysql_options(&mysql_connection,MYSQL_OPT_BIND,opt_bind_addr);
#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  if (shared_memory_base_name)
    mysql_options(&mysql_connection,MYSQL_SHARED_MEMORY_BASE_NAME,shared_memory_base_name);
#endif
  mysql_options(&mysql_connection, MYSQL_SET_CHARSET_NAME, default_charset);

  if (opt_plugin_dir && *opt_plugin_dir)
    mysql_options(&mysql_connection, MYSQL_PLUGIN_DIR, opt_plugin_dir);

  if (opt_default_auth && *opt_default_auth)
    mysql_options(&mysql_connection, MYSQL_DEFAULT_AUTH, opt_default_auth);

  if (using_opt_enable_cleartext_plugin)
    mysql_options(&mysql_connection, MYSQL_ENABLE_CLEARTEXT_PLUGIN,
                  (char *) &opt_enable_cleartext_plugin);

  mysql_options(&mysql_connection, MYSQL_OPT_CONNECT_ATTR_RESET, 0);
  mysql_options4(&mysql_connection, MYSQL_OPT_CONNECT_ATTR_ADD,
                 "program_name", "mysqldump");

  set_server_public_key(&mysql_connection);
  set_get_server_public_key_option(&mysql_connection);

  if (!(mysql= mysql_real_connect(&mysql_connection,host,user,passwd,
                                  NULL,opt_mysql_port,opt_mysql_unix_port,
                                  0)))
  {
    DB_error(&mysql_connection, "when trying to connect");
    DBUG_RETURN(1);
  }
  if ((mysql_get_server_version(&mysql_connection) < 40100) ||
      (opt_compatible_mode & 3))
  {
    /* Don't dump SET NAMES with a pre-4.1 server (bug#7997).  */
    opt_set_charset= 0;

    /* Don't switch charsets for 4.1 and earlier.  (bug#34192). */
    server_supports_switching_charsets= FALSE;
  } 
  /*
    As we're going to set SQL_MODE, it would be lost on reconnect, so we
    cannot reconnect.
  */
  mysql->reconnect= 0;
  my_snprintf(buff, sizeof(buff), "/*!40100 SET @@SQL_MODE='%s' */",
              compatible_mode_normal_str);
  if (mysql_query_with_error_report(mysql, 0, buff))
    DBUG_RETURN(1);
  /*
    set time_zone to UTC to allow dumping date types between servers with
    different time zone settings
  */
  if (opt_tz_utc)
  {
    my_snprintf(buff, sizeof(buff), "/*!40103 SET TIME_ZONE='+00:00' */");
    if (mysql_query_with_error_report(mysql, 0, buff))
      DBUG_RETURN(1);
  }
  DBUG_RETURN(0);
} /* connect_to_db */


/*
** dbDisconnect -- disconnects from the host.
*/
static void dbDisconnect(char *host)
{
  verbose_msg("-- Disconnecting from %s...\n", host ? host : "localhost");
  mysql_close(mysql);
} /* dbDisconnect */


static void unescape(FILE *file,char *pos, size_t length)
{
  char *tmp;
  DBUG_ENTER("unescape");
  if (!(tmp=(char*) my_malloc(PSI_NOT_INSTRUMENTED,
                              length*2+1, MYF(MY_WME))))
    die(EX_MYSQLERR, "Couldn't allocate memory");

  mysql_real_escape_string_quote(&mysql_connection, tmp, pos, (ulong)length, '\'');
  fputc('\'', file);
  fputs(tmp, file);
  fputc('\'', file);
  check_io(file);
  my_free(tmp);
  DBUG_VOID_RETURN;
} /* unescape */


static my_bool test_if_special_chars(const char *str)
{
  for ( ; *str ; str++)
    if (!my_isvar(charset_info,*str) && *str != '$')
      return 1;
  return 0;
} /* test_if_special_chars */



/*
  quote_name(name, buff, force)

  Quotes char string, taking into account compatible mode

  Args

  name                 Unquoted string containing that which will be quoted
  buff                 The buffer that contains the quoted value, also returned
  force                Flag to make it ignore 'test_if_special_chars'

  Returns

  buff                 quoted string

*/
static char *quote_name(const char *name, char *buff, my_bool force)
{
  char *to= buff;
  char qtype= (opt_compatible_mode & MASK_ANSI_QUOTES) ? '\"' : '`';

  if (!force && !opt_quoted && !test_if_special_chars(name))
    return (char*) name;
  *to++= qtype;
  while (*name)
  {
    if (*name == qtype)
      *to++= qtype;
    *to++= *name++;
  }
  to[0]= qtype;
  to[1]= 0;
  return buff;
} /* quote_name */

/**
  Unquotes char string, taking into account compatible mode

  @param opt_quoted_name   Optionally quoted string
  @param buff              The buffer that will contain the unquoted value,
                           may be returned

  @return Pointer to unquoted string (either original opt_quoted_name or
          buff).
*/
static char *unquote_name(const char *opt_quoted_name, char *buff)
{
  char *to= buff;
  const char qtype= (opt_compatible_mode & MASK_ANSI_QUOTES) ? '\"' : '`';

  if (!opt_quoted)
    return (char*)opt_quoted_name;
  if (*opt_quoted_name != qtype)
  {
    assert(strchr(opt_quoted_name, qtype) == 0);
    return (char*)opt_quoted_name;
  }

  ++opt_quoted_name;
  while (*opt_quoted_name)
  {
    if (*opt_quoted_name == qtype)
    {
      ++opt_quoted_name;
      if (*opt_quoted_name == qtype)
        *to++= qtype;
      else
      {
        assert(*opt_quoted_name == '\0');
      }
    }
    else
    {
      *to++= *opt_quoted_name++;
    }
  }
  to[0]= 0;
  return buff;
} /* unquote_name */


/*
  Quote a table name so it can be used in "SHOW TABLES LIKE <tabname>"

  SYNOPSIS
    quote_for_like()
    name     name of the table
    buff     quoted name of the table

  DESCRIPTION
    Quote \, _, ' and % characters

    Note: Because MySQL uses the C escape syntax in strings
    (for example, '\n' to represent newline), you must double
    any '\' that you use in your LIKE  strings. For example, to
    search for '\n', specify it as '\\n'. To search for '\', specify
    it as '\\\\' (the backslashes are stripped once by the parser
    and another time when the pattern match is done, leaving a
    single backslash to be matched).

    Example: "t\1" => "t\\\\1"

*/
static char *quote_for_like(const char *name, char *buff)
{
  char *to= buff;
  *to++= '\'';
  while (*name)
  {
    if (*name == '\\')
    {
      *to++='\\';
      *to++='\\';
      *to++='\\';
    }
    else if (*name == '\'' || *name == '_'  || *name == '%')
      *to++= '\\';
    *to++= *name++;
  }
  to[0]= '\'';
  to[1]= 0;
  return buff;
}


/**
  Quote and print a string.

  @param xml_file          - Output file.
  @param str               - String to print.
  @param len               - Its length.
  @param is_attribute_name - A check for attribute name or value.

  @description
    Quote '<' '>' '&' '\"' chars and print a string to the xml_file.
*/

static void print_quoted_xml(FILE *xml_file, const char *str, size_t len,
                             my_bool is_attribute_name)
{
  const char *end;

  for (end= str + len; str != end; str++)
  {
    switch (*str) {
    case '<':
      fputs("&lt;", xml_file);
      break;
    case '>':
      fputs("&gt;", xml_file);
      break;
    case '&':
      fputs("&amp;", xml_file);
      break;
    case '\"':
      fputs("&quot;", xml_file);
      break;
    case ' ':
      /* Attribute names cannot contain spaces. */
      if (is_attribute_name)
      {
        fputs("_", xml_file);
        break;
      }
      /* fall through */
    default:
      fputc(*str, xml_file);
      break;
    }
  }
  check_io(xml_file);
}


/*
  Print xml tag. Optionally add attribute(s).

  SYNOPSIS
    print_xml_tag(xml_file, sbeg, send, tag_name, first_attribute_name, 
                    ..., attribute_name_n, attribute_value_n, NullS)
    xml_file              - output file
    sbeg                  - line beginning
    line_end              - line ending
    tag_name              - XML tag name.
    first_attribute_name  - tag and first attribute
    first_attribute_value - (Implied) value of first attribute
    attribute_name_n      - attribute n
    attribute_value_n     - value of attribute n

  DESCRIPTION
    Print XML tag with any number of attribute="value" pairs to the xml_file.

    Format is:
      sbeg<tag_name first_attribute_name="first_attribute_value" ... 
      attribute_name_n="attribute_value_n">send
  NOTE
    Additional arguments must be present in attribute/value pairs.
    The last argument should be the null character pointer.
    All attribute_value arguments MUST be NULL terminated strings.
    All attribute_value arguments will be quoted before output.
*/

static void print_xml_tag(FILE * xml_file, const char* sbeg,
                          const char* line_end, 
                          const char* tag_name, 
                          const char* first_attribute_name, ...)
{
  va_list arg_list;
  const char *attribute_name, *attribute_value;

  fputs(sbeg, xml_file);
  fputc('<', xml_file);
  fputs(tag_name, xml_file);  

  va_start(arg_list, first_attribute_name);
  attribute_name= first_attribute_name;
  while (attribute_name != NullS)
  {
    attribute_value= va_arg(arg_list, char *);
    assert(attribute_value != NullS);

    fputc(' ', xml_file);
    fputs(attribute_name, xml_file);    
    fputc('\"', xml_file);
    
    print_quoted_xml(xml_file, attribute_value, strlen(attribute_value), 0);
    fputc('\"', xml_file);

    attribute_name= va_arg(arg_list, char *);
  }
  va_end(arg_list);

  fputc('>', xml_file);
  fputs(line_end, xml_file);
  check_io(xml_file);
}


/*
  Print xml tag with for a field that is null

  SYNOPSIS
    print_xml_null_tag()
    xml_file    - output file
    sbeg        - line beginning
    stag_atr    - tag and attribute
    sval        - value of attribute
    line_end        - line ending

  DESCRIPTION
    Print tag with one attribute to the xml_file. Format is:
      <stag_atr="sval" xsi:nil="true"/>
  NOTE
    sval MUST be a NULL terminated string.
    sval string will be qouted before output.
*/

static void print_xml_null_tag(FILE * xml_file, const char* sbeg,
                               const char* stag_atr, const char* sval,
                               const char* line_end)
{
  fputs(sbeg, xml_file);
  fputs("<", xml_file);
  fputs(stag_atr, xml_file);
  fputs("\"", xml_file);
  print_quoted_xml(xml_file, sval, strlen(sval), 0);
  fputs("\" xsi:nil=\"true\" />", xml_file);
  fputs(line_end, xml_file);
  check_io(xml_file);
}


/**
  Print xml CDATA section.

  @param xml_file    - output file
  @param str         - string to print
  @param len         - length of the string

  @note
    This function also takes care of the presence of '[[>'
    string in the str. If found, the CDATA section is broken
    into two CDATA sections, <![CDATA[]]]]> and <![CDATA[>]].
*/

static void print_xml_cdata(FILE *xml_file, const char *str, ulong len)
{
  const char *end;

  fputs("<![CDATA[\n", xml_file);
  for (end= str + len; str != end; str++)
  {
    switch(*str) {
    case ']':
      if ((*(str + 1) == ']') && (*(str + 2) =='>'))
      {
        fputs("]]]]><![CDATA[>", xml_file);
        str += 2;
        continue;
      }
      /* fall through */
    default:
      fputc(*str, xml_file);
      break;
    }
  }
  fputs("\n]]>\n", xml_file);
  check_io(xml_file);
}


/*
  Print xml tag with many attributes.

  SYNOPSIS
    print_xml_row()
    xml_file    - output file
    row_name    - xml tag name
    tableRes    - query result
    row         - result row
    str_create  - create statement header string

  DESCRIPTION
    Print tag with many attribute to the xml_file. Format is:
      \t\t<row_name Atr1="Val1" Atr2="Val2"... />
  NOTE
    All atributes and values will be quoted before output.
*/

static void print_xml_row(FILE *xml_file, const char *row_name,
                          MYSQL_RES *tableRes, MYSQL_ROW *row,
                          const char *str_create)
{
  uint i;
  char *create_stmt_ptr= NULL;
  ulong create_stmt_len= 0;
  MYSQL_FIELD *field;
  ulong *lengths= mysql_fetch_lengths(tableRes);

  fprintf(xml_file, "\t\t<%s", row_name);
  check_io(xml_file);
  mysql_field_seek(tableRes, 0);
  for (i= 0; (field= mysql_fetch_field(tableRes)); i++)
  {
    if ((*row)[i])
    {
      /* For 'create' statements, dump using CDATA. */
      if ((str_create) && (strcmp(str_create, field->name) == 0))
      {
        create_stmt_ptr= (*row)[i];
        create_stmt_len= lengths[i];
      }
      else
      {
        fputc(' ', xml_file);
        print_quoted_xml(xml_file, field->name, field->name_length, 1);
        fputs("=\"", xml_file);
        print_quoted_xml(xml_file, (*row)[i], lengths[i], 0);
        fputc('"', xml_file);
        check_io(xml_file);
      }
    }
  }

  if (create_stmt_len)
  {
    fputs(">\n", xml_file);
    print_xml_cdata(xml_file, create_stmt_ptr, create_stmt_len);
    fprintf(xml_file, "\t\t</%s>\n", row_name);
  }
  else
    fputs(" />\n", xml_file);

  check_io(xml_file);
}


/**
  Print xml comments.

  @param xml_file       - output file
  @param len            - length of comment message
  @param comment_string - comment message

  @description
    Print the comment message in the format:
      "<!-- \n comment string  \n -->\n"

  @note
    Any occurrence of continuous hyphens will be
    squeezed to a single hyphen.
*/

static void print_xml_comment(FILE *xml_file, size_t len,
                              const char *comment_string)
{
  const char* end;

  fputs("<!-- ", xml_file);

  for (end= comment_string + len; comment_string != end; comment_string++)
  {
    /*
      The string "--" (double-hyphen) MUST NOT occur within xml comments.
    */
    switch (*comment_string) {
    case '-':
      if (*(comment_string + 1) == '-')         /* Only one hyphen allowed. */
        break;
      // Fall through.
    default:
      fputc(*comment_string, xml_file);
      break;
    }
  }
  fputs(" -->\n", xml_file);
  check_io(xml_file);
}



/* A common printing function for xml and non-xml modes. */

static void print_comment(FILE *sql_file, my_bool is_error, const char *format,
                          ...)
{
  static char comment_buff[COMMENT_LENGTH];
  va_list args;

  /* If its an error message, print it ignoring opt_comments. */
  if (!is_error && !opt_comments)
    return;

  va_start(args, format);
  my_vsnprintf(comment_buff, COMMENT_LENGTH, format, args);
  va_end(args);

  if (!opt_xml)
  {
    fputs(comment_buff, sql_file);
    check_io(sql_file);
    return;
  }

  print_xml_comment(sql_file, strlen(comment_buff), comment_buff);
}

/**
  @brief Accepts object names and prefixes them with "-- " wherever
         end-of-line character ('\n') is found.

  @param[in]  object_name   object name list (concatenated string)
  @param[out] freemem       should buffer be released after usage

  @return
    @retval                 pointer to a string with prefixed objects
*/
static char const* fix_identifier_with_newline(char const* object_name, my_bool* freemem)
{
  const size_t PREFIX_LENGTH= 3; // strlen ("-- ")

  // static buffer for replacement procedure
  static char storage[NAME_LEN + 1];
  static char* buffer= storage;
  static size_t buffer_size= sizeof(storage) - 1;
  size_t index= 0;
  size_t required_size= 0;

  // we presume memory allocation won't be needed
  *freemem= FALSE;

  // traverse and reformat objects
  while (object_name && *object_name)
  {
    ++required_size;
    if (*object_name == '\n')
      required_size+= PREFIX_LENGTH;

    // do we need dynamic (re)allocation
    if (required_size > buffer_size)
    {
      // new alloc size increased in COMMENT_LENGTH multiple
      buffer_size= COMMENT_LENGTH * (1 + required_size/COMMENT_LENGTH);

      // is our buffer already dynamically allocated
      if (*freemem)
      {
        // just realloc
        buffer= (char*)my_realloc(PSI_NOT_INSTRUMENTED, buffer, buffer_size + 1,
                                  MYF(MY_WME));
        if (!buffer)
          exit(1);
      }
      else
      {
        // dynamic allocation + copy from static buffer
        buffer= (char*)my_malloc(PSI_NOT_INSTRUMENTED, buffer_size + 1,
                                 MYF(MY_WME));
        if (!buffer)
          exit(1);

        strncpy(buffer, storage, index);
        *freemem= TRUE;
      }
    }

    // copy a character
    buffer[index]= *object_name;
    ++index;

    // prefix new lines with double dash
    if (*object_name == '\n')
    {
      strcpy(buffer + index, "-- ");
      index += PREFIX_LENGTH;
    }

    ++object_name;
  }

  // don't forget null termination
  buffer[index]= '\0';
  return buffer;
}


/*
 create_delimiter
 Generate a new (null-terminated) string that does not exist in  query 
 and is therefore suitable for use as a query delimiter.  Store this
 delimiter in  delimiter_buff .
 
 This is quite simple in that it doesn't even try to parse statements as an
 interpreter would.  It merely returns a string that is not in the query, which
 is much more than adequate for constructing a delimiter.

 RETURN
   ptr to the delimiter  on Success
   NULL                  on Failure
*/
static char *create_delimiter(char *query, char *delimiter_buff, 
                              int delimiter_max_size) 
{
  int proposed_length;
  char *presence;

  delimiter_buff[0]= ';';  /* start with one semicolon, and */

  for (proposed_length= 2; proposed_length < delimiter_max_size; 
      delimiter_max_size++) {

    delimiter_buff[proposed_length-1]= ';';  /* add semicolons, until */
    delimiter_buff[proposed_length]= '\0';

    presence = strstr(query, delimiter_buff);
    if (presence == NULL) { /* the proposed delimiter is not in the query. */
       return delimiter_buff;
    }

  }
  return NULL;  /* but if we run out of space, return nothing at all. */
}


/*
  dump_events_for_db
  -- retrieves list of events for a given db, and prints out
  the CREATE EVENT statement into the output (the dump).

  RETURN
    0  Success
    1  Error
*/
static uint dump_events_for_db(char *db)
{
  char       query_buff[QUERY_LENGTH];
  char       db_name_buff[NAME_LEN*2+3], name_buff[NAME_LEN*2+3];
  char       *event_name;
  char       delimiter[QUERY_LENGTH];
  FILE       *sql_file= md_result_file;
  MYSQL_RES  *event_res, *event_list_res;
  MYSQL_ROW  row, event_list_row;

  char       db_cl_name[MY_CS_NAME_SIZE];
  int        db_cl_altered= FALSE;
  my_bool    freemem= FALSE;
  char const *text= fix_identifier_with_newline(db, &freemem);

  DBUG_ENTER("dump_events_for_db");
  DBUG_PRINT("enter", ("db: '%s'", db));

  mysql_real_escape_string_quote(mysql, db_name_buff,
                                 db, (ulong)strlen(db), '\'');
  /* nice comments */
  print_comment(sql_file, 0,
                "\n--\n-- Dumping events for database '%s'\n--\n",
                text);
  if (freemem)
    my_free((void*)text);

  /*
    not using "mysql_query_with_error_report" because we may have not
    enough privileges to lock mysql.events.
  */
  if (lock_tables)
    mysql_query(mysql, "LOCK TABLES mysql.event READ");

  if (mysql_query_with_error_report(mysql, &event_list_res, "show events"))
    DBUG_RETURN(0);

  strcpy(delimiter, ";");
  if (mysql_num_rows(event_list_res) > 0)
  {
    if (opt_xml)
      fputs("\t<events>\n", sql_file);
    else
    {
      fprintf(sql_file, "/*!50106 SET @save_time_zone= @@TIME_ZONE */ ;\n");

      /* Get database collation. */

      if (fetch_db_collation(db_name_buff, db_cl_name, sizeof (db_cl_name)))
        DBUG_RETURN(1);
    }

    if (switch_character_set_results(mysql, "binary"))
      DBUG_RETURN(1);

    while ((event_list_row= mysql_fetch_row(event_list_res)) != NULL)
    {
      event_name= quote_name(event_list_row[1], name_buff, 0);
      DBUG_PRINT("info", ("retrieving CREATE EVENT for %s", name_buff));
      my_snprintf(query_buff, sizeof(query_buff), "SHOW CREATE EVENT %s", 
          event_name);

      if (mysql_query_with_error_report(mysql, &event_res, query_buff))
        DBUG_RETURN(1);

      while ((row= mysql_fetch_row(event_res)) != NULL)
      {
        if (opt_xml)
        {
          print_xml_row(sql_file, "event", event_res, &row,
                        "Create Event");
          continue;
        }

        /*
          if the user has EXECUTE privilege he can see event names, but not the
          event body!
        */
        if (strlen(row[3]) != 0)
        {
          char *query_str;

          if (opt_drop)
            fprintf(sql_file, "/*!50106 DROP EVENT IF EXISTS %s */%s\n", 
                event_name, delimiter);

          if (create_delimiter(row[3], delimiter, sizeof(delimiter)) == NULL)
          {
            fprintf(stderr, "%s: Warning: Can't create delimiter for event '%s'\n",
                    my_progname, event_name);
            DBUG_RETURN(1);
          }

          fprintf(sql_file, "DELIMITER %s\n", delimiter);

          if (mysql_num_fields(event_res) >= 7)
          {
            if (switch_db_collation(sql_file, db_name_buff, delimiter,
                                    db_cl_name, row[6], &db_cl_altered))
            {
              DBUG_RETURN(1);
            }

            switch_cs_variables(sql_file, delimiter,
                                row[4],   /* character_set_client */
                                row[4],   /* character_set_results */
                                row[5]);  /* collation_connection */
          }
          else
          {
            /*
              mysqldump is being run against the server, that does not
              provide character set information in SHOW CREATE
              statements.

              NOTE: the dump may be incorrect, since character set
              information is required in order to restore event properly.
            */

            fprintf(sql_file,
                    "--\n"
                    "-- WARNING: old server version. "
                      "The following dump may be incomplete.\n"
                    "--\n");
          }
          remove_sql_mode(row[1], C_STRING_WITH_LEN("NO_AUTO_CREATE_USER"));
          switch_sql_mode(sql_file, delimiter, row[1]);

          switch_time_zone(sql_file, delimiter, row[2]);

          query_str= cover_definer_clause(row[3], strlen(row[3]),
                                          C_STRING_WITH_LEN("50117"),
                                          C_STRING_WITH_LEN("50106"),
                                          C_STRING_WITH_LEN(" EVENT"));

          fprintf(sql_file,
                  "/*!50106 %s */ %s\n",
                  (const char *) (query_str != NULL ? query_str : row[3]),
                  (const char *) delimiter);

          my_free(query_str);
          restore_time_zone(sql_file, delimiter);
          restore_sql_mode(sql_file, delimiter);

          if (mysql_num_fields(event_res) >= 7)
          {
            restore_cs_variables(sql_file, delimiter);

            if (db_cl_altered)
            {
              if (restore_db_collation(sql_file, db_name_buff, delimiter,
                                       db_cl_name))
                DBUG_RETURN(1);
            }
          }
        }
      } /* end of event printing */
      mysql_free_result(event_res);

    } /* end of list of events */
    if (opt_xml)
    {
      fputs("\t</events>\n", sql_file);
      check_io(sql_file);
    }
    else
    {
      fprintf(sql_file, "DELIMITER ;\n");
      fprintf(sql_file, "/*!50106 SET TIME_ZONE= @save_time_zone */ ;\n");
    }

    if (switch_character_set_results(mysql, default_charset))
      DBUG_RETURN(1);
  }
  mysql_free_result(event_list_res);

  if (lock_tables)
    (void) mysql_query_with_error_report(mysql, 0, "UNLOCK TABLES");
  DBUG_RETURN(0);
}


/*
  Print hex value for blob data.

  SYNOPSIS
    print_blob_as_hex()
    output_file         - output file
    str                 - string to print
    len                 - its length

  DESCRIPTION
    Print hex value for blob data.
*/

static void print_blob_as_hex(FILE *output_file, const char *str, ulong len)
{
    /* sakaik got the idea to to provide blob's in hex notation. */
    const char *ptr= str, *end= ptr + len;
    for (; ptr < end ; ptr++)
      fprintf(output_file, "%02X", *((uchar *)ptr));
    check_io(output_file);
}

/*
  dump_routines_for_db
  -- retrieves list of routines for a given db, and prints out
  the CREATE PROCEDURE definition into the output (the dump).

  This function has logic to print the appropriate syntax depending on whether
  this is a procedure or functions

  RETURN
    0  Success
    1  Error
*/

static uint dump_routines_for_db(char *db)
{
  char       query_buff[QUERY_LENGTH];
  const char *routine_type[]= {"FUNCTION", "PROCEDURE"};
  char       db_name_buff[NAME_LEN*2+3], name_buff[NAME_LEN*2+3];
  char       *routine_name;
  int        i;
  FILE       *sql_file= md_result_file;
  MYSQL_RES  *routine_res, *routine_list_res;
  MYSQL_ROW  row, routine_list_row;

  char       db_cl_name[MY_CS_NAME_SIZE];
  int        db_cl_altered= FALSE;
  my_bool    freemem= FALSE;
  char const *text= fix_identifier_with_newline(db, &freemem);

  DBUG_ENTER("dump_routines_for_db");
  DBUG_PRINT("enter", ("db: '%s'", db));

  mysql_real_escape_string_quote(mysql, db_name_buff,
                                 db, (ulong)strlen(db), '\'');
  /* nice comments */
  print_comment(sql_file, 0,
                "\n--\n-- Dumping routines for database '%s'\n--\n",
                text);

  if (freemem)
    my_free((void*)text);

  /*
    not using "mysql_query_with_error_report" because we may have not
    enough privileges to lock mysql.proc.
  */
  if (lock_tables)
    mysql_query(mysql, "LOCK TABLES mysql.proc READ");

  /* Get database collation. */

  if (fetch_db_collation(db_name_buff, db_cl_name, sizeof (db_cl_name)))
    DBUG_RETURN(1);

  if (switch_character_set_results(mysql, "binary"))
    DBUG_RETURN(1);

  if (opt_xml)
    fputs("\t<routines>\n", sql_file);

  /* 0, retrieve and dump functions, 1, procedures */
  for (i= 0; i <= 1; i++)
  {
    my_snprintf(query_buff, sizeof(query_buff),
                "SHOW %s STATUS WHERE Db = '%s'",
                routine_type[i], db_name_buff);

    if (mysql_query_with_error_report(mysql, &routine_list_res, query_buff))
      DBUG_RETURN(1);

    if (mysql_num_rows(routine_list_res))
    {

      while ((routine_list_row= mysql_fetch_row(routine_list_res)))
      {
        routine_name= quote_name(routine_list_row[1], name_buff, 0);
        DBUG_PRINT("info", ("retrieving CREATE %s for %s", routine_type[i],
                            name_buff));
        my_snprintf(query_buff, sizeof(query_buff), "SHOW CREATE %s %s",
                    routine_type[i], routine_name);

        if (mysql_query_with_error_report(mysql, &routine_res, query_buff))
          DBUG_RETURN(1);

        while ((row= mysql_fetch_row(routine_res)))
        {
          /*
            if the user has EXECUTE privilege he see routine names, but NOT the
            routine body of other routines that are not the creator of!
          */
          DBUG_PRINT("info",("length of body for %s row[2] '%s' is %zu",
                             routine_name, row[2] ? row[2] : "(null)",
                             row[2] ? strlen(row[2]) : 0));
          if (row[2] == NULL)
          {
            my_bool freemem= FALSE;
            char const* text= fix_identifier_with_newline(current_user, &freemem);

            print_comment(sql_file, 1, "\n-- insufficient privileges to %s\n",
                          query_buff);
            print_comment(sql_file, 1,
                          "-- does %s have permissions on mysql.proc?\n\n",
                          text);
            if (freemem)
              my_free((void*)text);

            maybe_die(EX_MYSQLERR,"%s has insufficent privileges to %s!", current_user, query_buff);
          }
          else if (strlen(row[2]))
          {
            if (opt_xml)
            {
              if (i)                            // Procedures.
                print_xml_row(sql_file, "routine", routine_res, &row,
                              "Create Procedure");
              else                              // Functions.
                print_xml_row(sql_file, "routine", routine_res, &row,
                              "Create Function");
              continue;
            }
            if (opt_drop)
              fprintf(sql_file, "/*!50003 DROP %s IF EXISTS %s */;\n",
                      routine_type[i], routine_name);

            if (mysql_num_fields(routine_res) >= 6)
            {
              if (switch_db_collation(sql_file, db_name_buff, ";",
                                      db_cl_name, row[5], &db_cl_altered))
              {
                DBUG_RETURN(1);
              }

              switch_cs_variables(sql_file, ";",
                                  row[3],   /* character_set_client */
                                  row[3],   /* character_set_results */
                                  row[4]);  /* collation_connection */
            }
            else
            {
              /*
                mysqldump is being run against the server, that does not
                provide character set information in SHOW CREATE
                statements.

                NOTE: the dump may be incorrect, since character set
                information is required in order to restore stored
                procedure/function properly.
              */

              fprintf(sql_file,
                      "--\n"
                      "-- WARNING: old server version. "
                        "The following dump may be incomplete.\n"
                      "--\n");
            }

            remove_sql_mode(row[1], C_STRING_WITH_LEN("NO_AUTO_CREATE_USER"));
            switch_sql_mode(sql_file, ";", row[1]);

            fprintf(sql_file,
                    "DELIMITER ;;\n"
                    "%s ;;\n"
                    "DELIMITER ;\n",
                    (const char *) row[2]);

            restore_sql_mode(sql_file, ";");

            if (mysql_num_fields(routine_res) >= 6)
            {
              restore_cs_variables(sql_file, ";");

              if (db_cl_altered)
              {
                if (restore_db_collation(sql_file, db_name_buff, ";", db_cl_name))
                  DBUG_RETURN(1);
              }
            }

          }
        } /* end of routine printing */
        mysql_free_result(routine_res);

      } /* end of list of routines */
    }
    mysql_free_result(routine_list_res);
  } /* end of for i (0 .. 1)  */

  if (opt_xml)
  {
    fputs("\t</routines>\n", sql_file);
    check_io(sql_file);
  }

  if (switch_character_set_results(mysql, default_charset))
    DBUG_RETURN(1);

  if (lock_tables)
    (void) mysql_query_with_error_report(mysql, 0, "UNLOCK TABLES");
  DBUG_RETURN(0);
}

/* general_log or slow_log tables under mysql database */
static inline my_bool general_log_or_slow_log_tables(const char *db,
                                                     const char *table)
{
  return (!my_strcasecmp(charset_info, db, "mysql")) &&
          (!my_strcasecmp(charset_info, table, "general_log") ||
           !my_strcasecmp(charset_info, table, "slow_log"));
}

/*
 slave_master_info,slave_relay_log_info and gtid_executed tables under
 mysql database
*/
static inline my_bool replication_metadata_tables(const char *db,
                                                  const char *table)
{
  return (!my_strcasecmp(charset_info, db, "mysql")) &&
          (!my_strcasecmp(charset_info, table, "slave_master_info") ||
           !my_strcasecmp(charset_info, table, "slave_relay_log_info") ||
           !my_strcasecmp(charset_info, table, "gtid_executed"));
}

/*
  Find the first occurrence of a quoted identifier in a given string. Returns
  the pointer to the opening quote, and stores the pointer to the closing quote
  to the memory location pointed to by the 'end' argument,

  If no quoted identifiers are found, returns NULL (and the value pointed to by
  'end' is undefined in this case).
*/

static const char *parse_quoted_identifier(const char *str,
                                            const char **end)
{
  const char *from;
  const char *to;

  if (!(from= strchr(str, '`')))
    return NULL;

  to= from;

  while ((to= strchr(to + 1, '`'))) {
    /*
      Double backticks represent a backtick in identifier, rather than a quote
      character.
    */
    if (to[1] == '`')
    {
      to++;
      continue;
    }

    break;
  }

  if (to <= from + 1)
    return NULL;                                /* Empty identifier */

  *end= to;

  return from;
}

/*
  Parse the specified key definition string and check if the key contains an
  AUTO_INCREMENT column as the first key part. We only check for the first key
  part, because unlike MyISAM, InnoDB does not allow the AUTO_INCREMENT column
  as a secondary key column, i.e. the AUTO_INCREMENT column would not be
  considered indexed for such key specification.
*/
static my_bool contains_autoinc_column(const char *autoinc_column,
                                       ssize_t autoinc_column_len,
                                       const char *keydef,
                                       key_type_t type)
{
  const char *from, *to;
  uint idnum;

  assert(type != KEY_TYPE_NONE);

  if (autoinc_column == NULL)
    return FALSE;

  idnum= 0;

  /*
    There is only 1 iteration of the following loop for type == KEY_TYPE_PRIMARY
    and 2 iterations for type == KEY_TYPE_UNIQUE / KEY_TYPE_NON_UNIQUE.
  */
  while ((from= parse_quoted_identifier(keydef, &to)))
  {
    idnum++;

    /*
      Skip the check if it's the first identifier and we are processing a
      secondary key.
    */
    if ((type == KEY_TYPE_PRIMARY || idnum != 1) &&
        to - from - 1 == autoinc_column_len &&
        !strncmp(autoinc_column, from + 1, autoinc_column_len))
      return TRUE;

    /*
      Check only the first (for PRIMARY KEY) or the second (for secondary keys)
      quoted identifier.
    */
    if (idnum == 1 + MY_TEST(type != KEY_TYPE_PRIMARY))
      break;

    keydef= to + 1;
  }

  return FALSE;
}


/*
  Remove secondary/foreign key definitions from a given SHOW CREATE TABLE string
  and store them into a temporary list to be used later.

  SYNOPSIS
    skip_secondary_keys()
    create_str                SHOW CREATE TABLE output
    has_pk                    TRUE, if the table has PRIMARY KEY
                              (or UNIQUE key on non-nullable columns)


  DESCRIPTION

    Stores all lines starting with "KEY" or "UNIQUE KEY"
    into skipped_keys_list and removes them from the input string.
    Stores all CONSTRAINT/FOREIGN KEYS declarations into
    alter_constraints_list and removes them from the input string.
*/

static void skip_secondary_keys(char *create_str, my_bool has_pk)
{
  char *ptr, *strend;
  char *last_comma= NULL;
  my_bool pk_processed= FALSE;
  char *autoinc_column= NULL;
  ssize_t autoinc_column_len= 0;
  my_bool has_autoinc= FALSE;
  key_type_t type;
  my_bool keys_processed= FALSE;

  strend= create_str + strlen(create_str);

  ptr= create_str;
  while (*ptr && !keys_processed)
  {
    char *tmp, *orig_ptr, c;

    orig_ptr= ptr;
    /* Skip leading whitespace */
    while (*ptr && my_isspace(charset_info, *ptr))
      ptr++;

    /* Read the next line */
    for (tmp= ptr; *tmp != '\n' && *tmp != '\0'; tmp++);

    c= *tmp;
    *tmp= '\0'; /* so strstr() only processes the current line */

    if (!strncmp(ptr, "CONSTRAINT ", sizeof("CONSTRAINT ") - 1))
      type= KEY_TYPE_CONSTRAINT;
    else if (!strncmp(ptr, "UNIQUE KEY ", sizeof("UNIQUE KEY ") - 1))
      type= KEY_TYPE_UNIQUE;
    else if (!strncmp(ptr, "KEY ", sizeof("KEY ") - 1))
      type= KEY_TYPE_NON_UNIQUE;
    else if (!strncmp(ptr, "PRIMARY KEY ", sizeof("PRIMARY KEY ") - 1))
      type= KEY_TYPE_PRIMARY;
    else
      type= KEY_TYPE_NONE;

    has_autoinc= (type != KEY_TYPE_NONE)
      ? contains_autoinc_column(autoinc_column, autoinc_column_len, ptr, type)
      : FALSE;

    /* Is it a secondary index definition? */
    if (c == '\n' && !has_autoinc &&
        ((type == KEY_TYPE_UNIQUE && (pk_processed || !has_pk)) ||
         type == KEY_TYPE_NON_UNIQUE || type == KEY_TYPE_CONSTRAINT))
    {
      char *data, *end= tmp - 1;

      /* Remove the trailing comma */
      if (*end == ',')
        end--;
      data= my_strndup(PSI_NOT_INSTRUMENTED, ptr, end - ptr + 1, MYF(MY_FAE));

      if (type == KEY_TYPE_CONSTRAINT)
        alter_constraints_list= list_cons(data, alter_constraints_list);
      else
        skipped_keys_list= list_cons(data, skipped_keys_list);

      memmove(orig_ptr, tmp + 1, strend - tmp);
      ptr= orig_ptr;
      strend-= tmp + 1 - ptr;

      /* Remove the comma on the previos line */
      if (last_comma != NULL)
      {
        *last_comma= ' ';
      }
    }
    else
    {
      char *end;

      if (last_comma != NULL && *ptr == ')')
      {
        keys_processed= TRUE;
      }
      else if (last_comma != NULL && !keys_processed)
      {
        /*
          It's not the last line of CREATE TABLE, so we have skipped a key
          definition. We have to restore the last removed comma.
        */
        *last_comma= ',';
      }

      /*
        If we are skipping a key which indexes an AUTO_INCREMENT column, it is
        safe to optimize all subsequent keys, i.e. we should not be checking for
        that column anymore.
      */
      if (type != KEY_TYPE_NONE && has_autoinc)
      {
          assert(autoinc_column != NULL);

          my_free(autoinc_column);
          autoinc_column= NULL;
      }

      if ((has_pk && type == KEY_TYPE_UNIQUE && !pk_processed) ||
          type == KEY_TYPE_PRIMARY)
        pk_processed= TRUE;

      if (strstr(ptr, "AUTO_INCREMENT") && *ptr == '`')
      {
        /*
          The first secondary key defined on this column later cannot be
          skipped, as CREATE TABLE would fail on import. Unless there is a
          PRIMARY KEY and it indexes that column.
        */
        for (end= ptr + 1;
             /* Skip double backticks as they are a part of identifier */
             *end != '\0' && (*end != '`' || end[1] == '`');
             end++)
          /* empty */;

        if (*end == '`' && end > ptr + 1)
        {
          assert(autoinc_column == NULL);

          autoinc_column_len= end - ptr - 1;
          autoinc_column= my_strndup(PSI_NOT_INSTRUMENTED, ptr + 1,
                                     autoinc_column_len, MYF(MY_FAE));
        }
      }

      *tmp= c;

      if (tmp[-1] == ',')
        last_comma= tmp - 1;
      ptr= (*tmp == '\0') ? tmp : tmp + 1;
    }
  }

  my_free(autoinc_column);
}

/**
  Removes some compressed columns extensions from the create table
  definition (a string produced by SHOW CREATE TABLE) depending on
  opt_compressed_columns and opt_compressed_columns_with_dictionaries flags.
  If opt_compressed_columns_with_dictionaries flags is true, in addition
  dictionaries list will be filled with referenced compression
  dictionaries.

  @param create_str     SHOW CREATE TABLE output
  @param dictionaries   the list of dictionary names found in the
                        create table definition
*/
static void skip_compressed_columns(char *create_str, LIST **dictionaries)
{
  static const char prefix[]=
    " /*!"
    STRINGIFY_ARG(FIRST_SUPPORTED_COMPRESSED_COLUMNS_VERSION)
    " COLUMN_FORMAT COMPRESSED";
  static const size_t prefix_length= sizeof(prefix) - 1;
  static const char suffix[]= " */";
  static const size_t suffix_length= sizeof(suffix) - 1;
  static const char dictionary_keyword[]=" WITH COMPRESSION_DICTIONARY ";
  static const size_t dictionary_keyword_length=
    sizeof(dictionary_keyword) - 1;

  char *ptr, *end_ptr, *prefix_ptr, *suffix_ptr, *dictionary_keyword_ptr;

  DBUG_ENTER("skip_compressed_columns");

  ptr= create_str;
  end_ptr= ptr + strlen(create_str);
  if (opt_compressed_columns_with_dictionaries && dictionaries != 0)
    *dictionaries= 0;

  while ((prefix_ptr= strstr(ptr, prefix)) != 0)
  {
    suffix_ptr= strstr(prefix_ptr + prefix_length, suffix);
    assert(suffix_ptr != 0);
    if (!opt_compressed_columns_with_dictionaries)
    {
      if (!opt_compressed_columns)
      {
        /* Strip out all compressed columns extensions. */
        memmove(prefix_ptr, suffix_ptr + suffix_length,
                end_ptr - (suffix_ptr + suffix_length) + 1);
        end_ptr-= suffix_ptr + suffix_length - prefix_ptr;
        ptr= prefix_ptr;
      }
      else
      {
        /* Strip out only compression dictionary references. */
        memmove(prefix_ptr + prefix_length, suffix_ptr,
          end_ptr - suffix_ptr + 1);
        end_ptr-= suffix_ptr - (prefix_ptr + prefix_length);
        ptr= prefix_ptr + prefix_length + suffix_length;
      }
    }
    else
    {
      /* Do not strip out anything. Leave full column definition as is. */
      if (dictionaries !=0 && prefix_ptr + prefix_length != suffix_ptr)
      {
        char *dictionary_name_ptr;
        size_t dictionary_name_length;
        char opt_quoted_buff[NAME_LEN * 2 + 3],
             unquoted_buff[NAME_LEN * 2 + 3];

        dictionary_keyword_ptr= strstr(prefix_ptr + prefix_length,
                                       dictionary_keyword);
        assert(dictionary_keyword_ptr < suffix_ptr);
        dictionary_name_length= suffix_ptr -
          (dictionary_keyword_ptr + dictionary_keyword_length);

        strncpy(opt_quoted_buff,
          dictionary_keyword_ptr + dictionary_keyword_length,
          dictionary_name_length);
        opt_quoted_buff[dictionary_name_length]= '\0';

        dictionary_name_ptr=
          my_strdup(PSI_NOT_INSTRUMENTED,
                    unquote_name(opt_quoted_buff, unquoted_buff), MYF(0));
        if (dictionary_name_ptr == 0)
          die(EX_MYSQLERR, "Couldn't allocate memory");

        list_push(*dictionaries, dictionary_name_ptr);
      }
      ptr= suffix_ptr + suffix_length;
    }
  }
  DBUG_VOID_RETURN;
}


/*
  Check if the table has a primary key defined either explicitly or
  implicitly (i.e. a unique key on non-nullable columns).

  SYNOPSIS
    my_bool has_primary_key(const char *table_name)

    table_name  quoted table name

  RETURNS     TRUE if the table has a primary key

  DESCRIPTION
*/

static my_bool has_primary_key(const char *table_name)
{
  MYSQL_RES  *res= NULL;
  MYSQL_ROW  row;
  char query_buff[QUERY_LENGTH];
  my_bool has_pk= TRUE;

  my_snprintf(query_buff, sizeof(query_buff),
              "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE "
              "TABLE_SCHEMA=DATABASE() AND TABLE_NAME='%s' AND "
              "COLUMN_KEY='PRI'", table_name);
  if (mysql_query(mysql, query_buff) || !(res= mysql_store_result(mysql)) ||
      !(row= mysql_fetch_row(res)))
  {
    fprintf(stderr, "%s: Warning: Couldn't determine if table %s has a "
            "primary key (%s). "
            "--innodb-optimize-keys may work inefficiently.\n",
            my_progname, table_name, mysql_error(mysql));
    goto cleanup;
  }

  has_pk= atoi(row[0]) > 0;

cleanup:
  if (res)
    mysql_free_result(res);

  return has_pk;
}

/**
  Prints "CREATE COMPRESSION_DICTIONARY ..." statement for the specified
  dictionary name if this is the first time this dictionary is referenced.

  @param sql_file          output file
  @param dictionary_name   dictionary name
*/
static void print_optional_create_compression_dictionary(FILE* sql_file,
  const char *dictionary_name)
{
  DBUG_ENTER("print_optional_create_compression_dictionary");
  DBUG_PRINT("enter", ("dictionary: %s", dictionary_name));

  /*
    We skip this compression dictionary if it has already been processed
  */
  if (my_hash_search(&processed_compression_dictionaries,
    (const uchar *)dictionary_name, strlen(dictionary_name)) == 0)
  {
    static const char get_zip_dict_data_stmt[] =
      "SELECT `ZIP_DICT` "
      "FROM `INFORMATION_SCHEMA`.`XTRADB_ZIP_DICT` "
      "WHERE `NAME` = '%s'";

    char quoted_buff[NAME_LEN * 2 + 3];
    char *quoted_dictionary_name;
    char query_buff[QUERY_LENGTH];
    MYSQL_RES *result= 0;
    MYSQL_ROW row;
    ulong *lengths;

    if (my_hash_insert(&processed_compression_dictionaries,
      (uchar*)my_strdup(PSI_NOT_INSTRUMENTED, dictionary_name, MYF(0))))
      die(EX_MYSQLERR, "Couldn't allocate memory");

    my_snprintf(query_buff, sizeof(query_buff), get_zip_dict_data_stmt,
                dictionary_name);

    if (mysql_query_with_error_report(mysql, &result, query_buff))
    {
      DBUG_VOID_RETURN;
    }

    row= mysql_fetch_row(result);
    if (row == 0)
    {
      mysql_free_result(result);
      maybe_die(EX_MYSQLERR,
                "Couldn't read data for compresion dictionary %s (%s)\n",
                dictionary_name, mysql_error(mysql));
      DBUG_VOID_RETURN;
    }
    lengths= mysql_fetch_lengths(result);
    assert(lengths != 0);

    quoted_dictionary_name= quote_name(dictionary_name, quoted_buff, 0);

    /*
      We print DROP COMPRESSION_DICTIONARY only if no --tab
      (file per table option) and no --skip-add-drop-compression-dictionary
      were specified
    */
    if (path == 0 && opt_drop_compression_dictionary)
    {
      fprintf(sql_file,
        "/*!"  STRINGIFY_ARG(FIRST_SUPPORTED_COMPRESSED_COLUMNS_VERSION)
        " DROP COMPRESSION_DICTIONARY IF EXISTS %s */;\n",
        quoted_dictionary_name);
      check_io(sql_file);
    }

    /*
      Whether IF NOT EXISTS is added to CREATE COMPRESSION_DICTIONARY
      depends on the --add-drop-compression-dictionary /
      --skip-add-drop-compression-dictionary options.
    */
    fprintf(sql_file,
      "/*!"  STRINGIFY_ARG(FIRST_SUPPORTED_COMPRESSED_COLUMNS_VERSION)
      " CREATE COMPRESSION_DICTIONARY %s%s (",
      path != 0 ? "IF NOT EXISTS " : "",
      quoted_dictionary_name);
    check_io(sql_file);

    unescape(sql_file, row[0], lengths[0]);
    fputs(") */;\n", sql_file);
    check_io(sql_file);

    mysql_free_result(result);
  }
  DBUG_VOID_RETURN;
}

/**
  Checks if --add-drop-table option is enabled and prints
  "DROP TABLE IF EXISTS ..." if the specified table is not a log table.

  @param sq_file            output file
  @param db                 db name
  @param table              table name
  @param opt_quoted_table   optionally quoted table name
*/
static void print_optional_drop_table(FILE *sql_file, const char* db,
                                      const char *table,
                                      const char *opt_quoted_table)
{
  DBUG_ENTER("print_optional_drop_table");
  DBUG_PRINT("enter", ("db: %s  table: %s", db, table));
  if (opt_drop)
  {
    if (!(general_log_or_slow_log_tables(db, table) ||
          replication_metadata_tables(db, table)))
    {
      fprintf(sql_file, "DROP TABLE IF EXISTS %s;\n", opt_quoted_table);
      check_io(sql_file);
    }
  }
  DBUG_VOID_RETURN;
}
/*
  get_table_structure -- retrievs database structure, prints out corresponding
  CREATE statement and fills out insert_pat if the table is the type we will
  be dumping.

  ARGS
    table       - table name
    db          - db name
    table_type  - table type, e.g. "MyISAM" or "InnoDB", but also "VIEW"
    ignore_flag - what we must particularly ignore - see IGNORE_ defines above
    real_columns- Contains one byte per column, 0 means unused, 1 is used
                  Generated columns are marked as unused
  RETURN
    number of fields in table, 0 if error
*/

static uint get_table_structure(char *table, char *db, char *table_type,
                                char *ignore_flag, my_bool real_columns[])
{
  my_bool    init=0, write_data, complete_insert;
  my_ulonglong num_fields;
  char       *result_table, *opt_quoted_table;
  const char *insert_option;
  char	     name_buff[NAME_LEN+3],table_buff[NAME_LEN*2+3];
  char       table_buff2[NAME_LEN*2+3], query_buff[QUERY_LENGTH];
  const char *show_fields_stmt= "SELECT `COLUMN_NAME` AS `Field`, "
                                "`COLUMN_TYPE` AS `Type`, "
                                "`IS_NULLABLE` AS `Null`, "
                                "`COLUMN_KEY` AS `Key`, "
                                "`COLUMN_DEFAULT` AS `Default`, "
                                "`EXTRA` AS `Extra`, "
                                "`COLUMN_COMMENT` AS `Comment` "
                                "FROM `INFORMATION_SCHEMA`.`COLUMNS` WHERE "
                                "TABLE_SCHEMA = '%s' AND TABLE_NAME = '%s'";
  FILE       *sql_file= md_result_file;
  size_t     len;
  my_bool    is_log_table;
  my_bool    is_replication_metadata_table;
  unsigned int colno;
  my_bool    is_innodb_table;
  MYSQL_RES  *result;
  MYSQL_ROW  row;
  my_bool    has_pk= FALSE;
  DBUG_ENTER("get_table_structure");
  DBUG_PRINT("enter", ("db: %s  table: %s", db, table));

  *ignore_flag= check_if_ignore_table(table, table_type);

  complete_insert= 0;
  if ((write_data= !(*ignore_flag & IGNORE_DATA)))
  {
    complete_insert= opt_complete_insert;
    if (!insert_pat_inited)
    {
      insert_pat_inited= 1;
      init_dynamic_string_checked(&insert_pat, "", 1024, 1024);
    }
    else
      dynstr_set_checked(&insert_pat, "");
  }

  insert_option= (opt_ignore ? " IGNORE " : "");

  verbose_msg("-- Retrieving table structure for table %s...\n", table);

  len= my_snprintf(query_buff, sizeof(query_buff),
                   "SET SQL_QUOTE_SHOW_CREATE=%d",
                   (opt_quoted || opt_keywords));
  if (!create_options)
    my_stpcpy(query_buff+len,
           "/*!40102 ,SQL_MODE=concat(@@sql_mode, _utf8 ',NO_KEY_OPTIONS,NO_TABLE_OPTIONS,NO_FIELD_OPTIONS') */");

  result_table=     quote_name(table, table_buff, 1);
  opt_quoted_table= quote_name(table, table_buff2, 0);

  if (opt_innodb_optimize_keys && !strcmp(table_type, "InnoDB"))
    has_pk= has_primary_key(table);

  if (opt_order_by_primary || opt_order_by_primary_desc)
    order_by= primary_key_fields(result_table,
                                 opt_order_by_primary_desc ? TRUE : FALSE);

  if (!opt_xml && !mysql_query_with_error_report(mysql, 0, query_buff))
  {
    /* using SHOW CREATE statement */
    if (!opt_no_create_info)
    {
      /* Make an sql-file, if path was given iow. option -T was given */
      char buff[20+FN_REFLEN];
      MYSQL_FIELD *field;
      my_bool freemem= FALSE;
      char const *text;

      my_snprintf(buff, sizeof(buff), "show create table %s", result_table);

      if (switch_character_set_results(mysql, "binary") ||
          mysql_query_with_error_report(mysql, &result, buff) ||
          switch_character_set_results(mysql, default_charset))
        DBUG_RETURN(0);

      if (path)
      {
        if (!(sql_file= open_sql_file_for_table(table, O_WRONLY)))
          DBUG_RETURN(0);

        write_header(sql_file, db);
      }

      text= fix_identifier_with_newline(result_table, &freemem);
      if (strcmp (table_type, "VIEW") == 0)         /* view */
        print_comment(sql_file, 0,
                      "\n--\n-- Temporary table structure for view %s\n--\n\n",
                      text);
      else
        print_comment(sql_file, 0,
                      "\n--\n-- Table structure for table %s\n--\n\n", text);

      if (freemem)
        my_free((void*)text);

      field= mysql_fetch_field_direct(result, 0);
      if (strcmp(field->name, "View") == 0)
      {
        char *scv_buff= NULL;
        my_ulonglong n_cols;

        /*
          Even if the "table" is a view, we do a DROP TABLE here.  The
          view-specific code below fills in the DROP VIEW.
          We will skip the DROP TABLE for general_log and slow_log, since
          those stmts will fail, in case we apply dump by enabling logging.
          We will skip this for replication metadata tables as well.
        */
        print_optional_drop_table(sql_file, db, table, opt_quoted_table);

        verbose_msg("-- It's a view, create dummy view\n");

        /* save "show create" statement for later */
        if ((row= mysql_fetch_row(result)) && (scv_buff=row[1]))
          scv_buff= my_strdup(PSI_NOT_INSTRUMENTED,
                              scv_buff, MYF(0));

        mysql_free_result(result);

        /*
          Create a table with the same name as the view and with columns of
          the same name in order to satisfy views that depend on this view.
          The table will be removed when the actual view is created.

          The properties of each column, are not preserved in this temporary
          table, because they are not necessary.

          This will not be necessary once we can determine dependencies
          between views and can simply dump them in the appropriate order.
        */
        my_snprintf(query_buff, sizeof(query_buff),
                    "SHOW FIELDS FROM %s", result_table);
        if (switch_character_set_results(mysql, "binary") ||
            mysql_query_with_error_report(mysql, &result, query_buff) ||
            switch_character_set_results(mysql, default_charset))
        {
          /*
            View references invalid or privileged table/col/fun (err 1356),
            so we cannot create a stand-in table.  Be defensive and dump
            a comment with the view's 'show create' statement. (Bug #17371)
          */

          if (mysql_errno(mysql) == ER_VIEW_INVALID)
            fprintf(sql_file, "\n-- failed on view %s: %s\n\n", result_table, scv_buff ? scv_buff : "");

          my_free(scv_buff);

          DBUG_RETURN(0);
        }
        else
          my_free(scv_buff);

        n_cols= mysql_num_rows(result);
        if (0 != n_cols)
        {

          /*
            The actual formula is based on the column names and how the .FRM
            files are stored and is too volatile to be repeated here.
            Thus we simply warn the user if the columns exceed a limit we
            know works most of the time.
          */
          if (n_cols >= 1000)
            fprintf(stderr,
                    "-- Warning: Creating a stand-in table for view %s may"
                    " fail when replaying the dump file produced because "
                    "of the number of columns exceeding 1000. Exercise "
                    "caution when replaying the produced dump file.\n", 
                    table);
          if (opt_drop)
          {
            /*
              We have already dropped any table of the same name above, so
              here we just drop the view.
            */

            fprintf(sql_file, "/*!50001 DROP VIEW IF EXISTS %s*/;\n",
                    opt_quoted_table);
            check_io(sql_file);
          }

          fprintf(sql_file,
                  "SET @saved_cs_client     = @@character_set_client;\n"
                  "SET character_set_client = utf8;\n"
                  "/*!50001 CREATE VIEW %s AS SELECT \n",
                  result_table);

          /*
            Get first row, following loop will prepend comma - keeps from
            having to know if the row being printed is last to determine if
            there should be a _trailing_ comma.
          */


          row= mysql_fetch_row(result);

          /*
            A temporary view is created to resolve the view interdependencies.
            This temporary view is dropped when the actual view is created.
          */

          fprintf(sql_file, " 1 AS %s",
                  quote_name(row[0], name_buff, 0));

          while((row= mysql_fetch_row(result)))
          {
            fprintf(sql_file, ",\n 1 AS %s",
                    quote_name(row[0], name_buff, 0));
          }

          fprintf(sql_file,"*/;\n"
                  "SET character_set_client = @saved_cs_client;\n");

          check_io(sql_file);
        }

        mysql_free_result(result);

        if (path)
          my_fclose(sql_file, MYF(MY_WME));

        seen_views= 1;
        DBUG_RETURN(0);
      }

      row= mysql_fetch_row(result);

      is_innodb_table= (strcmp(table_type, "InnoDB") == 0);
      if (opt_innodb_optimize_keys && is_innodb_table)
        skip_secondary_keys(row[1], has_pk);
      if (is_innodb_table)
      {
        /*
          Search for compressed columns attributes and remove them if
          necessary.
        */

        LIST *referenced_dictionaries= 0, *current_dictionary;

        skip_compressed_columns(row[1], &referenced_dictionaries);
        referenced_dictionaries= list_reverse(referenced_dictionaries);
        for (current_dictionary= referenced_dictionaries;
             current_dictionary != 0;
             current_dictionary= list_rest(current_dictionary))
        {
          print_optional_create_compression_dictionary(
            sql_file, (const char*)current_dictionary->data);
        }
        list_free(referenced_dictionaries, TRUE);
      }

      print_optional_drop_table(sql_file, db, table, opt_quoted_table);

      is_log_table= general_log_or_slow_log_tables(db, table);
      is_replication_metadata_table= replication_metadata_tables(db, table);
      if (is_log_table || is_replication_metadata_table)
        row[1]+= 13; /* strlen("CREATE TABLE ")= 13 */
      if (opt_compatible_mode & 3)
      {
        fprintf(sql_file,
                (is_log_table || is_replication_metadata_table) ?
                "CREATE TABLE IF NOT EXISTS %s;\n" : "%s;\n", row[1]);
      }
      else
      {
        fprintf(sql_file,
                "/*!40101 SET @saved_cs_client     = @@character_set_client */;\n"
                "/*!40101 SET character_set_client = utf8 */;\n"
                "%s%s;\n"
                "/*!40101 SET character_set_client = @saved_cs_client */;\n",
                (is_log_table || is_replication_metadata_table) ?
                "CREATE TABLE IF NOT EXISTS " : "", row[1]);
      }

      check_io(sql_file);
      mysql_free_result(result);
    }
    my_snprintf(query_buff, sizeof(query_buff), "show fields from %s",
                result_table);
    if (mysql_query_with_error_report(mysql, &result, query_buff))
    {
      if (path)
        my_fclose(sql_file, MYF(MY_WME));
      DBUG_RETURN(0);
    }

    if (write_data && !complete_insert)
    {
      /*
        If data contents of table are to be written and complete_insert
        is false (column list not required in INSERT statement), scan the
        column list for generated columns, as presence of any generated column
        will require that an explicit list of columns is printed.
      */
      while ((row= mysql_fetch_row(result)))
      {
        complete_insert|=
          strcmp(row[SHOW_EXTRA], "STORED GENERATED") == 0 ||
          strcmp(row[SHOW_EXTRA], "VIRTUAL GENERATED") == 0;
      }
      mysql_free_result(result);

      if (mysql_query_with_error_report(mysql, &result, query_buff))
      {
        if (path)
          my_fclose(sql_file, MYF(MY_WME));
        DBUG_RETURN(0);
      }
    }
    /*
      If write_data is true, then we build up insert statements for
      the table's data. Note: in subsequent lines of code, this test
      will have to be performed each time we are appending to
      insert_pat.
    */
    if (write_data)
    {
      if (opt_replace_into)
        dynstr_append_checked(&insert_pat, "REPLACE ");
      else
        dynstr_append_checked(&insert_pat, "INSERT ");
      dynstr_append_checked(&insert_pat, insert_option);
      dynstr_append_checked(&insert_pat, "INTO ");
      dynstr_append_checked(&insert_pat, opt_quoted_table);
      if (complete_insert)
      {
        dynstr_append_checked(&insert_pat, " (");
      }
      else
      {
        dynstr_append_checked(&insert_pat, " VALUES ");
        if (!extended_insert)
          dynstr_append_checked(&insert_pat, "(");
      }
    }

    colno= 0;
    while ((row= mysql_fetch_row(result)))
    {
      real_columns[colno]=
        strcmp(row[SHOW_EXTRA], "STORED GENERATED") != 0 &&
        strcmp(row[SHOW_EXTRA], "VIRTUAL GENERATED") != 0;

      if (real_columns[colno++] && complete_insert)
      {
        if (init)
        {
          dynstr_append_checked(&insert_pat, ", ");
        }
        init=1;
        dynstr_append_checked(&insert_pat,
                      quote_name(row[SHOW_FIELDNAME], name_buff, 0));
      }
    }
    num_fields= mysql_num_rows(result);
    mysql_free_result(result);
  }
  else
  {
    verbose_msg("%s: Warning: Can't set SQL_QUOTE_SHOW_CREATE option (%s)\n",
                my_progname, mysql_error(mysql));

    my_snprintf(query_buff, sizeof(query_buff), show_fields_stmt, db, table);

    if (mysql_query_with_error_report(mysql, &result, query_buff))
      DBUG_RETURN(0);

    if (write_data && !complete_insert)
    {
      /*
        If data contents of table are to be written and complete_insert
        is false (column list not required in INSERT statement), scan the
        column list for generated columns, as presence of any generated column
        will require that an explicit list of columns is printed.
      */
      while ((row= mysql_fetch_row(result)))
      {
        complete_insert|=
          strcmp(row[SHOW_EXTRA], "STORED GENERATED") == 0 ||
          strcmp(row[SHOW_EXTRA], "VIRTUAL GENERATED") == 0;
      }
      mysql_free_result(result);

      if (mysql_query_with_error_report(mysql, &result, query_buff))
      {
        if (path)
          my_fclose(sql_file, MYF(MY_WME));
        DBUG_RETURN(0);
      }
    }
    /* Make an sql-file, if path was given iow. option -T was given */
    if (!opt_no_create_info)
    {
      my_bool freemem= FALSE;
      char const *text;

      if (path)
      {
        if (!(sql_file= open_sql_file_for_table(table, O_WRONLY)))
          DBUG_RETURN(0);
        write_header(sql_file, db);
      }

      text= fix_identifier_with_newline(result_table, &freemem);
      print_comment(sql_file, 0,
                    "\n--\n-- Table structure for table %s\n--\n\n",
                    text);
      if (freemem)
        my_free((void*)text);

      if (opt_drop)
        fprintf(sql_file, "DROP TABLE IF EXISTS %s;\n", result_table);
      if (!opt_xml)
        fprintf(sql_file, "CREATE TABLE %s (\n", result_table);
      else
        print_xml_tag(sql_file, "\t", "\n", "table_structure", "name=", table, 
                NullS);
      check_io(sql_file);
    }

    if (write_data)
    {
      if (opt_replace_into)
        dynstr_append_checked(&insert_pat, "REPLACE ");
      else
        dynstr_append_checked(&insert_pat, "INSERT ");
      dynstr_append_checked(&insert_pat, insert_option);
      dynstr_append_checked(&insert_pat, "INTO ");
      dynstr_append_checked(&insert_pat, result_table);
      if (complete_insert)
        dynstr_append_checked(&insert_pat, " (");
      else
      {
        dynstr_append_checked(&insert_pat, " VALUES ");
        if (!extended_insert)
          dynstr_append_checked(&insert_pat, "(");
      }
    }

    colno= 0;
    while ((row= mysql_fetch_row(result)))
    {
      ulong *lengths= mysql_fetch_lengths(result);

      real_columns[colno]=
        strcmp(row[SHOW_EXTRA], "STORED GENERATED") != 0 &&
        strcmp(row[SHOW_EXTRA], "VIRTUAL GENERATED") != 0;

      if (!real_columns[colno++])
        continue;

      if (init)
      {
        if (!opt_xml && !opt_no_create_info)
        {
          fputs(",\n",sql_file);
          check_io(sql_file);
        }
        if (complete_insert)
          dynstr_append_checked(&insert_pat, ", ");
      }
      init=1;
      if (complete_insert)
        dynstr_append_checked(&insert_pat,
                      quote_name(row[SHOW_FIELDNAME], name_buff, 0));
      if (!opt_no_create_info)
      {
        if (opt_xml)
        {
          print_xml_row(sql_file, "field", result, &row, NullS);
          continue;
        }

        if (opt_keywords)
          fprintf(sql_file, "  %s.%s %s", result_table,
                  quote_name(row[SHOW_FIELDNAME],name_buff, 0),
                  row[SHOW_TYPE]);
        else
          fprintf(sql_file, "  %s %s", quote_name(row[SHOW_FIELDNAME],
                                                  name_buff, 0),
                  row[SHOW_TYPE]);
        if (row[SHOW_DEFAULT])
        {
          fputs(" DEFAULT ", sql_file);
          unescape(sql_file, row[SHOW_DEFAULT], lengths[SHOW_DEFAULT]);
        }
        if (!row[SHOW_NULL][0])
          fputs(" NOT NULL", sql_file);
        if (row[SHOW_EXTRA][0])
          fprintf(sql_file, " %s",row[SHOW_EXTRA]);
        check_io(sql_file);
      }
    }
    num_fields= mysql_num_rows(result);
    mysql_free_result(result);
    if (!opt_no_create_info)
    {
      /* Make an sql-file, if path was given iow. option -T was given */
      char buff[20+FN_REFLEN];
      uint keynr,primary_key;
      my_snprintf(buff, sizeof(buff), "show keys from %s", result_table);
      if (mysql_query_with_error_report(mysql, &result, buff))
      {
        if (mysql_errno(mysql) == ER_WRONG_OBJECT)
        {
          /* it is VIEW */
          fputs("\t\t<options Comment=\"view\" />\n", sql_file);
          goto continue_xml;
        }
        fprintf(stderr, "%s: Can't get keys for table %s (%s)\n",
                my_progname, result_table, mysql_error(mysql));
        if (path)
          my_fclose(sql_file, MYF(MY_WME));
        DBUG_RETURN(0);
      }

      /* Find first which key is primary key */
      keynr=0;
      primary_key=INT_MAX;
      while ((row= mysql_fetch_row(result)))
      {
        if (atoi(row[3]) == 1)
        {
          keynr++;
          if (!strcmp(row[2],"PRIMARY"))
          {
            primary_key=keynr;
            break;
          }
        }
      }
      mysql_data_seek(result,0);
      keynr=0;
      while ((row= mysql_fetch_row(result)))
      {
        if (opt_xml)
        {
          print_xml_row(sql_file, "key", result, &row, NullS);
          continue;
        }

        if (atoi(row[3]) == 1)
        {
          if (keynr++)
            putc(')', sql_file);
          if (atoi(row[1]))       /* Test if duplicate key */
            /* Duplicate allowed */
            fprintf(sql_file, ",\n  KEY %s (",quote_name(row[2],name_buff,0));
          else if (keynr == primary_key)
            fputs(",\n  PRIMARY KEY (",sql_file); /* First UNIQUE is primary */
          else
            fprintf(sql_file, ",\n  UNIQUE %s (",quote_name(row[2],name_buff,
                                                            0));
        }
        else
          putc(',', sql_file);
        fputs(quote_name(row[4], name_buff, 0), sql_file);
        if (row[7])
          fprintf(sql_file, " (%s)",row[7]);      /* Sub key */
        check_io(sql_file);
      }
      mysql_free_result(result);
      if (!opt_xml)
      {
        if (keynr)
          putc(')', sql_file);
        fputs("\n)",sql_file);
        check_io(sql_file);
      }

      /* Get MySQL specific create options */
      if (create_options)
      {
        char show_name_buff[NAME_LEN*2+2+24];

        /* Check memory for quote_for_like() */
        my_snprintf(buff, sizeof(buff), "show table status like %s",
                    quote_for_like(table, show_name_buff));

        if (mysql_query_with_error_report(mysql, &result, buff))
        {
          if (mysql_errno(mysql) != ER_PARSE_ERROR)
          {                                     /* If old MySQL version */
            verbose_msg("-- Warning: Couldn't get status information for " \
                        "table %s (%s)\n", result_table,mysql_error(mysql));
          }
        }
        else if (!(row= mysql_fetch_row(result)))
        {
          fprintf(stderr,
                  "Error: Couldn't read status information for table %s (%s)\n",
                  result_table,mysql_error(mysql));
        }
        else
        {
          if (opt_xml)
            print_xml_row(sql_file, "options", result, &row, NullS);
          else
          {
            fputs("/*!",sql_file);
            print_value(sql_file,result,row,"engine=","Engine",0);
            print_value(sql_file,result,row,"","Create_options",0);
            print_value(sql_file,result,row,"comment=","Comment",1);
            fputs(" */",sql_file);
            check_io(sql_file);
          }
        }
        mysql_free_result(result);              /* Is always safe to free */
      }
continue_xml:
      if (!opt_xml)
        fputs(";\n", sql_file);
      else
        fputs("\t</table_structure>\n", sql_file);
      check_io(sql_file);
    }
  }
  if (complete_insert)
  {
    dynstr_append_checked(&insert_pat, ") VALUES ");
    if (!extended_insert)
      dynstr_append_checked(&insert_pat, "(");
  }
  if (sql_file != md_result_file)
  {
    fputs("\n", sql_file);
    write_footer(sql_file);
    my_fclose(sql_file, MYF(MY_WME));
  }
  DBUG_RETURN((uint) num_fields);
} /* get_table_structure */

static void dump_trigger_old(FILE *sql_file, MYSQL_RES *show_triggers_rs,
                             MYSQL_ROW *show_trigger_row,
                             const char *table_name)
{
  char quoted_table_name_buf[NAME_LEN * 2 + 3];
  char *quoted_table_name= quote_name(table_name, quoted_table_name_buf, 1);

  char name_buff[NAME_LEN * 4 + 3];
  const char *xml_msg= "\nWarning! mysqldump being run against old server "
                       "that does not\nsupport 'SHOW CREATE TRIGGERS' "
                       "statement. Skipping..\n";

  DBUG_ENTER("dump_trigger_old");

  if (opt_xml)
  {
    print_xml_comment(sql_file, strlen(xml_msg), xml_msg);
    check_io(sql_file);
    DBUG_VOID_RETURN;
  }

  fprintf(sql_file,
          "--\n"
          "-- WARNING: old server version. "
            "The following dump may be incomplete.\n"
          "--\n");

  if (opt_compact)
    fprintf(sql_file, "/*!50003 SET @OLD_SQL_MODE=@@SQL_MODE*/;\n");

  if (opt_drop_trigger)
    fprintf(sql_file, "/*!50032 DROP TRIGGER IF EXISTS %s */;\n", (*show_trigger_row)[0]);

  fprintf(sql_file,
          "DELIMITER ;;\n"
          "/*!50003 SET SESSION SQL_MODE=\"%s\" */;;\n"
          "/*!50003 CREATE */ ",
          (*show_trigger_row)[6]);

  if (mysql_num_fields(show_triggers_rs) > 7)
  {
    /*
      mysqldump can be run against the server, that does not support
      definer in triggers (there is no DEFINER column in SHOW TRIGGERS
      output). So, we should check if we have this column before
      accessing it.
    */

    size_t user_name_len;
    char user_name_str[USERNAME_LENGTH + 1];
    char quoted_user_name_str[USERNAME_LENGTH * 2 + 3];
    size_t host_name_len;
    char host_name_str[HOSTNAME_LENGTH + 1];
    char quoted_host_name_str[HOSTNAME_LENGTH * 2 + 3];

    parse_user((*show_trigger_row)[7],
               strlen((*show_trigger_row)[7]),
               user_name_str, &user_name_len,
               host_name_str, &host_name_len);

    fprintf(sql_file,
            "/*!50017 DEFINER=%s@%s */ ",
            quote_name(user_name_str, quoted_user_name_str, FALSE),
            quote_name(host_name_str, quoted_host_name_str, FALSE));
  }

  fprintf(sql_file,
          "/*!50003 TRIGGER %s %s %s ON %s FOR EACH ROW%s%s */;;\n"
          "DELIMITER ;\n",
          quote_name((*show_trigger_row)[0], name_buff, 0), /* Trigger */
          (*show_trigger_row)[4], /* Timing */
          (*show_trigger_row)[1], /* Event */
          quoted_table_name,
          (strchr(" \t\n\r", *((*show_trigger_row)[3]))) ? "" : " ",
          (*show_trigger_row)[3] /* Statement */);

  if (opt_compact)
    fprintf(sql_file, "/*!50003 SET SESSION SQL_MODE=@OLD_SQL_MODE */;\n");

  DBUG_VOID_RETURN;
}

static int dump_trigger(FILE *sql_file, MYSQL_RES *show_create_trigger_rs,
                        const char *db_name,
                        const char *db_cl_name)
{
  MYSQL_ROW row;
  char *query_str;
  int db_cl_altered= FALSE;

  DBUG_ENTER("dump_trigger");

  while ((row= mysql_fetch_row(show_create_trigger_rs)))
  {
    if (opt_xml)
    {
      print_xml_row(sql_file, "trigger", show_create_trigger_rs, &row,
                    "SQL Original Statement");
      check_io(sql_file);
      continue;
    }

    query_str= cover_definer_clause(row[2], strlen(row[2]),
                                    C_STRING_WITH_LEN("50017"),
                                    C_STRING_WITH_LEN("50003"),
                                    C_STRING_WITH_LEN(" TRIGGER"));
    if (switch_db_collation(sql_file, db_name, ";",
                            db_cl_name, row[5], &db_cl_altered))
      DBUG_RETURN(TRUE);

    switch_cs_variables(sql_file, ";",
                        row[3],   /* character_set_client */
                        row[3],   /* character_set_results */
                        row[4]);  /* collation_connection */

    remove_sql_mode(row[1], C_STRING_WITH_LEN("NO_AUTO_CREATE_USER"));
    switch_sql_mode(sql_file, ";", row[1]);

    if (opt_drop_trigger)
      fprintf(sql_file, "/*!50032 DROP TRIGGER IF EXISTS %s */;\n", row[0]);

    fprintf(sql_file,
            "DELIMITER ;;\n"
            "/*!50003 %s */;;\n"
            "DELIMITER ;\n",
            (const char *) (query_str != NULL ? query_str : row[2]));

    restore_sql_mode(sql_file, ";");
    restore_cs_variables(sql_file, ";");

    if (db_cl_altered)
    {
      if (restore_db_collation(sql_file, db_name, ";", db_cl_name))
        DBUG_RETURN(TRUE);
    }

    my_free(query_str);
  }

  DBUG_RETURN(FALSE);
}

/**
  Dump the triggers for a given table.

  This should be called after the tables have been dumped in case a trigger
  depends on the existence of a table.

  @param[in] table_name
  @param[in] db_name

  @return Error status.
    @retval TRUE error has occurred.
    @retval FALSE operation succeed.
*/

static int dump_triggers_for_table(char *table_name, char *db_name)
{
  char       name_buff[NAME_LEN*4+3];
  char       query_buff[QUERY_LENGTH];
  uint       old_opt_compatible_mode= opt_compatible_mode;
  MYSQL_RES  *show_triggers_rs;
  MYSQL_ROW  row;
  FILE      *sql_file= md_result_file;

  char       db_cl_name[MY_CS_NAME_SIZE];
  int        ret= TRUE;

  DBUG_ENTER("dump_triggers_for_table");
  DBUG_PRINT("enter", ("db: %s, table_name: %s", db_name, table_name));

  if (path && !(sql_file= open_sql_file_for_table(table_name,
                                                  O_WRONLY | O_APPEND)))
    DBUG_RETURN(1);

  /* Do not use ANSI_QUOTES on triggers in dump */
  opt_compatible_mode&= ~MASK_ANSI_QUOTES;

  /* Get database collation. */

  if (switch_character_set_results(mysql, "binary"))
    goto done;

  if (fetch_db_collation(db_name, db_cl_name, sizeof (db_cl_name)))
    goto done;

  /* Get list of triggers. */

  my_snprintf(query_buff, sizeof(query_buff),
              "SHOW TRIGGERS LIKE %s",
              quote_for_like(table_name, name_buff));

  if (mysql_query_with_error_report(mysql, &show_triggers_rs, query_buff))
    goto done;

  /* Dump triggers. */

  if (! mysql_num_rows(show_triggers_rs))
    goto skip;

  if (opt_xml)
    print_xml_tag(sql_file, "\t", "\n", "triggers", "name=",
                  table_name, NullS);

  while ((row= mysql_fetch_row(show_triggers_rs)))
  {

    my_snprintf(query_buff, sizeof (query_buff),
                "SHOW CREATE TRIGGER %s",
                quote_name(row[0], name_buff, TRUE));

    if (mysql_query(mysql, query_buff))
    {
      /*
        mysqldump is being run against old server, that does not support
        SHOW CREATE TRIGGER statement. We should use SHOW TRIGGERS output.

        NOTE: the dump may be incorrect, as old SHOW TRIGGERS does not
        provide all the necessary information to restore trigger properly.
      */

      dump_trigger_old(sql_file, show_triggers_rs, &row, table_name);
    }
    else
    {
      MYSQL_RES *show_create_trigger_rs= mysql_store_result(mysql);

      if (!show_create_trigger_rs ||
          dump_trigger(sql_file, show_create_trigger_rs, db_name, db_cl_name))
        goto done;

      mysql_free_result(show_create_trigger_rs);
    }

  }

  if (opt_xml)
  {
    fputs("\t</triggers>\n", sql_file);
    check_io(sql_file);
  }

skip:
  mysql_free_result(show_triggers_rs);

  if (switch_character_set_results(mysql, default_charset))
    goto done;

  /*
    make sure to set back opt_compatible mode to
    original value
  */
  opt_compatible_mode=old_opt_compatible_mode;

  ret= FALSE;

done:
  if (path)
    my_fclose(sql_file, MYF(0));

  DBUG_RETURN(ret);
}

static void add_load_option(DYNAMIC_STRING *str, const char *option,
                             const char *option_value)
{
  if (!option_value)
  {
    /* Null value means we don't add this option. */
    return;
  }

  dynstr_append_checked(str, option);
  
  if (strncmp(option_value, "0x", sizeof("0x")-1) == 0)
  {
    /* It's a hex constant, don't escape */
    dynstr_append_checked(str, option_value);
  }
  else
  {
    /* char constant; escape */
    field_escape(str, option_value);
  }
}


/*
  Allow the user to specify field terminator strings like:
  "'", "\", "\\" (escaped backslash), "\t" (tab), "\n" (newline)
  This is done by doubling ' and add a end -\ if needed to avoid
  syntax errors from the SQL parser.
*/

static void field_escape(DYNAMIC_STRING* in, const char *from)
{
  uint end_backslashes= 0; 

  dynstr_append_checked(in, "'");

  while (*from)
  {
    dynstr_append_mem_checked(in, from, 1);

    if (*from == '\\')
      end_backslashes^=1;    /* find odd number of backslashes */
    else
    {
      if (*from == '\'' && !end_backslashes)
      {
        /* We want a duplicate of "'" for MySQL */
        dynstr_append_checked(in, "\'");
      }
      end_backslashes=0;
    }
    from++;
  }
  /* Add missing backslashes if user has specified odd number of backs.*/
  if (end_backslashes)
    dynstr_append_checked(in, "\\");
  
  dynstr_append_checked(in, "'");
}



static char *alloc_query_str(size_t size)
{
  char *query;

  if (!(query= (char*) my_malloc(PSI_NOT_INSTRUMENTED,
                                 size, MYF(MY_WME))))
    die(EX_MYSQLERR, "Couldn't allocate a query string.");

  return query;
}



/*
  Dump delayed secondary index definitions when --innodb-optimize-keys is used.
*/

static void dump_skipped_keys(const char *table)
{
  uint keys;

  if (!skipped_keys_list && !alter_constraints_list)
    return;

  verbose_msg("-- Dumping delayed secondary index definitions for table %s\n",
              table);

  if (skipped_keys_list)
  {
    uint sk_list_len= list_length(skipped_keys_list);
    skipped_keys_list= list_reverse(skipped_keys_list);
    fprintf(md_result_file, "ALTER TABLE %s%s", table,
            (sk_list_len > 1) ? "\n" : " ");

    for (keys= sk_list_len; keys > 0; keys--)
    {
      LIST *node= skipped_keys_list;
      char *def= node->data;

      fprintf(md_result_file, "%sADD %s%s", (sk_list_len > 1) ? "  " : "",
              def, (keys > 1) ? ",\n" : ";\n");

      skipped_keys_list= list_delete(skipped_keys_list, node);
      my_free(def);
      my_free(node);
    }
  }

  if (alter_constraints_list)
  {
    uint ac_list_len= list_length(alter_constraints_list);
    alter_constraints_list= list_reverse(alter_constraints_list);
    fprintf(md_result_file, "ALTER TABLE %s%s", table,
            (ac_list_len > 1) ? "\n" : " ");

    for (keys= ac_list_len; keys > 0; keys--)
    {
      LIST *node= alter_constraints_list;
      char *def= node->data;

      fprintf(md_result_file, "%sADD %s%s", (ac_list_len > 1) ? "  " : "",
              def, (keys > 1) ? ",\n" : ";\n");

      alter_constraints_list= list_delete(alter_constraints_list, node);
      my_free(def);
      my_free(node);
    }
  }

  assert(skipped_keys_list == NULL);
  assert(alter_constraints_list == NULL);
}


/*

 SYNOPSIS
  dump_table()

  dump_table saves database contents as a series of INSERT statements.

  ARGS
   table - table name
   db    - db name

   RETURNS
    void
*/


static void dump_table(char *table, char *db)
{
  char ignore_flag;
  char buf[200], table_buff[NAME_LEN+3];
  DYNAMIC_STRING query_string;
  DYNAMIC_STRING extended_row;
  char table_type[NAME_LEN];
  char *result_table, table_buff2[NAME_LEN*2+3], *opt_quoted_table;
  int error= 0;
  ulong         rownr, row_break;
  size_t        total_length, init_length;
  uint num_fields;
  MYSQL_RES     *res;
  MYSQL_FIELD   *field;
  MYSQL_ROW     row;
  my_bool real_columns[MAX_FIELDS];
  DBUG_ENTER("dump_table");

  /*
    Make sure you get the create table info before the following check for
    --no-data flag below. Otherwise, the create table info won't be printed.
  */
  num_fields= get_table_structure(table, db, table_type, &ignore_flag,
                                  real_columns);

  /*
    The "table" could be a view.  If so, we don't do anything here.
  */
  if (strcmp(table_type, "VIEW") == 0)
    DBUG_VOID_RETURN;

  /*
    We don't dump data fo`r replication metadata tables.
  */
  if (replication_metadata_tables(db, table))
    DBUG_VOID_RETURN;

  result_table= quote_name(table,table_buff, 1);
  opt_quoted_table= quote_name(table, table_buff2, 0);

  /* Check --no-data flag */
  if (opt_no_data)
  {
    dump_skipped_keys(opt_quoted_table);

    verbose_msg("-- Skipping dump data for table '%s', --no-data was used\n",
                table);
    DBUG_VOID_RETURN;
  }

  DBUG_PRINT("info",
             ("ignore_flag: %x  num_fields: %d", (int) ignore_flag,
              num_fields));
  /*
    If the table type is a merge table or any type that has to be
     _completely_ ignored and no data dumped
  */
  if (ignore_flag & IGNORE_DATA)
  {
    verbose_msg("-- Warning: Skipping data for table '%s' because " \
                "it's of type %s\n", table, table_type);
    DBUG_VOID_RETURN;
  }
  /* Check that there are any fields in the table */
  if (num_fields == 0)
  {
    verbose_msg("-- Skipping dump data for table '%s', it has no fields\n",
                table);
    DBUG_VOID_RETURN;
  }

  verbose_msg("-- Sending SELECT query...\n");

  init_dynamic_string_checked(&query_string, "", 1024, 1024);
  if (extended_insert)
    init_dynamic_string_checked(&extended_row, "", 1024, 1024);

  if (path)
  {
    char filename[FN_REFLEN], tmp_path[FN_REFLEN];

    /*
      Convert the path to native os format
      and resolve to the full filepath.
    */
    convert_dirname(tmp_path,path,NullS);    
    my_load_path(tmp_path, tmp_path, NULL);
    fn_format(filename, table, tmp_path, ".txt", MYF(MY_UNPACK_FILENAME));

    /* Must delete the file that 'INTO OUTFILE' will write to */
    my_delete(filename, MYF(0));

    /* convert to a unix path name to stick into the query */
    to_unix_path(filename);

    /* now build the query string */

    dynstr_append_checked(&query_string, "SELECT /*!40001 SQL_NO_CACHE */ * INTO OUTFILE '");
    dynstr_append_checked(&query_string, filename);
    dynstr_append_checked(&query_string, "'");

    dynstr_append_checked(&query_string, " /*!50138 CHARACTER SET ");
    dynstr_append_checked(&query_string, default_charset == mysql_universal_client_charset ?
                                         my_charset_bin.name : /* backward compatibility */
                                         default_charset);
    dynstr_append_checked(&query_string, " */");

    if (fields_terminated || enclosed || opt_enclosed || escaped)
      dynstr_append_checked(&query_string, " FIELDS");
    
    add_load_option(&query_string, " TERMINATED BY ", fields_terminated);
    add_load_option(&query_string, " ENCLOSED BY ", enclosed);
    add_load_option(&query_string, " OPTIONALLY ENCLOSED BY ", opt_enclosed);
    add_load_option(&query_string, " ESCAPED BY ", escaped);
    add_load_option(&query_string, " LINES TERMINATED BY ", lines_terminated);

    dynstr_append_checked(&query_string, " FROM ");
    dynstr_append_checked(&query_string, result_table);

    if (where)
    {
      dynstr_append_checked(&query_string, " WHERE ");
      dynstr_append_checked(&query_string, where);
    }
    else if ((!my_strcasecmp(charset_info, db, "mysql")) &&
             (!my_strcasecmp(charset_info, table, "proc")) &&
             opt_alldbs)
    {
      dynstr_append_checked(&query_string, " WHERE db != 'sys'");
    }

    if (order_by)
    {
      dynstr_append_checked(&query_string, " ORDER BY ");
      dynstr_append_checked(&query_string, order_by);

      my_free(order_by);
      order_by = 0;
    }

    if (mysql_real_query(mysql, query_string.str, (ulong)query_string.length))
    {
      DB_error(mysql, "when executing 'SELECT INTO OUTFILE'");
      dynstr_free(&query_string);
      DBUG_VOID_RETURN;
    }
  }
  else
  {
    my_bool freemem= FALSE;
    char const* text= fix_identifier_with_newline(result_table, &freemem);
    print_comment(md_result_file, 0, "\n--\n-- Dumping data for table %s\n--\n",
                  text);
    if (freemem)
      my_free((void*)text);

    dynstr_append_checked(&query_string, "SELECT /*!40001 SQL_NO_CACHE */ * FROM ");
    dynstr_append_checked(&query_string, result_table);

    if (where)
    {
      freemem= FALSE;
      text= fix_identifier_with_newline(where, &freemem);
      print_comment(md_result_file, 0, "-- WHERE:  %s\n", text);
      if (freemem)
        my_free((void*)text);

      dynstr_append_checked(&query_string, " WHERE ");
      dynstr_append_checked(&query_string, where);
    }
    /*
      If table is mysql.proc then do not dump routines which belong
      to sys schema
    */
    else if ((!my_strcasecmp(charset_info, db, "mysql")) &&
             (!my_strcasecmp(charset_info, table, "proc")) &&
             opt_alldbs)
    {
      dynstr_append_checked(&query_string, " WHERE db != 'sys'");
    }
    if (order_by)
    {
      freemem= FALSE;
      text= fix_identifier_with_newline(order_by, &freemem);
      print_comment(md_result_file, 0, "-- ORDER BY:  %s\n", text);
      if (freemem)
        my_free((void*)text);

      dynstr_append_checked(&query_string, " ORDER BY ");
      dynstr_append_checked(&query_string, order_by);

      my_free(order_by);
      order_by = 0;
    }

    if (!opt_xml && !opt_compact)
    {
      fputs("\n", md_result_file);
      check_io(md_result_file);
    }
    if (mysql_query_with_error_report(mysql, 0, query_string.str))
    {
      DB_error(mysql, "when retrieving data from server");
      goto err;
    }
    if (quick)
      res=mysql_use_result(mysql);
    else
      res=mysql_store_result(mysql);
    if (!res)
    {
      DB_error(mysql, "when retrieving data from server");
      goto err;
    }

    verbose_msg("-- Retrieving rows...\n");
    if (mysql_num_fields(res) != num_fields)
    {
      fprintf(stderr,"%s: Error in field count for table: %s !  Aborting.\n",
              my_progname, result_table);
      error= EX_CONSCHECK;
      goto err;
    }

    if (opt_lock)
    {
      fprintf(md_result_file,"LOCK TABLES %s WRITE;\n", opt_quoted_table);
      check_io(md_result_file);
    }
    /* Moved disable keys to after lock per bug 15977 */
    if (opt_disable_keys)
    {
      fprintf(md_result_file, "/*!40000 ALTER TABLE %s DISABLE KEYS */;\n",
	      opt_quoted_table);
      check_io(md_result_file);
    }

    total_length= opt_net_buffer_length;                /* Force row break */
    row_break=0;
    rownr=0;
    init_length=(uint) insert_pat.length+4;
    if (opt_xml)
      print_xml_tag(md_result_file, "\t", "\n", "table_data", "name=", table,
              NullS);
    if (opt_autocommit)
    {
      fprintf(md_result_file, "set autocommit=0;\n");
      check_io(md_result_file);
    }

    while ((row= mysql_fetch_row(res)))
    {
      uint i;
      ulong *lengths= mysql_fetch_lengths(res);
      rownr++;
      if (!extended_insert && !opt_xml)
      {
        fputs(insert_pat.str,md_result_file);
        check_io(md_result_file);
      }
      mysql_field_seek(res,0);

      if (opt_xml)
      {
        fputs("\t<row>\n", md_result_file);
        check_io(md_result_file);
      }

      for (i= 0; i < mysql_num_fields(res); i++)
      {
        int is_blob;
        ulong length= lengths[i];

        if (!(field= mysql_fetch_field(res)))
          die(EX_CONSCHECK,
                      "Not enough fields from table %s! Aborting.\n",
                      result_table);

        if (!real_columns[i])
          continue;
        /*
           63 is my_charset_bin. If charsetnr is not 63,
           we have not a BLOB but a TEXT column.
        */
        is_blob= (field->charsetnr == 63 &&
                  (field->type == MYSQL_TYPE_BIT ||
                   field->type == MYSQL_TYPE_STRING ||
                   field->type == MYSQL_TYPE_VAR_STRING ||
                   field->type == MYSQL_TYPE_VARCHAR ||
                   field->type == MYSQL_TYPE_BLOB ||
                   field->type == MYSQL_TYPE_LONG_BLOB ||
                   field->type == MYSQL_TYPE_MEDIUM_BLOB ||
                   field->type == MYSQL_TYPE_TINY_BLOB ||
                   field->type == MYSQL_TYPE_GEOMETRY)) ? 1 : 0;
        if (extended_insert && !opt_xml)
        {
          if (i == 0)
            dynstr_set_checked(&extended_row,"(");
          else
            dynstr_append_checked(&extended_row,",");

          if (row[i])
          {
            if (length)
            {
              if (!(field->flags & NUM_FLAG))
              {
                /*
                  "length * 2 + 2" is OK for HEX mode:
                  - In HEX mode we need exactly 2 bytes per character
                  plus 2 bytes for '0x' prefix.
                  - In non-HEX mode we need up to 2 bytes per character,
                  plus 2 bytes for leading and trailing '\'' characters
                  and reserve 1 byte for terminating '\0'.
                  In addition to this, for the blob type, we need to
                  reserve for the "_binary " string that gets added in
                  front of the string in the dump.
                */
                if (opt_hex_blob && is_blob)
                {
                  dynstr_realloc_checked(&extended_row,length * 2 + 2 + 1);
                  dynstr_append_checked(&extended_row, "0x");
                  extended_row.length+= mysql_hex_string(extended_row.str +
                                                         extended_row.length,
                                                         row[i], length);
                  assert(extended_row.length+1 <= extended_row.max_length);
                  /* mysql_hex_string() already terminated string by '\0' */
                  assert(extended_row.str[extended_row.length] == '\0');
                }
                else
                {
                  dynstr_realloc_checked(&extended_row,length * 2 + 2 + 1 +
                                         (is_blob? strlen("_binary ") : 0));
                  if (is_blob)
                  {
                    /*
                      inform SQL parser that this string isn't in
                      character_set_connection, so it doesn't emit a warning.
                    */
                    dynstr_append_checked(&extended_row, "_binary ");
                  }
                  dynstr_append_checked(&extended_row,"'");
                  extended_row.length +=
                  mysql_real_escape_string_quote(&mysql_connection,
                                         &extended_row.str[extended_row.length],
                                         row[i],length,
                                         '\'');
                  extended_row.str[extended_row.length]='\0';
                  dynstr_append_checked(&extended_row,"'");
                }
              }
              else
              {
                /* change any strings ("inf", "-inf", "nan") into NULL */
                char *ptr= row[i];
                if (my_isalpha(charset_info, *ptr) || (*ptr == '-' &&
                    my_isalpha(charset_info, ptr[1])))
                  dynstr_append_checked(&extended_row, "NULL");
                else
                {
                  if (field->type == MYSQL_TYPE_DECIMAL)
                  {
                    /* add " signs around */
                    dynstr_append_checked(&extended_row, "'");
                    dynstr_append_checked(&extended_row, ptr);
                    dynstr_append_checked(&extended_row, "'");
                  }
                  else
                    dynstr_append_checked(&extended_row, ptr);
                }
              }
            }
            else
              dynstr_append_checked(&extended_row,"''");
          }
          else
            dynstr_append_checked(&extended_row,"NULL");
        }
        else
        {
          if (i && !opt_xml)
          {
            fputc(',', md_result_file);
            check_io(md_result_file);
          }
          if (row[i])
          {
            if (!(field->flags & NUM_FLAG))
            {
              if (opt_xml)
              {
                if (opt_hex_blob && is_blob && length)
                {
                  /* Define xsi:type="xs:hexBinary" for hex encoded data */
                  print_xml_tag(md_result_file, "\t\t", "", "field", "name=",
                                field->name, "xsi:type=", "xs:hexBinary", NullS);
                  print_blob_as_hex(md_result_file, row[i], length);
                }
                else
                {
                  print_xml_tag(md_result_file, "\t\t", "", "field", "name=", 
                                field->name, NullS);
                  print_quoted_xml(md_result_file, row[i], length, 0);
                }
                fputs("</field>\n", md_result_file);
              }
              else if (opt_hex_blob && is_blob && length)
              {
                fputs("0x", md_result_file);
                print_blob_as_hex(md_result_file, row[i], length);
              }
              else
              {
                if (is_blob)
                {
                  fputs("_binary ", md_result_file);
                  check_io(md_result_file);
                }
                unescape(md_result_file, row[i], length);
              }
            }
            else
            {
              /* change any strings ("inf", "-inf", "nan") into NULL */
              char *ptr= row[i];
              if (opt_xml)
              {
                print_xml_tag(md_result_file, "\t\t", "", "field", "name=",
                        field->name, NullS);
                fputs(!my_isalpha(charset_info, *ptr) ? ptr: "NULL",
                      md_result_file);
                fputs("</field>\n", md_result_file);
              }
              else if (my_isalpha(charset_info, *ptr) ||
                       (*ptr == '-' && my_isalpha(charset_info, ptr[1])))
                fputs("NULL", md_result_file);
              else if (field->type == MYSQL_TYPE_DECIMAL)
              {
                /* add " signs around */
                fputc('\'', md_result_file);
                fputs(ptr, md_result_file);
                fputc('\'', md_result_file);
              }
              else
                fputs(ptr, md_result_file);
            }
          }
          else
          {
            /* The field value is NULL */
            if (!opt_xml)
              fputs("NULL", md_result_file);
            else
              print_xml_null_tag(md_result_file, "\t\t", "field name=",
                                 field->name, "\n");
          }
          check_io(md_result_file);
        }
      }

      if (opt_xml)
      {
        fputs("\t</row>\n", md_result_file);
        check_io(md_result_file);
      }

      if (extended_insert)
      {
        size_t row_length;
        dynstr_append_checked(&extended_row,")");
        row_length= 2 + extended_row.length;
        if (total_length + row_length < opt_net_buffer_length)
        {
          total_length+= row_length;
          fputc(',',md_result_file);            /* Always row break */
          fputs(extended_row.str,md_result_file);
        }
        else
        {
          if (row_break)
            fputs(";\n", md_result_file);
          row_break=1;                          /* This is first row */

          fputs(insert_pat.str,md_result_file);
          fputs(extended_row.str,md_result_file);
          total_length= row_length+init_length;
        }
        check_io(md_result_file);
      }
      else if (!opt_xml)
      {
        fputs(");\n", md_result_file);
        check_io(md_result_file);
      }
    }

    /* XML - close table tag and supress regular output */
    if (opt_xml)
        fputs("\t</table_data>\n", md_result_file);
    else if (extended_insert && row_break)
      fputs(";\n", md_result_file);             /* If not empty table */
    fflush(md_result_file);
    check_io(md_result_file);
    if (mysql_errno(mysql))
    {
      my_snprintf(buf, sizeof(buf),
                  "%s: Error %d: %s when dumping table %s at row: %ld\n",
                  my_progname,
                  mysql_errno(mysql),
                  mysql_error(mysql),
                  result_table,
                  rownr);
      fputs(buf,stderr);
      error= EX_CONSCHECK;
      goto err;
    }

    dump_skipped_keys(opt_quoted_table);

    /* Moved enable keys to before unlock per bug 15977 */
    if (opt_disable_keys)
    {
      fprintf(md_result_file,"/*!40000 ALTER TABLE %s ENABLE KEYS */;\n",
              opt_quoted_table);
      check_io(md_result_file);
    }
    if (opt_lock)
    {
      fputs("UNLOCK TABLES;\n", md_result_file);
      check_io(md_result_file);
    }
    if (opt_autocommit)
    {
      fprintf(md_result_file, "commit;\n");
      check_io(md_result_file);
    }
    mysql_free_result(res);
  }
  dynstr_free(&query_string);
  if (extended_insert)
    dynstr_free(&extended_row);
  DBUG_VOID_RETURN;

err:
  dynstr_free(&query_string);
  if (extended_insert)
    dynstr_free(&extended_row);
  maybe_exit(error);
  DBUG_VOID_RETURN;
} /* dump_table */


static char *getTableName(int reset)
{
  static MYSQL_RES *res= NULL;
  MYSQL_ROW    row;

  if (!res)
  {
    if (!(res= mysql_list_tables(mysql,NullS)))
      return(NULL);
  }
  if ((row= mysql_fetch_row(res)))
    return((char*) row[0]);

  if (reset)
    mysql_data_seek(res,0);      /* We want to read again */
  else
  {
    mysql_free_result(res);
    res= NULL;
  }
  return(NULL);
} /* getTableName */


/*
  dump all logfile groups and tablespaces
*/

static int dump_all_tablespaces()
{
  return dump_tablespaces(NULL);
}

static int dump_tablespaces_for_tables(char *db, char **table_names, int tables)
{
  DYNAMIC_STRING where;
  int r;
  int i;
  char name_buff[NAME_LEN*2+3];

  mysql_real_escape_string_quote(mysql, name_buff, db, (ulong)strlen(db), '\'');

  init_dynamic_string_checked(&where, " AND TABLESPACE_NAME IN ("
                      "SELECT DISTINCT TABLESPACE_NAME FROM"
                      " INFORMATION_SCHEMA.PARTITIONS"
                      " WHERE"
                      " TABLE_SCHEMA='", 256, 1024);
  dynstr_append_checked(&where, name_buff);
  dynstr_append_checked(&where, "' AND TABLE_NAME IN (");

  for (i=0 ; i<tables ; i++)
  {
    mysql_real_escape_string_quote(mysql, name_buff,
                           table_names[i], (ulong)strlen(table_names[i]), '\'');

    dynstr_append_checked(&where, "'");
    dynstr_append_checked(&where, name_buff);
    dynstr_append_checked(&where, "',");
  }
  dynstr_trunc(&where, 1);
  dynstr_append_checked(&where,"))");

  DBUG_PRINT("info",("Dump TS for Tables where: %s",where.str));
  r= dump_tablespaces(where.str);
  dynstr_free(&where);
  return r;
}

static int dump_tablespaces_for_databases(char** databases)
{
  DYNAMIC_STRING where;
  int r;
  int i;

  init_dynamic_string_checked(&where, " AND TABLESPACE_NAME IN ("
                      "SELECT DISTINCT TABLESPACE_NAME FROM"
                      " INFORMATION_SCHEMA.PARTITIONS"
                      " WHERE"
                      " TABLE_SCHEMA IN (", 256, 1024);

  for (i=0 ; databases[i]!=NULL ; i++)
  {
    char db_name_buff[NAME_LEN*2+3];
    mysql_real_escape_string_quote(mysql, db_name_buff,
                               databases[i], (ulong)strlen(databases[i]), '\'');
    dynstr_append_checked(&where, "'");
    dynstr_append_checked(&where, db_name_buff);
    dynstr_append_checked(&where, "',");
  }
  dynstr_trunc(&where, 1);
  dynstr_append_checked(&where,"))");

  DBUG_PRINT("info",("Dump TS for DBs where: %s",where.str));
  r= dump_tablespaces(where.str);
  dynstr_free(&where);
  return r;
}

static int dump_tablespaces(char* ts_where)
{
  MYSQL_ROW row;
  MYSQL_RES *tableres;
  char buf[FN_REFLEN];
  DYNAMIC_STRING sqlbuf;
  int first= 0;
  /*
    The following are used for parsing the EXTRA field
  */
  char extra_format[]= "UNDO_BUFFER_SIZE=";
  char *ubs;
  char *endsemi;
  DBUG_ENTER("dump_tablespaces");

  init_dynamic_string_checked(&sqlbuf,
                      "SELECT LOGFILE_GROUP_NAME,"
                      " FILE_NAME,"
                      " TOTAL_EXTENTS,"
                      " INITIAL_SIZE,"
                      " ENGINE,"
                      " EXTRA"
                      " FROM INFORMATION_SCHEMA.FILES"
                      " WHERE FILE_TYPE = 'UNDO LOG'"
                      " AND FILE_NAME IS NOT NULL"
                      " AND LOGFILE_GROUP_NAME IS NOT NULL",
                      256, 1024);
  if(ts_where)
  {
    dynstr_append_checked(&sqlbuf,
                  " AND LOGFILE_GROUP_NAME IN ("
                  "SELECT DISTINCT LOGFILE_GROUP_NAME"
                  " FROM INFORMATION_SCHEMA.FILES"
                  " WHERE FILE_TYPE = 'DATAFILE'"
                  );
    dynstr_append_checked(&sqlbuf, ts_where);
    dynstr_append_checked(&sqlbuf, ")");
  }
  dynstr_append_checked(&sqlbuf,
                " GROUP BY LOGFILE_GROUP_NAME, FILE_NAME"
                ", ENGINE, TOTAL_EXTENTS, INITIAL_SIZE"
                " ORDER BY LOGFILE_GROUP_NAME");

  if (mysql_query(mysql, sqlbuf.str) ||
      !(tableres = mysql_store_result(mysql)))
  {
    dynstr_free(&sqlbuf);
    if (mysql_errno(mysql) == ER_BAD_TABLE_ERROR ||
        mysql_errno(mysql) == ER_BAD_DB_ERROR ||
        mysql_errno(mysql) == ER_UNKNOWN_TABLE)
    {
      fprintf(md_result_file,
              "\n--\n-- Not dumping tablespaces as no INFORMATION_SCHEMA.FILES"
              " table on this server\n--\n");
      check_io(md_result_file);
      DBUG_RETURN(0);
    }

    my_printf_error(0, "Error: '%s' when trying to dump tablespaces",
                    MYF(0), mysql_error(mysql));
    DBUG_RETURN(1);
  }

  buf[0]= 0;
  while ((row= mysql_fetch_row(tableres)))
  {
    if (strcmp(buf, row[0]) != 0)
      first= 1;
    if (first)
    {
      print_comment(md_result_file, 0, "\n--\n-- Logfile group: %s\n--\n",
                    row[0]);

      fprintf(md_result_file, "\nCREATE");
    }
    else
    {
      fprintf(md_result_file, "\nALTER");
    }
    fprintf(md_result_file,
            " LOGFILE GROUP %s\n"
            "  ADD UNDOFILE '%s'\n",
            row[0],
            row[1]);
    if (first)
    {
      ubs= strstr(row[5],extra_format);
      if(!ubs)
        break;
      ubs+= strlen(extra_format);
      endsemi= strstr(ubs,";");
      if(endsemi)
        endsemi[0]= '\0';
      fprintf(md_result_file,
              "  UNDO_BUFFER_SIZE %s\n",
              ubs);
    }
    fprintf(md_result_file,
            "  INITIAL_SIZE %s\n"
            "  ENGINE=%s;\n",
            row[3],
            row[4]);
    check_io(md_result_file);
    if (first)
    {
      first= 0;
      strxmov(buf, row[0], NullS);
    }
  }
  dynstr_free(&sqlbuf);
  mysql_free_result(tableres);
  init_dynamic_string_checked(&sqlbuf,
                      "SELECT DISTINCT TABLESPACE_NAME,"
                      " FILE_NAME,"
                      " LOGFILE_GROUP_NAME,"
                      " EXTENT_SIZE,"
                      " INITIAL_SIZE,"
                      " ENGINE"
                      " FROM INFORMATION_SCHEMA.FILES"
                      " WHERE FILE_TYPE = 'DATAFILE'",
                      256, 1024);

  if(ts_where)
    dynstr_append_checked(&sqlbuf, ts_where);

  dynstr_append_checked(&sqlbuf, " ORDER BY TABLESPACE_NAME, LOGFILE_GROUP_NAME");

  if (mysql_query_with_error_report(mysql, &tableres, sqlbuf.str))
  {
    dynstr_free(&sqlbuf);
    DBUG_RETURN(1);
  }

  buf[0]= 0;
  while ((row= mysql_fetch_row(tableres)))
  {
    if (strcmp(buf, row[0]) != 0)
      first= 1;
    if (first)
    {
      print_comment(md_result_file, 0, "\n--\n-- Tablespace: %s\n--\n", row[0]);
      fprintf(md_result_file, "\nCREATE");
    }
    else
    {
      fprintf(md_result_file, "\nALTER");
    }
    fprintf(md_result_file,
            " TABLESPACE %s\n"
            "  ADD DATAFILE '%s'\n",
            row[0],
            row[1]);
    if (first)
    {
      fprintf(md_result_file,
              "  USE LOGFILE GROUP %s\n"
              "  EXTENT_SIZE %s\n",
              row[2],
              row[3]);
    }
    fprintf(md_result_file,
            "  INITIAL_SIZE %s\n"
            "  ENGINE=%s;\n",
            row[4],
            row[5]);
    check_io(md_result_file);
    if (first)
    {
      first= 0;
      strxmov(buf, row[0], NullS);
    }
  }

  mysql_free_result(tableres);
  dynstr_free(&sqlbuf);
  DBUG_RETURN(0);
}


static int
is_ndbinfo(MYSQL* mysql, const char* dbname)
{
  static int checked_ndbinfo= 0;
  static int have_ndbinfo= 0;

  if (!checked_ndbinfo)
  {
    MYSQL_RES *res;
    MYSQL_ROW row;
    char buf[32], query[64];

    my_snprintf(query, sizeof(query),
                "SHOW VARIABLES LIKE %s",
                quote_for_like("ndbinfo_version", buf));

    checked_ndbinfo= 1;

    if (mysql_query_with_error_report(mysql, &res, query))
      return 0;

    if (!(row= mysql_fetch_row(res)))
    {
      mysql_free_result(res);
      return 0;
    }

    have_ndbinfo= 1;
    mysql_free_result(res);
  }

  if (!have_ndbinfo)
    return 0;

  if (my_strcasecmp(&my_charset_latin1, dbname, "ndbinfo") == 0)
    return 1;

  return 0;
}


static int dump_all_databases()
{
  MYSQL_ROW row;
  MYSQL_RES *tableres;
  int result=0;

  my_ulonglong total_databases= 0;
  char **database_list;
  uint db_cnt = 0, cnt = 0;
  uint mysql_db_found = 0;

  if (mysql_query_with_error_report(mysql, &tableres, "SHOW DATABASES"))
    return 1;

  total_databases= mysql_num_rows(tableres);
  database_list = (char **) my_malloc(PSI_NOT_INSTRUMENTED,
    (sizeof(char *) * total_databases), MYF(MY_WME));

  while ((row= mysql_fetch_row(tableres)))
  {
    if (mysql_get_server_version(mysql) >= FIRST_INFORMATION_SCHEMA_VERSION &&
        !my_strcasecmp(&my_charset_latin1, row[0], INFORMATION_SCHEMA_DB_NAME))
      continue;

    if (mysql_get_server_version(mysql) >= FIRST_PERFORMANCE_SCHEMA_VERSION &&
        !my_strcasecmp(&my_charset_latin1, row[0], PERFORMANCE_SCHEMA_DB_NAME))
      continue;

    if (mysql_get_server_version(mysql) >= FIRST_SYS_SCHEMA_VERSION &&
        !my_strcasecmp(&my_charset_latin1, row[0], SYS_SCHEMA_DB_NAME))
      continue;

    if (is_ndbinfo(mysql, row[0]))
      continue;

    if (mysql_db_found || (!my_strcasecmp(charset_info, row[0], "mysql")))
    {
      if (dump_all_tables_in_db(row[0]))
        result=1;
      mysql_db_found = 1;
      /*
        once mysql database is found dump all dbs saved as part
        of database_list
      */
      for (; cnt < db_cnt; cnt++)
      {
        if (dump_all_tables_in_db(database_list[cnt]))
          result=1;
        my_free(database_list[cnt]);
      }
    }
    else
    {
      /*
        till mysql database is not found save database names to
        database_list
      */
      database_list[db_cnt] = my_strdup(PSI_NOT_INSTRUMENTED, row[0],
                                        MYF(MY_WME | MY_ZEROFILL));
      db_cnt++;
    }
  }
  assert(mysql_db_found);
  memset(database_list, 0, sizeof(*database_list));
  my_free(database_list);

  mysql_free_result(tableres);
  if (seen_views)
  {
    if (mysql_query(mysql, "SHOW DATABASES") ||
        !(tableres= mysql_store_result(mysql)))
    {
      my_printf_error(0, "Error: Couldn't execute 'SHOW DATABASES': %s",
                      MYF(0), mysql_error(mysql));
      return 1;
    }
    while ((row= mysql_fetch_row(tableres)))
    {
      if (mysql_get_server_version(mysql) >= FIRST_INFORMATION_SCHEMA_VERSION &&
          !my_strcasecmp(&my_charset_latin1, row[0], INFORMATION_SCHEMA_DB_NAME))
        continue;

      if (mysql_get_server_version(mysql) >= FIRST_PERFORMANCE_SCHEMA_VERSION &&
          !my_strcasecmp(&my_charset_latin1, row[0], PERFORMANCE_SCHEMA_DB_NAME))
        continue;

      if (mysql_get_server_version(mysql) >= FIRST_SYS_SCHEMA_VERSION &&
          !my_strcasecmp(&my_charset_latin1, row[0], SYS_SCHEMA_DB_NAME))
        continue;

      if (is_ndbinfo(mysql, row[0]))
        continue;

      if (dump_all_views_in_db(row[0]))
        result=1;
    }
    mysql_free_result(tableres);
  }
  return result;
}
/* dump_all_databases */


static int dump_databases(char **db_names)
{
  int result=0;
  char **db;
  DBUG_ENTER("dump_databases");

  for (db= db_names ; *db ; db++)
  {
    if (dump_all_tables_in_db(*db))
      result=1;
  }
  if (!result && seen_views)
  {
    for (db= db_names ; *db ; db++)
    {
      if (dump_all_views_in_db(*db))
        result=1;
    }
  }
  DBUG_RETURN(result);
} /* dump_databases */


/*
View Specific database initalization.

SYNOPSIS
  init_dumping_views
  qdatabase      quoted name of the database
  is_mysql_db    TRUE if the db is mysql, else FALSE

RETURN VALUES
  0        Success.
  1        Failure.
*/
int init_dumping_views(char *qdatabase MY_ATTRIBUTE((unused)),
                       my_bool is_mysql_db MY_ATTRIBUTE((unused)))
{
    return 0;
} /* init_dumping_views */


/*
Table Specific database initalization.

SYNOPSIS
  init_dumping_tables
  qdatabase      quoted name of the database
  is_mysql_db    TRUE if the db is mysql, else FALSE

RETURN VALUES
  0        Success.
  1        Failure.
*/

int init_dumping_tables(char *qdatabase, my_bool is_mysql_db)
{
  DBUG_ENTER("init_dumping_tables");

  if (!opt_create_db)
  {
    char qbuf[256];
    MYSQL_ROW row;
    MYSQL_RES *dbinfo;

    my_snprintf(qbuf, sizeof(qbuf),
                "SHOW CREATE DATABASE IF NOT EXISTS %s",
                qdatabase);

    if (mysql_query(mysql, qbuf) || !(dbinfo = mysql_store_result(mysql)))
    {
      /* Old server version, dump generic CREATE DATABASE */
      if (opt_drop_database && (!opt_skip_mysql_schema || !is_mysql_db))
        fprintf(md_result_file,
                "\n/*!40000 DROP DATABASE IF EXISTS %s*/;\n",
                qdatabase);
      fprintf(md_result_file,
              "\nCREATE DATABASE /*!32312 IF NOT EXISTS*/ %s;\n",
              qdatabase);
    }
    else
    {
      if (opt_drop_database && (!opt_skip_mysql_schema || !is_mysql_db))
        fprintf(md_result_file,
                "\n/*!40000 DROP DATABASE IF EXISTS %s*/;\n",
                qdatabase);
      row = mysql_fetch_row(dbinfo);
      if (row[1])
      {
        fprintf(md_result_file,"\n%s;\n",row[1]);
      }
      mysql_free_result(dbinfo);
    }
  }
  DBUG_RETURN(0);
} /* init_dumping_tables */


static int init_dumping(char *database, int init_func(char*, my_bool))
{
  if (is_ndbinfo(mysql, database))
  {
    verbose_msg("-- Skipping dump of ndbinfo database\n");
    return 0;
  }

  if (mysql_select_db(mysql, database))
  {
    DB_error(mysql, "when selecting the database");
    return 1;                   /* If --force */
  }
  if (!path && !opt_xml)
  {
    if (opt_databases || opt_alldbs)
    {
      /*
        length of table name * 2 (if name contains quotes), 2 quotes and 0
      */
      char quoted_database_buf[NAME_LEN*2+3];
      char *qdatabase= quote_name(database,quoted_database_buf,opt_quoted);
      my_bool freemem= FALSE;
      char const* text= fix_identifier_with_newline(qdatabase, &freemem);
      my_bool is_mysql_db= !my_strcasecmp(charset_info, database, "mysql");

      print_comment(md_result_file, 0, "\n--\n-- Current Database: %s\n--\n",
                    text);
      if (freemem)
        my_free((void*)text);

      /* Call the view or table specific function */
      init_func(qdatabase, is_mysql_db);

      fprintf(md_result_file,"\nUSE %s;\n", qdatabase);
      check_io(md_result_file);
    }
  }
  return 0;
} /* init_dumping */


/* Return 1 if we should copy the table */

my_bool include_table(const uchar *hash_key, size_t len)
{
  return ! my_hash_search(&ignore_table, hash_key, len);
}


static int dump_all_tables_in_db(char *database)
{
  char *table;
  uint numrows;
  char table_buff[NAME_LEN*2+3];
  char hash_key[2*NAME_LEN+2];  /* "db.tablename" */
  char *afterdot;
  my_bool general_log_table_exists= 0, slow_log_table_exists=0;
  int using_mysql_db= !my_strcasecmp(charset_info, database, "mysql");
  my_bool real_columns[MAX_FIELDS];

  DBUG_ENTER("dump_all_tables_in_db");

  afterdot= my_stpcpy(hash_key, database);
  *afterdot++= '.';

  if (init_dumping(database, init_dumping_tables))
    DBUG_RETURN(1);
  if (opt_xml)
    print_xml_tag(md_result_file, "", "\n", "database", "name=", database, NullS);

  if (lock_tables)
  {
    DYNAMIC_STRING query;
    init_dynamic_string_checked(&query, "LOCK TABLES ", 256, 1024);
    for (numrows= 0 ; (table= getTableName(1)) ; )
    {
      char *end= my_stpcpy(afterdot, table);
      if (include_table((uchar*) hash_key,end - hash_key))
      {
        numrows++;
        dynstr_append_checked(&query, quote_name(table, table_buff, 1));
        dynstr_append_checked(&query, " READ /*!32311 LOCAL */,");
      }
    }
    if (numrows && mysql_real_query(mysql, query.str, (ulong)(query.length-1)))
      DB_error(mysql, "when using LOCK TABLES");
            /* We shall continue here, if --force was given */
    dynstr_free(&query);
  }
  if (flush_logs)
  {
    if (mysql_refresh(mysql, REFRESH_LOG))
      DB_error(mysql, "when doing refresh");
           /* We shall continue here, if --force was given */
    else
      verbose_msg("-- dump_all_tables_in_db : logs flushed successfully!\n");
  }
  if (opt_single_transaction && mysql_get_server_version(mysql) >= 50500)
  {
    verbose_msg("-- Setting savepoint...\n");
    if (mysql_query_with_error_report(mysql, 0, "SAVEPOINT sp"))
      DBUG_RETURN(1);
  }
  while ((table= getTableName(0)))
  {
    char *end= my_stpcpy(afterdot, table);
    if (include_table((uchar*) hash_key, end - hash_key))
    {
      dump_table(table,database);
      if (opt_dump_triggers && mysql_get_server_version(mysql) >= 50009)
      {
        if (dump_triggers_for_table(table, database))
        {
          if (path)
            my_fclose(md_result_file, MYF(MY_WME));
          maybe_exit(EX_MYSQLERR);
        }
      }

      /**
        ROLLBACK TO SAVEPOINT in --single-transaction mode to release metadata
        lock on table which was already dumped. This allows to avoid blocking
        concurrent DDL on this table without sacrificing correctness, as we
        won't access table second time and dumps created by --single-transaction
        mode have validity point at the start of transaction anyway.
        Note that this doesn't make --single-transaction mode with concurrent
        DDL safe in general case. It just improves situation for people for whom
        it might be working.
      */
      if (opt_single_transaction && mysql_get_server_version(mysql) >= 50500)
      {
        verbose_msg("-- Rolling back to savepoint sp...\n");
        if (mysql_query_with_error_report(mysql, 0, "ROLLBACK TO SAVEPOINT sp"))
          maybe_exit(EX_MYSQLERR);
      }
    }
    else
    {
      /*
        If general_log and slow_log exists in the 'mysql' database,
         we should dump the table structure. But we cannot
         call get_table_structure() here as 'LOCK TABLES' query got executed
         above on the session and that 'LOCK TABLES' query does not contain
         'general_log' and 'slow_log' tables. (you cannot acquire lock
         on log tables). Hence mark the existence of these log tables here and
         after 'UNLOCK TABLES' query is executed on the session, get the table
         structure from server and dump it in the file.
      */
      if (using_mysql_db)
      {
        if (!my_strcasecmp(charset_info, table, "general_log"))
          general_log_table_exists= 1;
        else if (!my_strcasecmp(charset_info, table, "slow_log"))
          slow_log_table_exists= 1;
      }
    }
  }

  if (opt_single_transaction && mysql_get_server_version(mysql) >= 50500)
  {
    verbose_msg("-- Releasing savepoint...\n");
    if (mysql_query_with_error_report(mysql, 0, "RELEASE SAVEPOINT sp"))
      DBUG_RETURN(1);
  }

  if (opt_events && mysql_get_server_version(mysql) >= 50106)
  {
    DBUG_PRINT("info", ("Dumping events for database %s", database));
    dump_events_for_db(database);
  }
  if (opt_routines && mysql_get_server_version(mysql) >= 50009)
  {
    DBUG_PRINT("info", ("Dumping routines for database %s", database));
    dump_routines_for_db(database);
  }
  if (opt_xml)
  {
    fputs("</database>\n", md_result_file);
    check_io(md_result_file);
  }
  if (lock_tables)
    (void) mysql_query_with_error_report(mysql, 0, "UNLOCK TABLES");
  if (using_mysql_db)
  {
    char table_type[NAME_LEN];
    char ignore_flag;
    if (general_log_table_exists)
    {
      if (!get_table_structure((char *) "general_log",
                               database, table_type, &ignore_flag,
                               real_columns))
        verbose_msg("-- Warning: get_table_structure() failed with some internal "
                    "error for 'general_log' table\n");
      if (order_by) {
        my_free(order_by);
        order_by = 0;
      }
    }
    if (slow_log_table_exists)
    {
      if (!get_table_structure((char *) "slow_log",
                               database, table_type, &ignore_flag,
                               real_columns))
        verbose_msg("-- Warning: get_table_structure() failed with some internal "
                    "error for 'slow_log' table\n");
      if (order_by) {
        my_free(order_by);
        order_by = 0;
      }
    }
  }
  if (flush_privileges && using_mysql_db)
  {
    fprintf(md_result_file,"\n--\n-- Flush Grant Tables \n--\n");
    fprintf(md_result_file,"\n/*! FLUSH PRIVILEGES */;\n");
  }
  DBUG_RETURN(0);
} /* dump_all_tables_in_db */


/*
   dump structure of views of database

   SYNOPSIS
     dump_all_views_in_db()
     database  database name

  RETURN
    0 OK
    1 ERROR
*/

static my_bool dump_all_views_in_db(char *database)
{
  char *table;
  uint numrows;
  char table_buff[NAME_LEN*2+3];
  char hash_key[2*NAME_LEN+2];  /* "db.tablename" */
  char *afterdot;

  afterdot= my_stpcpy(hash_key, database);
  *afterdot++= '.';

  if (init_dumping(database, init_dumping_views))
    return 1;
  if (opt_xml)
    print_xml_tag(md_result_file, "", "\n", "database", "name=", database, NullS);
  if (lock_tables)
  {
    DYNAMIC_STRING query;
    init_dynamic_string_checked(&query, "LOCK TABLES ", 256, 1024);
    for (numrows= 0 ; (table= getTableName(1)); )
    {
      char *end= my_stpcpy(afterdot, table);
      if (include_table((uchar*) hash_key,end - hash_key))
      {
        numrows++;
        dynstr_append_checked(&query, quote_name(table, table_buff, 1));
        dynstr_append_checked(&query, " READ /*!32311 LOCAL */,");
      }
    }
    if (numrows && mysql_real_query(mysql, query.str, (ulong)(query.length-1)))
      DB_error(mysql, "when using LOCK TABLES");
            /* We shall continue here, if --force was given */
    dynstr_free(&query);
  }
  if (flush_logs)
  {
    if (mysql_refresh(mysql, REFRESH_LOG))
      DB_error(mysql, "when doing refresh");
           /* We shall continue here, if --force was given */
    else
      verbose_msg("-- dump_all_views_in_db : logs flushed successfully!\n");
  }
  while ((table= getTableName(0)))
  {
    char *end= my_stpcpy(afterdot, table);
    if (include_table((uchar*) hash_key, end - hash_key))
      get_view_structure(table, database);
  }
  if (opt_xml)
  {
    fputs("</database>\n", md_result_file);
    check_io(md_result_file);
  }
  if (lock_tables)
    (void) mysql_query_with_error_report(mysql, 0, "UNLOCK TABLES");
  return 0;
} /* dump_all_tables_in_db */


/*
  get_actual_table_name -- executes a SHOW TABLES LIKE '%s' to get the actual
  table name from the server for the table name given on the command line.
  we do this because the table name given on the command line may be a
  different case (e.g.  T1 vs t1)

  RETURN
    pointer to the table name
    0 if error
*/

static char *get_actual_table_name(const char *old_table_name, MEM_ROOT *root)
{
  char *name= 0;
  MYSQL_RES  *table_res;
  MYSQL_ROW  row;
  char query[50 + 2*NAME_LEN];
  char show_name_buff[FN_REFLEN];
  DBUG_ENTER("get_actual_table_name");

  /* Check memory for quote_for_like() */
  assert(2*sizeof(old_table_name) < sizeof(show_name_buff));
  my_snprintf(query, sizeof(query), "SHOW TABLES LIKE %s",
              quote_for_like(old_table_name, show_name_buff));

  if (mysql_query_with_error_report(mysql, 0, query))
    DBUG_RETURN(NullS);

  if ((table_res= mysql_store_result(mysql)))
  {
    my_ulonglong num_rows= mysql_num_rows(table_res);
    if (num_rows > 0)
    {
      ulong *lengths;
      /*
        Return first row
        TODO: Return all matching rows
      */
      row= mysql_fetch_row(table_res);
      lengths= mysql_fetch_lengths(table_res);
      name= strmake_root(root, row[0], lengths[0]);
    }
    mysql_free_result(table_res);
  }
  DBUG_PRINT("exit", ("new_table_name: %s", name));
  DBUG_RETURN(name);
}


static int dump_selected_tables(char *db, char **table_names, int tables)
{
  char table_buff[NAME_LEN*2+3];
  DYNAMIC_STRING lock_tables_query;
  MEM_ROOT root;
  char **dump_tables, **pos, **end;
  DBUG_ENTER("dump_selected_tables");

  if (init_dumping(db, init_dumping_tables))
    DBUG_RETURN(1);

  init_alloc_root(PSI_NOT_INSTRUMENTED, &root, 8192, 0);
  if (!(dump_tables= pos= (char**) alloc_root(&root, tables * sizeof(char *))))
     die(EX_EOM, "alloc_root failure.");

  init_dynamic_string_checked(&lock_tables_query, "LOCK TABLES ", 256, 1024);
  for (; tables > 0 ; tables-- , table_names++)
  {
    /* the table name passed on commandline may be wrong case */
    if ((*pos= get_actual_table_name(*table_names, &root)))
    {
      /* Add found table name to lock_tables_query */
      if (lock_tables)
      {
        dynstr_append_checked(&lock_tables_query, quote_name(*pos, table_buff, 1));
        dynstr_append_checked(&lock_tables_query, " READ /*!32311 LOCAL */,");
      }
      pos++;
    }
    else
    {
      if (!opt_force)
      {
        dynstr_free(&lock_tables_query);
        free_root(&root, MYF(0));
      }
      maybe_die(EX_ILLEGAL_TABLE, "Couldn't find table: \"%s\"", *table_names);
      /* We shall countinue here, if --force was given */
    }
  }
  end= pos;

  /* Can't LOCK TABLES in I_S / P_S, so don't try. */
  if (lock_tables &&
      !(mysql_get_server_version(mysql) >= FIRST_INFORMATION_SCHEMA_VERSION &&
        !my_strcasecmp(&my_charset_latin1, db, INFORMATION_SCHEMA_DB_NAME)) &&
      !(mysql_get_server_version(mysql) >= FIRST_PERFORMANCE_SCHEMA_VERSION &&
        !my_strcasecmp(&my_charset_latin1, db, PERFORMANCE_SCHEMA_DB_NAME)))
  {
    if (mysql_real_query(mysql, lock_tables_query.str,
                         (ulong)(lock_tables_query.length-1)))
    {
      if (!opt_force)
      {
        dynstr_free(&lock_tables_query);
        free_root(&root, MYF(0));
      }
      DB_error(mysql, "when doing LOCK TABLES");
       /* We shall countinue here, if --force was given */
    }
  }
  dynstr_free(&lock_tables_query);
  if (flush_logs)
  {
    if (mysql_refresh(mysql, REFRESH_LOG))
    {
      if (!opt_force)
        free_root(&root, MYF(0));
      DB_error(mysql, "when doing refresh");
    }
     /* We shall countinue here, if --force was given */
    else
      verbose_msg("-- dump_selected_tables : logs flushed successfully!\n");
  }
  if (opt_xml)
    print_xml_tag(md_result_file, "", "\n", "database", "name=", db, NullS);

  if (opt_single_transaction && mysql_get_server_version(mysql) >= 50500)
  {
    verbose_msg("-- Setting savepoint...\n");
    if (mysql_query_with_error_report(mysql, 0, "SAVEPOINT sp"))
      DBUG_RETURN(1);
  }

  /* Dump each selected table */
  for (pos= dump_tables; pos < end; pos++)
  {
    DBUG_PRINT("info",("Dumping table %s", *pos));
    dump_table(*pos, db);
    if (opt_dump_triggers &&
        mysql_get_server_version(mysql) >= 50009)
    {
      if (dump_triggers_for_table(*pos, db))
      {
        if (path)
          my_fclose(md_result_file, MYF(MY_WME));
        maybe_exit(EX_MYSQLERR);
      }
    }

    /**
      ROLLBACK TO SAVEPOINT in --single-transaction mode to release metadata
      lock on table which was already dumped. This allows to avoid blocking
      concurrent DDL on this table without sacrificing correctness, as we
      won't access table second time and dumps created by --single-transaction
      mode have validity point at the start of transaction anyway.
      Note that this doesn't make --single-transaction mode with concurrent
      DDL safe in general case. It just improves situation for people for whom
      it might be working.
    */
    if (opt_single_transaction && mysql_get_server_version(mysql) >= 50500)
    {
      verbose_msg("-- Rolling back to savepoint sp...\n");
      if (mysql_query_with_error_report(mysql, 0, "ROLLBACK TO SAVEPOINT sp"))
        maybe_exit(EX_MYSQLERR);
    }
  }

  if (opt_single_transaction && mysql_get_server_version(mysql) >= 50500)
  {
    verbose_msg("-- Releasing savepoint...\n");
    if (mysql_query_with_error_report(mysql, 0, "RELEASE SAVEPOINT sp"))
      DBUG_RETURN(1);

  }

  /* Dump each selected view */
  if (seen_views)
  {
    for (pos= dump_tables; pos < end; pos++)
      get_view_structure(*pos, db);
  }
  if (opt_events && mysql_get_server_version(mysql) >= 50106)
  {
    DBUG_PRINT("info", ("Dumping events for database %s", db));
    dump_events_for_db(db);
  }
  /* obtain dump of routines (procs/functions) */
  if (opt_routines && mysql_get_server_version(mysql) >= 50009)
  {
    DBUG_PRINT("info", ("Dumping routines for database %s", db));
    dump_routines_for_db(db);
  }
  free_root(&root, MYF(0));
  if (opt_xml)
  {
    fputs("</database>\n", md_result_file);
    check_io(md_result_file);
  }
  if (lock_tables)
    (void) mysql_query_with_error_report(mysql, 0, "UNLOCK TABLES");
  DBUG_RETURN(0);
} /* dump_selected_tables */


static int do_show_master_status(MYSQL *mysql_con, int consistent_binlog_pos)
{
  MYSQL_ROW row;
  MYSQL_RES *master;
  char binlog_pos_file[FN_REFLEN];
  char binlog_pos_offset[LONGLONG_LEN+1];
  char *file, *offset;
  const char *comment_prefix=
    (opt_master_data == MYSQL_OPT_MASTER_DATA_COMMENTED_SQL) ? "-- " : "";

  if (consistent_binlog_pos)
  {
    if (!check_consistent_binlog_pos(binlog_pos_file, binlog_pos_offset))
      return 1;

    file= binlog_pos_file;
    offset= binlog_pos_offset;
  }
  else
  {
    if (mysql_query_with_error_report(mysql_con, &master, "SHOW MASTER STATUS"))
      return 1;

    row= mysql_fetch_row(master);
    if (row && row[0] && row[1])
    {
      file= row[0];
      offset= row[1];
    }
    else
    {
      mysql_free_result(master);
      if (!opt_force)
      {
        /* SHOW MASTER STATUS reports nothing and --force is not enabled */
        my_printf_error(0, "Error: Binlogging on server not active", MYF(0));
        maybe_exit(EX_MYSQLERR);
        return 1;
      }
      else
      {
        return 0;
      }
    }
  }

  /* SHOW MASTER STATUS reports file and position */
  print_comment(md_result_file, 0,
                "\n--\n-- Position to start replication or point-in-time "
                "recovery from\n--\n\n");
  fprintf(md_result_file,
          "%sCHANGE MASTER TO MASTER_LOG_FILE='%s', MASTER_LOG_POS=%s;\n",
          comment_prefix, file, offset);
  check_io(md_result_file);

  if (!consistent_binlog_pos)
    mysql_free_result(master);

  return 0;
}

static int do_stop_slave_sql(MYSQL *mysql_con)
{
  MYSQL_RES *slave;
  /* We need to check if the slave sql is running in the first place */
  if (mysql_query_with_error_report(mysql_con, &slave, "SHOW SLAVE STATUS"))
    return(1);
  else
  {
    MYSQL_ROW row= mysql_fetch_row(slave);
    if (row && row[11])
    {
      /* if SLAVE SQL is not running, we don't stop it */
      if (!strcmp(row[11],"No"))
      {
        mysql_free_result(slave);
        /* Silently assume that they don't have the slave running */
        return(0);
      }
    }
  }
  mysql_free_result(slave);

  /* now, stop slave if running */
  if (mysql_query_with_error_report(mysql_con, 0, "STOP SLAVE SQL_THREAD"))
    return(1);

  return(0);
}

static int add_stop_slave(void)
{
  if (opt_comments)
    fprintf(md_result_file,
            "\n--\n-- stop slave statement to make a recovery dump)\n--\n\n");
  fprintf(md_result_file, "STOP SLAVE;\n");
  return(0);
}

static int add_slave_statements(void)
{
  if (opt_comments)
    fprintf(md_result_file,
            "\n--\n-- start slave statement to make a recovery dump)\n--\n\n");
  fprintf(md_result_file, "START SLAVE;\n");
  return(0);
}

static int do_show_slave_status(MYSQL *mysql_con)
{
  MYSQL_RES *slave= NULL;
  const char *comment_prefix=
    (opt_slave_data == MYSQL_OPT_SLAVE_DATA_COMMENTED_SQL) ? "-- " : "";
  if (mysql_query_with_error_report(mysql_con, &slave, "SHOW SLAVE STATUS"))
  {
    if (!opt_force)
    {
      /* SHOW SLAVE STATUS reports nothing and --force is not enabled */
      my_printf_error(0, "Error: Slave not set up", MYF(0));
    }
    mysql_free_result(slave);
    return 1;
  }
  else
  {
    const int n_master_host= 1;
    const int n_master_port= 3;
    const int n_master_log_file= 9;
    const int n_master_log_pos= 21;
    const int n_channel_name= 55;
    MYSQL_ROW row= mysql_fetch_row(slave);
    /* Since 5.7 is is possible that SSS returns multiple channels */
    while (row)
    {
      if (row[n_master_log_file] && row[n_master_log_pos])
      {
        /* SHOW MASTER STATUS reports file and position */
        if (opt_comments)
          fprintf(md_result_file,
                  "\n--\n-- Position to start replication or point-in-time "
                  "recovery from (the master of this slave)\n--\n\n");

        fprintf(md_result_file, "%sCHANGE MASTER TO ", comment_prefix);

        if (opt_include_master_host_port)
        {
          if (row[n_master_host])
            fprintf(md_result_file, "MASTER_HOST='%s', ", row[n_master_host]);
          if (row[n_master_port])
            fprintf(md_result_file, "MASTER_PORT=%s, ", row[n_master_port]);
        }
        fprintf(md_result_file,
                "MASTER_LOG_FILE='%s', MASTER_LOG_POS=%s",
                row[n_master_log_file], row[n_master_log_pos]);

        /* Only print the FOR CHANNEL if there is more than one channel */
        if (slave->row_count > 1)
          fprintf(md_result_file, " FOR CHANNEL '%s'", row[n_channel_name]);

        fprintf(md_result_file, ";\n");
      }
      row= mysql_fetch_row(slave);
    }
    check_io(md_result_file);
    mysql_free_result(slave);
  }
  return 0;
}

static int do_start_slave_sql(MYSQL *mysql_con)
{
  MYSQL_RES *slave;
  /* We need to check if the slave sql is stopped in the first place */
  if (mysql_query_with_error_report(mysql_con, &slave, "SHOW SLAVE STATUS"))
    return(1);
  else
  {
    MYSQL_ROW row= mysql_fetch_row(slave);
    if (row && row[11])
    {
      /* if SLAVE SQL is not running, we don't start it */
      if (!strcmp(row[11],"Yes"))
      {
        mysql_free_result(slave);
        /* Silently assume that they don't have the slave running */
        return(0);
      }
    }
  }
  mysql_free_result(slave);

  /* now, start slave if stopped */
  if (mysql_query_with_error_report(mysql_con, 0, "START SLAVE"))
  {
    my_printf_error(0, "Error: Unable to start slave", MYF(0));
    return 1;
  }
  return(0);
}



static int do_flush_tables_read_lock(MYSQL *mysql_con)
{
  /*
    We do first a FLUSH TABLES. If a long update is running, the FLUSH TABLES
    will wait but will not stall the whole mysqld, and when the long update is
    done the FLUSH TABLES WITH READ LOCK will start and succeed quickly. So,
    FLUSH TABLES is to lower the probability of a stage where both mysqldump
    and most client connections are stalled. Of course, if a second long
    update starts between the two FLUSHes, we have that bad stall.
  */
  return
    ( mysql_query_with_error_report(mysql_con, 0, 
                                    ((opt_master_data != 0) ? 
                                        "FLUSH /*!40101 LOCAL */ TABLES" : 
                                        "FLUSH TABLES")) ||
      mysql_query_with_error_report(mysql_con, 0,
                                    "FLUSH TABLES WITH READ LOCK") );
}

/**
   Execute LOCK TABLES FOR BACKUP if supported by the server.

   @note If LOCK TABLES FOR BACKUP is not supported by the server, then nothing
         is done and no error condition is returned.

   @returns  whether there was an error or not
*/

static int do_lock_tables_for_backup(MYSQL *mysql_con)
{
  return mysql_query_with_error_report(mysql_con, 0,
                                       "LOCK TABLES FOR BACKUP");
}

static int do_unlock_tables(MYSQL *mysql_con)
{
  return mysql_query_with_error_report(mysql_con, 0, "UNLOCK TABLES");
}

static int get_bin_log_name(MYSQL *mysql_con,
                            char* buff_log_name, uint buff_len)
{
  MYSQL_RES *res;
  MYSQL_ROW row;

  if (mysql_query(mysql_con, "SHOW MASTER STATUS") ||
      !(res= mysql_store_result(mysql)))
    return 1;

  if (!(row= mysql_fetch_row(res)))
  {
    mysql_free_result(res);
    return 1;
  }
  /*
    Only one row is returned, and the first column is the name of the
    active log.
  */
  strmake(buff_log_name, row[0], buff_len - 1);

  mysql_free_result(res);
  return 0;
}

static int purge_bin_logs_to(MYSQL *mysql_con, char* log_name)
{
  DYNAMIC_STRING str;
  int err;
  init_dynamic_string_checked(&str, "PURGE BINARY LOGS TO '", 1024, 1024);
  dynstr_append_checked(&str, log_name);
  dynstr_append_checked(&str, "'");
  err = mysql_query_with_error_report(mysql_con, 0, str.str);
  dynstr_free(&str);
  return err;
}


static int start_transaction(MYSQL *mysql_con)
{
  verbose_msg("-- Starting transaction...\n");
  /*
    We use BEGIN for old servers. --single-transaction --master-data will fail
    on old servers, but that's ok as it was already silently broken (it didn't
    do a consistent read, so better tell people frankly, with the error).

    We want the first consistent read to be used for all tables to dump so we
    need the REPEATABLE READ level (not anything lower, for example READ
    COMMITTED would give one new consistent read per dumped table).
  */
  if ((mysql_get_server_version(mysql_con) < 40100) && opt_master_data)
  {
    fprintf(stderr, "-- %s: the combination of --single-transaction and "
            "--master-data requires a MySQL server version of at least 4.1 "
            "(current server's version is %s). %s\n",
            opt_force ? "Warning" : "Error",
            mysql_con->server_version ? mysql_con->server_version : "unknown",
            opt_force ? "Continuing due to --force, backup may not be "
            "consistent across all tables!" : "Aborting.");
    if (!opt_force)
      exit(EX_MYSQLERR);
  }

  return (mysql_query_with_error_report(mysql_con, 0,
                                        "SET SESSION TRANSACTION ISOLATION "
                                        "LEVEL REPEATABLE READ") ||
          mysql_query_with_error_report(mysql_con, 0,
                                        "START TRANSACTION "
                                        "/*!40100 WITH CONSISTENT SNAPSHOT */"));
}


static ulong find_set(TYPELIB *lib, const char *x, size_t length,
                      char **err_pos, uint *err_len)
{
  const char *end= x + length;
  ulong found= 0;
  uint find;
  char buff[255];

  *err_pos= 0;                  /* No error yet */
  while (end > x && my_isspace(charset_info, end[-1]))
    end--;

  *err_len= 0;
  if (x != end)
  {
    const char *start= x;
    for (;;)
    {
      const char *pos= start;
      uint var_len;

      for (; pos != end && *pos != ','; pos++) ;
      var_len= (uint) (pos - start);
      strmake(buff, start, MY_MIN(sizeof(buff) - 1, var_len));
      find= find_type(buff, lib, FIND_TYPE_BASIC);
      if (!find)
      {
        *err_pos= (char*) start;
        *err_len= var_len;
      }
      else
        found|= ((longlong) 1 << (find - 1));
      if (pos == end)
        break;
      start= pos + 1;
    }
  }
  return found;
}


/* Print a value with a prefix on file */
static void print_value(FILE *file, MYSQL_RES  *result, MYSQL_ROW row,
                        const char *prefix, const char *name,
                        int string_value)
{
  MYSQL_FIELD   *field;
  mysql_field_seek(result, 0);

  for ( ; (field= mysql_fetch_field(result)) ; row++)
  {
    if (!strcmp(field->name,name))
    {
      if (row[0] && row[0][0] && strcmp(row[0],"0")) /* Skip default */
      {
        fputc(' ',file);
        fputs(prefix, file);
        if (string_value)
          unescape(file,row[0], strlen(row[0]));
        else
          fputs(row[0], file);
        check_io(file);
        return;
      }
    }
  }
  return;                                       /* This shouldn't happen */
} /* print_value */


/*
  SYNOPSIS

  Check if the table is one of the table types that should be ignored:
  MRG_ISAM, MRG_MYISAM.

  If the table should be altogether ignored, it returns a TRUE, FALSE if it
  should not be ignored.

  ARGS

    check_if_ignore_table()
    table_name                  Table name to check
    table_type                  Type of table

  GLOBAL VARIABLES
    mysql                       MySQL connection
    verbose                     Write warning messages

  RETURN
    char (bit value)            See IGNORE_ values at top
*/

char check_if_ignore_table(const char *table_name, char *table_type)
{
  char result= IGNORE_NONE;
  char buff[FN_REFLEN+80], show_name_buff[FN_REFLEN];
  MYSQL_RES *res= NULL;
  MYSQL_ROW row;
  DBUG_ENTER("check_if_ignore_table");

  /* Check memory for quote_for_like() */
  assert(2*sizeof(table_name) < sizeof(show_name_buff));
  my_snprintf(buff, sizeof(buff), "show table status like %s",
              quote_for_like(table_name, show_name_buff));
  if (mysql_query_with_error_report(mysql, &res, buff))
  {
    if (mysql_errno(mysql) != ER_PARSE_ERROR)
    {                                   /* If old MySQL version */
      verbose_msg("-- Warning: Couldn't get status information for "
                  "table %s (%s)\n", table_name, mysql_error(mysql));
      DBUG_RETURN(result);                       /* assume table is ok */
    }
  }
  if (!(row= mysql_fetch_row(res)))
  {
    fprintf(stderr,
            "Error: Couldn't read status information for table %s (%s)\n",
            table_name, mysql_error(mysql));
    mysql_free_result(res);
    DBUG_RETURN(result);                         /* assume table is ok */
  }
  if (!(row[1]))
    strmake(table_type, "VIEW", NAME_LEN-1);
  else
  {
    strmake(table_type, row[1], NAME_LEN-1);

    /*  If these two types, we want to skip dumping the table. */
    if (!opt_no_data &&
        (!my_strcasecmp(&my_charset_latin1, table_type, "MRG_MyISAM") ||
         !strcmp(table_type,"MRG_ISAM") ||
         !strcmp(table_type,"FEDERATED")))
      result= IGNORE_DATA;
  }
  mysql_free_result(res);
  DBUG_RETURN(result);
}


/*
  Get string of comma-separated primary key field names

  SYNOPSIS
    char *primary_key_fields(const char *table_name)
    RETURNS     pointer to allocated buffer (must be freed by caller)
    table_name  quoted table name

  DESCRIPTION
    Use SHOW KEYS FROM table_name, allocate a buffer to hold the
    field names, and then build that string and return the pointer
    to that buffer.

    Returns NULL if there is no PRIMARY or UNIQUE key on the table,
    or if there is some failure.  It is better to continue to dump
    the table unsorted, rather than exit without dumping the data.
*/

static char *primary_key_fields(const char *table_name, const my_bool desc)
{
  MYSQL_RES  *res= NULL;
  MYSQL_ROW  row;
  /* SHOW KEYS FROM + table name * 2 (escaped) + 2 quotes + \0 */
  char show_keys_buff[15 + NAME_LEN * 2 + 3];
  size_t result_length= 0;
  char *result= 0;
  char buff[NAME_LEN * 2 + 3];
  char *quoted_field;
  static const char *desc_index= " DESC";

  my_snprintf(show_keys_buff, sizeof(show_keys_buff),
              "SHOW KEYS FROM %s", table_name);
  if (mysql_query(mysql, show_keys_buff) ||
      !(res= mysql_store_result(mysql)))
  {
    fprintf(stderr, "Warning: Couldn't read keys from table %s;"
            " records are NOT sorted (%s)\n",
            table_name, mysql_error(mysql));
    /* Don't exit, because it's better to print out unsorted records */
    goto cleanup;
  }

  /*
   * Figure out the length of the ORDER BY clause result.
   * Note that SHOW KEYS is ordered:  a PRIMARY key is always the first
   * row, and UNIQUE keys come before others.  So we only need to check
   * the first key, not all keys.
   */
  if ((row= mysql_fetch_row(res)) && atoi(row[1]) == 0)
  {
    /* Key is unique */
    do
    {
      quoted_field= quote_name(row[4], buff, 0);
      result_length+= strlen(quoted_field) + 1; /* + 1 for ',' or \0 */
      if (desc)
      {
        result_length+= strlen(desc_index);
      }
    } while ((row= mysql_fetch_row(res)) && atoi(row[3]) > 1);
  }

  /* Build the ORDER BY clause result */
  if (result_length)
  {
    char *end;
    /* result (terminating \0 is already in result_length) */
    result= my_malloc(PSI_NOT_INSTRUMENTED,
                      result_length + 10, MYF(MY_WME));
    if (!result)
    {
      fprintf(stderr, "Error: Not enough memory to store ORDER BY clause\n");
      goto cleanup;
    }
    mysql_data_seek(res, 0);
    row= mysql_fetch_row(res);
    quoted_field= quote_name(row[4], buff, 0);
    end= my_stpcpy(result, quoted_field);
    while ((row= mysql_fetch_row(res)) && atoi(row[3]) > 1)
    {
      quoted_field= quote_name(row[4], buff, 0);
      end= strxmov(end, desc ? " DESC," : ",", quoted_field, NullS);
    }
    if (desc)
    {
      end= my_stpmov(end, " DESC");
    }
  }

cleanup:
  if (res)
    mysql_free_result(res);

  return result;
}


/*
  Replace a substring

  SYNOPSIS
    replace
    ds_str      The string to search and perform the replace in
    search_str  The string to search for
    search_len  Length of the string to search for
    replace_str The string to replace with
    replace_len Length of the string to replace with

  RETURN
    0 String replaced
    1 Could not find search_str in str
*/

static int replace(DYNAMIC_STRING *ds_str,
                   const char *search_str, size_t search_len,
                   const char *replace_str, size_t replace_len)
{
  DYNAMIC_STRING ds_tmp;
  const char *start= strstr(ds_str->str, search_str);
  if (!start)
    return 1;
  init_dynamic_string_checked(&ds_tmp, "",
                      ds_str->length + replace_len, 256);
  dynstr_append_mem_checked(&ds_tmp, ds_str->str, start - ds_str->str);
  dynstr_append_mem_checked(&ds_tmp, replace_str, replace_len);
  dynstr_append_checked(&ds_tmp, start + search_len);
  dynstr_set_checked(ds_str, ds_tmp.str);
  dynstr_free(&ds_tmp);
  return 0;
}


/**
  This function sets the session binlog in the dump file.
  When --set-gtid-purged is used, this function is called to
  disable the session binlog and at the end of the dump, to restore
  the session binlog.

  @note: md_result_file should have been opened, before
         this function is called.
*/

static void set_session_binlog()
{
  static my_bool is_binlog_disabled= FALSE;

  if (!is_binlog_disabled)
  {
    fprintf(md_result_file,
            "SET @MYSQLDUMP_TEMP_LOG_BIN = @@SESSION.SQL_LOG_BIN;\n");
    fprintf(md_result_file, "SET @@SESSION.SQL_LOG_BIN= 0;\n");
    is_binlog_disabled= 1;
  }
  else
  {
    fprintf(md_result_file,
            "SET @@SESSION.SQL_LOG_BIN = @MYSQLDUMP_TEMP_LOG_BIN;\n");
    is_binlog_disabled= 0;
  }
}


/**
  This function gets the GTID_EXECUTED sets from the
  server and assigns those sets to GTID_PURGED in the
  dump file.

  @param[in]  mysql_con     connection to the server
  @param[in]  ftwrl_done    FLUSH TABLES WITH READ LOCK query was issued

  @retval     FALSE         succesfully printed GTID_PURGED sets
                             in the dump file.
  @retval     TRUE          failed.

*/

static my_bool add_set_gtid_purged(MYSQL *mysql_con, my_bool ftwrl_done)
{
  MYSQL_RES* gtid_purged_res;
  MYSQL_ROW  gtid_set;
  ulonglong  num_sets, idx;
  int        value_idx= 1;
  int        capture_raw_gtid_executed= TRUE;
  char       gtid_buffer[128];
  /*
   Check if we didn't already acquire FTWRL
   and we are in transaction with consistent snapshot.
   If we are, and snapshot of gtid_executed is supported by server - use it.
  */
  if (!ftwrl_done && opt_single_transaction)
  {
    if (!consistent_gtid_executed_supported(mysql_con) ||
        mysql_query_with_error_report(
            mysql_con, &gtid_purged_res,
            "SHOW STATUS LIKE 'Binlog_snapshot_gtid_executed'"))
    {
      fprintf(stderr,
              "\nWARNING: Server does not support consistent snapshot of "
              "GTID_EXECUTED."
              "\nThe value provided for GTID_PURGED may be inaccurate!"
              "\nTo overcome this issue, start mysqldump with "
              "--lock-all-tables.\n");

      fprintf(md_result_file,
              "\n\n--"
              "\n-- WARNING: Server does not support consistent snapshot of "
              "GTID_EXECUTED."
              "\n-- The value provided for GTID_PURGED may be inaccurate!"
              "\n-- To overcome this issue, start mysqldump with "
              "--lock-all-tables."
              "\n--\n");
    }
    else
    {
      capture_raw_gtid_executed= FALSE;
    }
  }

  if (capture_raw_gtid_executed)
  {
    /* query to get the GTID_EXECUTED */
    value_idx= 0;
    if (mysql_query_with_error_report(mysql_con, &gtid_purged_res,
                                      "SELECT @@GLOBAL.GTID_EXECUTED"))
    {
      return TRUE;
    }
  }

  /* Proceed only if gtid_purged_res is non empty */
  if ((num_sets= mysql_num_rows(gtid_purged_res)) > 0)
  {
    gtid_executed_buffer_inited= 1;
    init_dynamic_string_checked(&gtid_executed_buffer, "", 1024, 1024);
    if (opt_comments)
    {
      my_snprintf(gtid_buffer, 128,
              "\n--\n-- GTID state at the end of the backup"
              "\n-- (origin: %s)"
              "\n--\n\n",
              capture_raw_gtid_executed ? "@@global.gtid_executed"
                                        : "Binlog_snapshot_gtid_executed");
      dynstr_append_checked(&gtid_executed_buffer, gtid_buffer);
    }

    dynstr_append_checked(&gtid_executed_buffer, "SET @@GLOBAL.GTID_PURGED='");

    /* formatting is not required, even for multiple gtid sets */
    for(idx = 0 ; idx < num_sets ; idx++)
    {
      gtid_set= mysql_fetch_row(gtid_purged_res);
      dynstr_append_checked(&gtid_executed_buffer, (char *)gtid_set[value_idx]);
    }
    /* for the last set close the SET expression */
    dynstr_append_checked(&gtid_executed_buffer, "';\n");
  }
  mysql_free_result(gtid_purged_res);

  return FALSE;  /*success */
}


/**
  This function processes the opt_set_gtid_purged option.
  This function when called with the flag as FALSE, just
  disables the binlog by calling set_session_binlog().
  Later when this function is called with the flag as TRUE,
  SET @@GLOBAL.GTID_PURGED is written in the output and the
  session binlog is restored if disabled previously.

  @param[in]          mysql_con     the connection to the server
  @param[in]          ftwrl_done    FLUSH TABLES WITH READ LOCK query was issued
  @param[in]          flag          If FALSE, just disable binlog and not
                                    set the gtid purged as it will be set
                                    at a later point of time.
                                    If TRUE, set the gtid purged and
                                    restore the session binlog if disabled
                                    previously.

  @retval             FALSE         successful according to the value
                                    of opt_set_gtid_purged.
  @retval             TRUE          fail.
*/

static my_bool process_set_gtid_purged(MYSQL* mysql_con, my_bool ftwrl_done,
                                       my_bool flag)
{
  MYSQL_RES   *gtid_mode_res;
  MYSQL_ROW   gtid_mode_row;
  char *gtid_mode_val= 0;
  static int  gtid_mode= -1;
  char buf[32], query[64];

  if (opt_set_gtid_purged_mode == SET_GTID_PURGED_OFF)
    return FALSE;  /* nothing to be done */

  /*
     Set gtid_mode, by fetching gtid_mode from server, if its not
     yet populated. gtid_mode is set to -1 if gtid_mode is not yet
     fetched from the server.
  */
  if (gtid_mode < 0)
  {
    /*
      Check if the server has the knowledge of GTIDs(pre mysql-5.6)
      or if the gtid_mode is ON or OFF.
    */
    my_snprintf(query, sizeof(query), "SHOW VARIABLES LIKE %s",
                quote_for_like("gtid_mode", buf));

    if (mysql_query_with_error_report(mysql_con, &gtid_mode_res, query))
      return TRUE;

    gtid_mode_row = mysql_fetch_row(gtid_mode_res);

    /*
       gtid_mode_row is NULL for pre 5.6 versions. For versions >= 5.6,
       get the gtid_mode value from the second column.
    */
    gtid_mode_val = gtid_mode_row ? (char*)gtid_mode_row[1] : NULL;
    gtid_mode= (gtid_mode_val && strcmp(gtid_mode_val, "OFF")) ? 1 : 0;
    mysql_free_result(gtid_mode_res);
  }

  if (gtid_mode)
  {
    /*
       For any gtid_mode !=OFF and irrespective of --set-gtid-purged
       being AUTO or ON,  add GTID_PURGED in the output.
    */
    if (!flag)
    {
      set_session_binlog();
      if (add_set_gtid_purged(mysql_con, ftwrl_done))
        return TRUE;
    }

    else
    {
      if (flag && (opt_databases || !opt_alldbs || !opt_dump_triggers
          || !opt_routines || !opt_events))
      {
        fprintf(stderr,"Warning: A partial dump from a server that has GTIDs will "
                       "by default include the GTIDs of all transactions, even "
                       "those that changed suppressed parts of the database. If "
                       "you don't want to restore GTIDs, pass "
                       "--set-gtid-purged=OFF. To make a complete dump, pass "
                       "--all-databases --triggers --routines --events. \n");
      }

      fputs(gtid_executed_buffer.str, md_result_file);
    }
  }
  else /* gtid_mode is off */
  {
    if (flag && opt_set_gtid_purged_mode == SET_GTID_PURGED_ON)
    {
      fprintf(stderr, "Error: Server has GTIDs disabled.\n");
      return TRUE;
    }
  }

  return FALSE;
}


/*
  Getting VIEW structure

  SYNOPSIS
    get_view_structure()
    table   view name
    db      db name

  RETURN
    0 OK
    1 ERROR
*/

static my_bool get_view_structure(char *table, char* db)
{
  MYSQL_RES  *table_res;
  MYSQL_ROW  row;
  MYSQL_FIELD *field;
  char       *result_table, *opt_quoted_table;
  char       table_buff[NAME_LEN*2+3];
  char       table_buff2[NAME_LEN*2+3];
  char       query[QUERY_LENGTH];
  FILE       *sql_file= md_result_file;
  my_bool    freemem= FALSE;
  char const *text;
  DBUG_ENTER("get_view_structure");

  if (opt_no_create_info) /* Don't write table creation info */
    DBUG_RETURN(0);

  verbose_msg("-- Retrieving view structure for table %s...\n", table);

  result_table=     quote_name(table, table_buff, 1);
  opt_quoted_table= quote_name(table, table_buff2, 0);

  if (switch_character_set_results(mysql, "binary"))
    DBUG_RETURN(1);

  my_snprintf(query, sizeof(query), "SHOW CREATE TABLE %s", result_table);

  if (mysql_query_with_error_report(mysql, &table_res, query))
  {
    switch_character_set_results(mysql, default_charset);
    DBUG_RETURN(0);
  }

  /* Check if this is a view */
  field= mysql_fetch_field_direct(table_res, 0);
  if (strcmp(field->name, "View") != 0)
  {
    switch_character_set_results(mysql, default_charset);
    verbose_msg("-- It's base table, skipped\n");
    mysql_free_result(table_res);
    DBUG_RETURN(0);
  }

  /* If requested, open separate .sql file for this view */
  if (path)
  {
    if (!(sql_file= open_sql_file_for_table(table, O_WRONLY)))
    {
      mysql_free_result(table_res);
      DBUG_RETURN(1);
    }

    write_header(sql_file, db);
  }

  text= fix_identifier_with_newline(result_table, &freemem);
  print_comment(sql_file, 0,
                "\n--\n-- Final view structure for view %s\n--\n\n", text);
  if (freemem)
    my_free((void*)text);

  verbose_msg("-- Dropping the temporary view structure created\n");
  fprintf(sql_file, "/*!50001 DROP VIEW IF EXISTS %s*/;\n", opt_quoted_table);

  my_snprintf(query, sizeof(query),
              "SELECT CHECK_OPTION, DEFINER, SECURITY_TYPE, "
              "       CHARACTER_SET_CLIENT, COLLATION_CONNECTION "
              "FROM information_schema.views "
              "WHERE table_name=\"%s\" AND table_schema=\"%s\"", table, db);

  if (mysql_query(mysql, query))
  {
    /*
      Use the raw output from SHOW CREATE TABLE if
       information_schema query fails.
     */
    row= mysql_fetch_row(table_res);
    fprintf(sql_file, "/*!50001 %s */;\n", row[1]);
    check_io(sql_file);
    mysql_free_result(table_res);
  }
  else
  {
    char *ptr;
    ulong *lengths;
    char search_buf[256], replace_buf[256];
    ulong search_len, replace_len;
    DYNAMIC_STRING ds_view;

    /* Save the result of SHOW CREATE TABLE in ds_view */
    row= mysql_fetch_row(table_res);
    lengths= mysql_fetch_lengths(table_res);
    init_dynamic_string_checked(&ds_view, row[1], lengths[1] + 1, 1024);
    mysql_free_result(table_res);

    /* Get the result from "select ... information_schema" */
    if (!(table_res= mysql_store_result(mysql)) ||
        !(row= mysql_fetch_row(table_res)))
    {
      if (table_res)
        mysql_free_result(table_res);
      dynstr_free(&ds_view);
      DB_error(mysql, "when trying to save the result of SHOW CREATE TABLE in ds_view.");
      DBUG_RETURN(1);
    }

    lengths= mysql_fetch_lengths(table_res);

    /*
      "WITH %s CHECK OPTION" is available from 5.0.2
      Surround it with !50002 comments
    */
    if (strcmp(row[0], "NONE"))
    {

      ptr= search_buf;
      search_len= (ulong)(strxmov(ptr, "WITH ", row[0],
                                  " CHECK OPTION", NullS) - ptr);
      ptr= replace_buf;
      replace_len=(ulong)(strxmov(ptr, "*/\n/*!50002 WITH ", row[0],
                                  " CHECK OPTION", NullS) - ptr);
      replace(&ds_view, search_buf, search_len, replace_buf, replace_len);
    }

    /*
      "DEFINER=%s SQL SECURITY %s" is available from 5.0.13
      Surround it with !50013 comments
    */
    {
      size_t     user_name_len;
      char       user_name_str[USERNAME_LENGTH + 1];
      char       quoted_user_name_str[USERNAME_LENGTH * 2 + 3];
      size_t     host_name_len;
      char       host_name_str[HOSTNAME_LENGTH + 1];
      char       quoted_host_name_str[HOSTNAME_LENGTH * 2 + 3];

      parse_user(row[1], lengths[1], user_name_str, &user_name_len,
                 host_name_str, &host_name_len);

      ptr= search_buf;
      search_len=
        (ulong)(strxmov(ptr, "DEFINER=",
                        quote_name(user_name_str, quoted_user_name_str, FALSE),
                        "@",
                        quote_name(host_name_str, quoted_host_name_str, FALSE),
                        " SQL SECURITY ", row[2], NullS) - ptr);
      ptr= replace_buf;
      replace_len=
        (ulong)(strxmov(ptr, "*/\n/*!50013 DEFINER=",
                        quote_name(user_name_str, quoted_user_name_str, FALSE),
                        "@",
                        quote_name(host_name_str, quoted_host_name_str, FALSE),
                        " SQL SECURITY ", row[2],
                        " */\n/*!50001", NullS) - ptr);
      replace(&ds_view, search_buf, search_len, replace_buf, replace_len);
    }

    /* Dump view structure to file */

    fprintf(sql_file,
            "/*!50001 SET @saved_cs_client          = @@character_set_client */;\n"
            "/*!50001 SET @saved_cs_results         = @@character_set_results */;\n"
            "/*!50001 SET @saved_col_connection     = @@collation_connection */;\n"
            "/*!50001 SET character_set_client      = %s */;\n"
            "/*!50001 SET character_set_results     = %s */;\n"
            "/*!50001 SET collation_connection      = %s */;\n"
            "/*!50001 %s */;\n"
            "/*!50001 SET character_set_client      = @saved_cs_client */;\n"
            "/*!50001 SET character_set_results     = @saved_cs_results */;\n"
            "/*!50001 SET collation_connection      = @saved_col_connection */;\n",
            (const char *) row[3],
            (const char *) row[3],
            (const char *) row[4],
            (const char *) ds_view.str);

    check_io(sql_file);
    mysql_free_result(table_res);
    dynstr_free(&ds_view);
  }

  if (switch_character_set_results(mysql, default_charset))
    DBUG_RETURN(1);

  /* If a separate .sql file was opened, close it now */
  if (sql_file != md_result_file)
  {
    fputs("\n", sql_file);
    write_footer(sql_file);
    my_fclose(sql_file, MYF(MY_WME));
  }
  DBUG_RETURN(0);
}

/*
  The following functions are wrappers for the dynamic string functions
  and if they fail, the wrappers will terminate the current process.
*/

#define DYNAMIC_STR_ERROR_MSG "Couldn't perform DYNAMIC_STRING operation"

static void init_dynamic_string_checked(DYNAMIC_STRING *str, const char *init_str,
			    size_t init_alloc, size_t alloc_increment)
{
  if (init_dynamic_string(str, init_str, init_alloc, alloc_increment))
    die(EX_MYSQLERR, DYNAMIC_STR_ERROR_MSG);
}

static void dynstr_append_checked(DYNAMIC_STRING* dest, const char* src)
{
  if (dynstr_append(dest, src))
    die(EX_MYSQLERR, DYNAMIC_STR_ERROR_MSG);
}

static void dynstr_set_checked(DYNAMIC_STRING *str, const char *init_str)
{
  if (dynstr_set(str, init_str))
    die(EX_MYSQLERR, DYNAMIC_STR_ERROR_MSG);
}

static void dynstr_append_mem_checked(DYNAMIC_STRING *str, const char *append,
			  size_t length)
{
  if (dynstr_append_mem(str, append, length))
    die(EX_MYSQLERR, DYNAMIC_STR_ERROR_MSG);
}

static void dynstr_realloc_checked(DYNAMIC_STRING *str, size_t additional_size)
{
  if (dynstr_realloc(str, additional_size))
    die(EX_MYSQLERR, DYNAMIC_STR_ERROR_MSG);
}

static my_bool has_session_variables_like(MYSQL *mysql_con, const char *var_name)
{
  MYSQL_RES  *res;
  MYSQL_ROW  row;
  char       *val= 0;
  char       buf[32], query[256];
  my_bool    has_var= FALSE;
  my_bool    has_table= FALSE;

  my_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM"
              " INFORMATION_SCHEMA.TABLES WHERE table_schema ="
              " 'performance_schema' AND table_name = 'session_variables'");
  if (mysql_query_with_error_report(mysql_con, &res, query))
    return FALSE;

  row = mysql_fetch_row(res);
  val = row ? (char*)row[0] : NULL;
  has_table = val && strcmp(val, "0") != 0;
  mysql_free_result(res);

  if (has_table)
  {
    my_snprintf(query, sizeof(query), "SELECT COUNT(*) FROM"
                " performance_schema.session_variables WHERE VARIABLE_NAME LIKE"
                " %s", quote_for_like(var_name, buf));
    if (mysql_query_with_error_report(mysql_con, &res, query))
      return FALSE;

    row = mysql_fetch_row(res);
    val = row ? (char*)row[0] : NULL;
    has_var = val && strcmp(val, "0") != 0;
    mysql_free_result(res);
  }

  return has_var;
}

/**
   Check if the server supports LOCK TABLES FOR BACKUP.

   @returns  TRUE if there is support, FALSE otherwise.
*/

static my_bool server_supports_backup_locks(void)
{
  MYSQL_RES *res;
  MYSQL_ROW row;
  my_bool rc;

  if (mysql_query_with_error_report(mysql, &res,
                                    "SHOW VARIABLES LIKE 'have_backup_locks'"))
    return FALSE;

  if ((row= mysql_fetch_row(res)) == NULL)
  {
    mysql_free_result(res);
    return FALSE;
  }

  rc= mysql_num_fields(res) > 1 && !strcmp(row[1], "YES");

  mysql_free_result(res);

  return rc;
}

/*
 This function executes all sql statements from the given file.
 Each statement lenght is limited to 1023 characters including
 trailing semicolon.
 Each statement has to be in its own line.

  @param[in]   sql_file      File name containing sql statements to be
                             executed.
  @retval  1 failure
           0 success
*/
#ifndef NDEBUG
#define SQL_STATEMENT_MAX_LEN 1024  // 1023 chars for statement + trailing 0
static int execute_sql_file(const char *sql_file)
{
  static const char *win_eol= "\r\n";
  static const char *linux_eol= "\n";
  static const char *win_semicolon= ";\r\n";
  static const char *linux_semicolon= ";\n";
  static const char *semicolon= ";";
  static const char *comment= "#";

  FILE *file;
  char  buf[SQL_STATEMENT_MAX_LEN];

  if (!sql_file)
    return 0;

  if (!(file= fopen(sql_file, "r")))
  {
    fprintf(stderr, "Cannot open file %s\n", sql_file);
    return 1;
  }

  while (fgets(buf, SQL_STATEMENT_MAX_LEN, file))
  {
    // simple validation
    size_t query_len= strlen(buf);

    // empty file
    if (query_len == 0)
    {
      fclose(file);
      return 1;
    }

    // If this is empty or comment line, skip it
    if (strcmp(buf, linux_eol) == 0 || strcmp(buf, win_eol) == 0 ||
        strstr(buf, comment) == buf)
    {
      continue;
    }

    // we need line ending with semicolon and optionally a new line
    // which differs on Windows and Linux
    if (strstr(buf, linux_semicolon) == 0 &&
        strstr(buf, win_semicolon) == 0 && strstr(buf, semicolon) == 0)
    {
      fclose(file);
      return 1;
    }

    if (mysql_query_with_error_report(mysql, 0, buf))
    {
      fclose(file);
      return 1;
    }
  }

  fclose(file);
  return 0;
}
#endif  // NDEBUG

int main(int argc, char **argv)
{
  char bin_log_name[FN_REFLEN];
  int exit_code, md_result_fd;
  int has_consistent_binlog_pos= 0;
  int has_consistent_gtid_executed= 0;
  my_bool ftwrl_done= FALSE;

  MY_INIT("mysqldump");

  compatible_mode_normal_str[0]= 0;
  default_charset= (char *)mysql_universal_client_charset;
  memset(&ignore_table, 0, sizeof(ignore_table));

  exit_code= get_options(&argc, &argv);
  if (exit_code)
  {
    free_resources();
    exit(exit_code);
  }

  /*
    Disable comments in xml mode if 'comments' option is not explicitly used.
  */
  if (opt_xml && !opt_comments_used)
    opt_comments= 0;

  if (log_error_file)
  {
    if(!(stderror_file= freopen(log_error_file, "a+", stderr)))
    {
      free_resources();
      exit(EX_MYSQLERR);
    }
  }

  if (connect_to_db(current_host, current_user, opt_password))
  {
    free_resources();
    exit(EX_MYSQLERR);
  }

#ifndef NDEBUG
  if (execute_sql_file(start_sql_file))
    goto err;
#endif

  if (!path)
    write_header(md_result_file, *argv);

  if (opt_lock_for_backup && !server_supports_backup_locks())
  {
    fprintf(stderr, "%s: Error: --lock-for-backup was specified with "
            "--single-transaction, but the server does not support "
            "LOCK TABLES FOR BACKUP.\n",
            my_progname);
    goto err;
  }

  if (opt_slave_data && do_stop_slave_sql(mysql))
    goto err;

  if (opt_single_transaction && opt_master_data)
  {
    /*
       See if we can avoid FLUSH TABLES WITH READ LOCK with Binlog_snapshot_*
       variables.
    */
    has_consistent_binlog_pos= check_consistent_binlog_pos(NULL, NULL);
  }

  has_consistent_gtid_executed= consistent_gtid_executed_supported(mysql);

  /*
   NOTE:
   1. --lock-all-tables and --single-transaction are mutually exclusive
   2. has_consistent_binlog_pos == true => opt_single_transaction == true
   3. --master-data => implicitly adds --lock-all-tables
   4. --master-data + --single-transaction => does not add implicit --lock-all-tables

   We require FTWRL if any of the following:
   1. explicitly requested by --lock-all-tables
   2. --master-data requested, but server does not provide consistent
      binlog position (or does not support consistent gtid_executed)
      Having consistent gtid_executed condition is here to be compatible with upstream
      behavior on servers which support consistent binlog position, but do not
      support consistent gtid_executed. In such case we need FTWRL.
   3. --single-transaction and --flush-logs
   */
  if (opt_lock_all_tables ||
      (opt_master_data &&
       (!has_consistent_binlog_pos || !has_consistent_gtid_executed)) ||
      (opt_single_transaction && flush_logs))
  {
    if (do_flush_tables_read_lock(mysql))
      goto err;
    ftwrl_done = TRUE;
  }
  else if (opt_lock_for_backup && do_lock_tables_for_backup(mysql))
    goto err;

  /*
    Flush logs before starting transaction since
    this causes implicit commit starting mysql-5.5.
  */
  if (opt_lock_all_tables || opt_master_data ||
      (opt_single_transaction && flush_logs) ||
      opt_delete_master_logs)
  {
    if (flush_logs || opt_delete_master_logs)
    {
      if (mysql_refresh(mysql, REFRESH_LOG))
      {
        DB_error(mysql, "when doing refresh");
        goto err;
      }
      verbose_msg("-- main : logs flushed successfully!\n");
    }

    /* Not anymore! That would not be sensible. */
    flush_logs= 0;
  }

  if (opt_delete_master_logs)
  {
    if (get_bin_log_name(mysql, bin_log_name, sizeof(bin_log_name)))
      goto err;
  }

  if (has_session_variables_like(mysql, "rocksdb_skip_fill_cache"))
    mysql_query_with_error_report(mysql, 0,
                                  "SET SESSION rocksdb_skip_fill_cache=1");

  if (opt_single_transaction && start_transaction(mysql))
    goto err;

  /* Add 'STOP SLAVE to beginning of dump */
  if (opt_slave_apply && add_stop_slave())
    goto err;

  /* Process opt_set_gtid_purged and add SET disable binlog if required. */
  if (process_set_gtid_purged(mysql, ftwrl_done, FALSE))
    goto err;


  if (opt_master_data && do_show_master_status(mysql, has_consistent_binlog_pos))
    goto err;
  if (opt_slave_data && do_show_slave_status(mysql))
    goto err;

  /**
    Note:
    opt_single_transaction == true => opt_lock_all_tables == false and vice versa

    We acquired the lock (FTWRL or LTFB) if
    1. --lock-all-tables => FTWRL + opt_single_transaction == false
    2. --lock-for-backup => LTFB + opt_single_transaction == true
    3. --master-data => (--lock-all-tables) FTWRL + opt_single_transaction == false
    4. --master-data + --single-transaction =>
         FTWRL if consistent snapshot not supported + opt_single_transaction == true
    5. --single-transaction + --flush-logs =>  FTWRL + opt_single_transaction == true

    We have to unlock in cases: 4, 5

    We need to keep the lock up to the end of backup if:
    1. we have --lock-for-backup
    2. we have --lock-all-tables (so opt_single_transaction == false)
    We unlock if none of above.

    If not locked previously, unlocking will not do any harm.
   */
  if (!(opt_lock_all_tables || opt_lock_for_backup))
  {
    if (do_unlock_tables(mysql)) /* unlock but no commit! */
      goto err;
  }

  if (opt_alltspcs)
    dump_all_tablespaces();

  if (opt_alldbs)
  {
    if (!opt_alltspcs && !opt_notspcs)
      dump_all_tablespaces();
    dump_all_databases();
  }
  else
  {
    // Check all arguments meet length condition. Currently database and table
    // names are limited to NAME_LEN bytes and stack-based buffers assumes
    // that escaped name will be not longer than NAME_LEN*2 + 2 bytes long.
    int argument;
    for (argument= 0; argument < argc; argument++)
    {
      size_t argument_length= strlen(argv[argument]);
      if (argument_length > NAME_LEN)
      {
        die(EX_CONSCHECK, "[ERROR] Argument '%s' is too long, it cannot be "
          "name for any table or database.\n", argv[argument]);
      }
    }

    if (argc > 1 && !opt_databases)
    {
      /* Only one database and selected table(s) */
      if (!opt_alltspcs && !opt_notspcs)
        dump_tablespaces_for_tables(*argv, (argv + 1), (argc - 1));
      dump_selected_tables(*argv, (argv + 1), (argc - 1));
    }
    else
    {
      /* One or more databases, all tables */
      if (!opt_alltspcs && !opt_notspcs)
        dump_tablespaces_for_databases(argv);
      dump_databases(argv);
    }
  }

  /* if --dump-slave , start the slave sql thread */
  if (opt_slave_data && do_start_slave_sql(mysql))
    goto err;

  /* Process opt_set_gtid_purged and add SET @@GLOBAL.GTID_PURGED if required. */
   if (process_set_gtid_purged(mysql, ftwrl_done, TRUE))
     goto err;

  /* add 'START SLAVE' to end of dump */
  if (opt_slave_apply && add_slave_statements())
    goto err;

  if (md_result_file)
    md_result_fd= my_fileno(md_result_file);

  /* 
     Ensure dumped data flushed.
     First we will flush the file stream data to kernel buffers with fflush().
     Second we will flush the kernel buffers data to physical disk file with
     my_sync(), this will make sure the data succeessfully dumped to disk file.
     fsync() fails with EINVAL if stdout is not redirected to any file, hence
     MY_IGNORE_BADFD is passed to ingnore that error.
  */
  if (md_result_file &&
      (fflush(md_result_file) || my_sync(md_result_fd, MYF(MY_IGNORE_BADFD))))
  {
    if (!first_error)
      first_error= EX_MYSQLERR;
    goto err;
  }
  /* everything successful, purge the old logs files */
  if (opt_delete_master_logs && purge_bin_logs_to(mysql, bin_log_name))
    goto err;

#if defined (_WIN32) && !defined (EMBEDDED_LIBRARY)
  my_free(shared_memory_base_name);
#endif
  /*
    No reason to explicitely COMMIT the transaction, neither to explicitely
    UNLOCK TABLES: these will be automatically be done by the server when we
    disconnect now. Saves some code here, some network trips, adds nothing to
    server.
  */
err:
#ifndef NDEBUG
  execute_sql_file(finish_sql_file);
#endif

  dbDisconnect(current_host);
  if (!path)
    write_footer(md_result_file);
  free_resources();

  if (stderror_file)
    fclose(stderror_file);

  return(first_error);
} /* main */
