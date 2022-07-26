# InnoDB transparent tablespace data encryption
# This test case will test basic encryption support features.

--source include/no_valgrind_without_big.inc

<<<<<<< HEAD:mysql-test/include/log_encrypt_2.inc
# Restart the server with keyring loaded
--let $restart_parameters= restart: $KEYRING_PARAMS
--source include/restart_mysqld_no_echo.inc
||||||| 8d8c986e571:mysql-test/suite/innodb/t/log_encrypt_2.test
#Suppress following messages from myslqd log
--disable_query_log
call mtr.add_suppression("keyring_file initialization failure. Please check if the keyring_file_data points to readable keyring file or keyring file can be created in the specified location. The keyring_file will stay unusable until correct path to the keyring file gets provided");
call mtr.add_suppression("\\[Error\\] .*MY-\\d+.* Can't generate new master key for tablespace encryption, please check the keyring plugin is loaded.");
call mtr.add_suppression("\\[Error\\] .*MY-\\d+.* Encryption can't find master key, please check the keyring plugin is loaded.");
call mtr.add_suppression("\\[ERROR\\] .*MY-\\d+.* Function 'keyring_file' already exists");
call mtr.add_suppression("\\[ERROR\\] .*MY-\\d+.* Couldn't load plugin named 'keyring_file' with soname 'keyring_file.*'.");
call mtr.add_suppression("Plugin keyring_file reported");
call mtr.add_suppression("\\[ERROR\\] .*MY-\\d+.* Can't set redo log tablespace to be encrypted.");
call mtr.add_suppression("You need to use --log-bin to make --binlog-format work");
--enable_query_log
=======
#Suppress following messages from myslqd log
--disable_query_log
call mtr.add_suppression("keyring_file initialization failure. Please check if the keyring_file_data points to readable keyring file or keyring file can be created in the specified location. The keyring_file will stay unusable until correct path to the keyring file gets provided");
call mtr.add_suppression("\\[Error\\] .*MY-\\d+.* Can't generate new master key for tablespace encryption, please check the keyring plugin is loaded.");
call mtr.add_suppression("\\[Error\\] .*MY-\\d+.* Encryption can't find master key, please check the keyring plugin is loaded.");
call mtr.add_suppression("\\[ERROR\\] .*MY-\\d+.* Function 'keyring_file' already exists");
call mtr.add_suppression("\\[ERROR\\] .*MY-\\d+.* Couldn't load plugin named 'keyring_file' with soname 'keyring_file.*'.");
call mtr.add_suppression("Plugin keyring_file reported");
call mtr.add_suppression("\\[ERROR\\] .*MY-\\d+.* Can't set redo log files to be encrypted.");
call mtr.add_suppression("You need to use --log-bin to make --binlog-format work");
--enable_query_log
>>>>>>> mysql-8.0.30:mysql-test/suite/innodb/t/log_encrypt_2.test

SHOW VARIABLES LIKE "%innodb_redo_log_encrypt%";

let $innodb_file_per_table = `SELECT @@innodb_file_per_table`;

SET GLOBAL innodb_file_per_table = 1;
SELECT @@innodb_file_per_table;

# Create a table with encryption
CREATE TABLE t1(c1 INT, c2 char(20)) ENCRYPTION="Y" ENGINE = InnoDB;

SHOW CREATE TABLE t1;
INSERT INTO t1 VALUES(0, "aaaaa");
INSERT INTO t1 VALUES(1, "bbbbb");
INSERT INTO t1 VALUES(2, "ccccc");
INSERT INTO t1 VALUES(3, "ddddd");
INSERT INTO t1 VALUES(4, "eeeee");
INSERT INTO t1 VALUES(5, "fffff");
INSERT INTO t1 VALUES(6, "ggggg");
INSERT INTO t1 VALUES(7, "hhhhh");
INSERT INTO t1 VALUES(8, "iiiii");
INSERT INTO t1 VALUES(9, "jjjjj");
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;

SELECT * FROM t1 LIMIT 10;

# Restart to confirm the encryption info can be retrieved properly.
--let $restart_parameters= restart: $KEYRING_PARAMS
--source include/restart_mysqld_no_echo.inc

SHOW VARIABLES LIKE "%innodb_redo_log_encrypt%";

SELECT * FROM t1 LIMIT 10;

if (`select locate("KEYRING_KEY", "$redo_log_mode") > 0`) {

# KEYRING_KEY related tests

ALTER INSTANCE ROTATE REDO SYSTEM KEY;

--let $wait_condition = select variable_value = 2 from performance_schema.global_status where variable_name = 'innodb_encryption_redo_key_version'
--source include/wait_condition.inc

--let $server_uuid= query_get_value(SELECT @@SERVER_UUID, @@SERVER_UUID, 1)
--let $percona_key_name_v2=percona_redo-$server_uuid:2

# Check that a new key was created inside keyring
--let SEARCH_PATTERN=$percona_key_name_v2
--let ABORT_ON=NOT_FOUND
--let SEARCH_FILE=$MYSQL_TMP_DIR/mysecret_keyring2
--source include/search_pattern_in_file.inc

ALTER INSTANCE ROTATE REDO SYSTEM KEY;

--let $wait_condition = select variable_value = 3 from performance_schema.global_status where variable_name = 'innodb_encryption_redo_key_version'
--source include/wait_condition.inc

--let $percona_key_name_v3=percona_redo-$server_uuid:3

# Check that a new key was created inside keyring
--let SEARCH_PATTERN=$percona_key_name_v3
--let ABORT_ON=NOT_FOUND
--let SEARCH_FILE=$MYSQL_TMP_DIR/mysecret_keyring2
--source include/search_pattern_in_file.inc

# EOF KEYRING_KEY related tests
}

ALTER INSTANCE ROTATE INNODB MASTER KEY;

DROP TABLE t1;

# Crash/recovery test.
CREATE TABLE t1(c1 INT, c2 char(20)) ENCRYPTION="Y" ENGINE = InnoDB;

INSERT INTO t1 VALUES(0, "aaaaa");
INSERT INTO t1 VALUES(1, "bbbbb");
INSERT INTO t1 VALUES(2, "ccccc");
INSERT INTO t1 VALUES(3, "ddddd");
INSERT INTO t1 VALUES(4, "eeeee");
INSERT INTO t1 VALUES(5, "fffff");
INSERT INTO t1 VALUES(6, "ggggg");
INSERT INTO t1 VALUES(7, "hhhhh");
INSERT INTO t1 VALUES(8, "iiiii");
INSERT INTO t1 VALUES(9, "jjjjj");
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;
INSERT INTO t1 SELECT * FROM t1;

# Restart to confirm the encryption info can be retrieved properly.
--let $restart_parameters= restart: $KEYRING_PARAMS
--let $do_not_echo_parameters = 1
--source include/kill_and_restart_mysqld.inc

SHOW VARIABLES LIKE "%innodb_redo_log_encrypt%";

SELECT * FROM t1 LIMIT 10;

--let $restart_parameters = restart: $KEYRING_PARAMS --general-log --log-output=FILE --general_log_file=$MYSQL_TMP_DIR/keyring_query_log
--source include/restart_mysqld_no_echo.inc

INSERT INTO t1 SELECT * FROM t1;
DROP TABLE t1;

--let $restart_parameters = restart: $KEYRING_PARAMS --general-log --log-output=FILE --general_log_file=$MYSQL_TMP_DIR/keyring_query_log
--source include/restart_mysqld_no_echo.inc

SHOW VARIABLES LIKE "%innodb_redo_log_encrypt%";

#
# Check no effect of block_encryption_mode = 'aes-256-cbc' variable on table encryption
SET block_encryption_mode = 'aes-256-cbc';
# Test encryption .
CREATE DATABASE tde_db;
CREATE TABLE tde_db.t1(c1 INT PRIMARY KEY, c2 char(50)) ENCRYPTION = 'Y' ENGINE = InnoDB;

INSERT INTO tde_db.t1 VALUES(0, 'abc');
INSERT INTO tde_db.t1 VALUES(1, 'xyz');
INSERT INTO tde_db.t1 VALUES(2, null);
INSERT INTO tde_db.t1 VALUES(3, null);
SELECT * FROM tde_db.t1 LIMIT 10;
ALTER INSTANCE ROTATE INNODB MASTER KEY;
SELECT * FROM tde_db.t1 LIMIT 10;
--echo # Mysqldump output
--exec $MYSQL_DUMP --compact --skip-comments --databases tde_db
--echo # Redirecting mysqlpump output to MYSQL_TMP_DIR/mysqlpump_encrypt.sql
--exec $MYSQL_PUMP --default-parallelism=1 --databases tde_db > $MYSQL_TMP_DIR/mysqlpump_encrypt.sql
DROP DATABASE tde_db;

--let SEARCH_FILE=$MYSQL_TMP_DIR/keyring_query_log
let SEARCH_PATTERN= ALTER INSTANCE ROTATE INNODB MASTER KEY;
--source include/search_pattern.inc

--echo # Loading tables from mysqlpump_encrypt.sql
--exec $MYSQL --skip-comments < $MYSQL_TMP_DIR/mysqlpump_encrypt.sql
SELECT * FROM tde_db.t1 LIMIT 10;
INSERT INTO tde_db.t1 VALUES(4, null);
SELECT * FROM tde_db.t1 LIMIT 10;
DROP DATABASE tde_db;
#
--let $restart_parameters = restart: $KEYRING_PARAMS
--source include/restart_mysqld_no_echo.inc

# Cleanup
--remove_file $MYSQL_TMP_DIR/keyring_query_log
--remove_file $MYSQL_TMP_DIR/mysqlpump_encrypt.sql
eval SET GLOBAL innodb_file_per_table=$innodb_file_per_table;
