# WL#9290 InnoDB: Support transparent tablespace data encryption for redo log
# This test case will test basic redo log encryption support features.

--source include/no_valgrind_without_big.inc
--source include/have_innodb_max_16k.inc

--disable_query_log
<<<<<<< HEAD:mysql-test/include/log_encrypt_1.inc
call mtr.add_suppression("Ignoring tablespace .* because it could not be opened");
call mtr.add_suppression("Encryption can't find master key, please check the keyring is loaded.");
call mtr.add_suppression("Redo log cannot be encrypted if the keyring is not loaded.");
call mtr.add_suppression("Check keyring fail, please check the keyring is loaded.");
call mtr.add_suppression("Redo log key generation failed.");
||||||| 8d8c986e571:mysql-test/suite/innodb/t/log_encrypt_1.test
call mtr.add_suppression("\\[Warning\\] .* Ignoring tablespace .* because it could not be opened");
call mtr.add_suppression("\\[Error\\] .* Encryption can't find master key, please check the keyring plugin is loaded.");
call mtr.add_suppression("\\[ERROR\\] .* Failed to find tablespace for table `\.\.*`\.`\.\.*` in the cache.");
call mtr.add_suppression("\\[ERROR\\] .* Operating system error number 2 in a file operation.");
call mtr.add_suppression("\\[ERROR\\] .* The error means the system cannot find the path specified.");
call mtr.add_suppression("\\[ERROR\\] .* Could not find a valid tablespace file for");
call mtr.add_suppression("\\[ERROR\\] .* If you are installing InnoDB, remember that you must create directories yourself, InnoDB does not create them.");
call mtr.add_suppression("\\[ERROR\\] .* Can't set redo log tablespace to be encrypted.");
=======
call mtr.add_suppression("\\[Warning\\] .* Ignoring tablespace .* because it could not be opened");
call mtr.add_suppression("\\[Error\\] .* Encryption can't find master key, please check the keyring plugin is loaded.");
call mtr.add_suppression("\\[ERROR\\] .* Failed to find tablespace for table `\.\.*`\.`\.\.*` in the cache.");
call mtr.add_suppression("\\[ERROR\\] .* Operating system error number 2 in a file operation.");
call mtr.add_suppression("\\[ERROR\\] .* The error means the system cannot find the path specified.");
call mtr.add_suppression("\\[ERROR\\] .* Could not find a valid tablespace file for");
call mtr.add_suppression("\\[ERROR\\] .* If you are installing InnoDB, remember that you must create directories yourself, InnoDB does not create them.");
call mtr.add_suppression("\\[ERROR\\] .* Can't set redo log files to be encrypted.");
>>>>>>> mysql-8.0.30:mysql-test/suite/innodb/t/log_encrypt_1.test
--enable_query_log

--let $restart_parameters = restart: $KEYRING_PARAMS
--source include/restart_mysqld_no_echo.inc

CREATE TABLE t1(c1 INT, c2 char(20)) ENGINE = InnoDB;

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
INSERT INTO t1 select * from t1;
INSERT INTO t1 select * from t1;
INSERT INTO t1 select * from t1;
INSERT INTO t1 select * from t1;
INSERT INTO t1 select * from t1;
INSERT INTO t1 select * from t1;

SELECT * FROM t1 ORDER BY c1 LIMIT 10;

# Restart to confirm the encryption info can be retrieved properly.
--let $restart_parameters = restart: $KEYRING_PARAMS
--source include/restart_mysqld_no_echo.inc

SELECT * FROM t1 ORDER BY c1 LIMIT 10;

DROP TABLE t1;

# Crash/recovery test.
CREATE TABLE t1(c1 INT, c2 char(20)) ENGINE = InnoDB;

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

# Restart to confirm the encryption info can be retrieved properly.
--let $restart_parameters = restart: $KEYRING_PARAMS
--source include/restart_mysqld_no_echo.inc

SELECT * FROM t1 ORDER BY c1 LIMIT 10;
DELETE FROM t1;

START TRANSACTION;
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

# Restart to confirm the encryption info can be retrieved properly.
--let $restart_parameters = restart: $KEYRING_PARAMS --general-log --log-output=FILE --general_log_file=$MYSQL_TMP_DIR/keyring_query_log
--source include/restart_mysqld_no_echo.inc

SELECT * FROM t1 ORDER BY c1 LIMIT 10;

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

SELECT * FROM t1 ORDER BY c1 LIMIT 10;

# Cleanup
DROP TABLE t1;
