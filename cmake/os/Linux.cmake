
# Copyright (c) 2010, 2022, Oracle and/or its affiliates.
# 
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License, version 2.0,
# as published by the Free Software Foundation.
#
# This program is also distributed with certain software (including
# but not limited to OpenSSL) that is licensed under separate terms,
# as designated in a particular file or component or in included license
# documentation.  The authors of MySQL hereby grant you an additional
# permission to link the program and your derivative works with the
# separately licensed software that they have included with MySQL.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License, version 2.0, for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA 

# This file includes Linux specific options and quirks, related to system checks

INCLUDE(CheckSymbolExists)
INCLUDE(CheckCSourceRuns)

SET(LINUX 1)
SET(TARGET_OS_LINUX 1)

# Use 'uname -r' and 'rpm -qf /' to figure out host system.
# For Docker images we cannot trust uname, so use rpm instead.
IF(UNIX)
  FIND_PROGRAM(MY_UNAME uname /bin /usr/bin /usr/local/bin /sbin)
  IF(MY_UNAME)
    EXECUTE_PROCESS(COMMAND ${MY_UNAME} -s
            OUTPUT_VARIABLE MY_HOST_SYSTEM_NAME
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE MY_UNAME_RESULT
            )
  ENDIF()
  FIND_PROGRAM(MY_RPM rpm /bin /usr/bin)
  IF(MY_RPM)
    EXECUTE_PROCESS(COMMAND ${MY_RPM} -qf /
            OUTPUT_VARIABLE MY_HOST_FILESYSTEM_NAME
            OUTPUT_STRIP_TRAILING_WHITESPACE
            RESULT_VARIABLE MY_RPM_RESULT
            )
  ENDIF()
ENDIF()

IF(MY_HOST_SYSTEM_NAME MATCHES "Linux")
  # Trust 'rpm -qf /' rather than 'uname -s'
  STRING(REGEX MATCH "\\.el([6789])\\." MATCH_FSYS "${MY_HOST_FILESYSTEM_NAME}")

  IF(CMAKE_MATCH_1)
    SET(LINUX_RHEL 1)
  ENDIF()
ENDIF()

IF(EXISTS "/etc/fedora-release")
  SET(LINUX_FEDORA 1)
  FILE(READ "/etc/fedora-release" FEDORA_RELEASE)
  IF(FEDORA_RELEASE MATCHES "Fedora" AND
     FEDORA_RELEASE MATCHES "28")
    SET(LINUX_FEDORA_28 1)
  ENDIF()
ENDIF()

IF(EXISTS "/etc/os-release")
  FILE(READ "/etc/os-release" MY_OS_RELEASE)
  IF(MY_OS_RELEASE MATCHES "Ubuntu")
    SET(LINUX_UBUNTU 1)
    IF(MY_OS_RELEASE MATCHES "16.04")
      SET(LINUX_UBUNTU_16_04 1)
    ENDIF()
  ENDIF()
  IF(MY_OS_RELEASE MATCHES "Debian")
    SET(LINUX_DEBIAN 1)
    IF(MY_OS_RELEASE MATCHES "jessie")
      SET(LINUX_DEBIAN_8 1)
    ENDIF()
    IF(MY_OS_RELEASE MATCHES "stretch")
      SET(LINUX_DEBIAN_9 1)
    ENDIF()
  ENDIF()
ENDIF()

# Use dpkg-buildflags --get CPPFLAGS | CFLAGS | CXXFLAGS | LDFLAGS
# to get flags for this platform.
IF(LINUX_DEBIAN OR LINUX_UBUNTU)
  SET(LINUX_DEB_PLATFORM 1)
ENDIF()

# Use CMAKE_C_FLAGS | CMAKE_CXX_FLAGS = rpm --eval %optflags
# to get flags for this platform.
IF(LINUX_FEDORA OR LINUX_RHEL)
  SET(LINUX_RPM_PLATFORM 1)
ENDIF()

# We require at least GCC 4.4 or Clang 3.3.
IF(NOT FORCE_UNSUPPORTED_COMPILER)
  IF(CMAKE_COMPILER_IS_GNUCC)
    EXECUTE_PROCESS(COMMAND ${CMAKE_C_COMPILER} -dumpversion
                    OUTPUT_VARIABLE GCC_VERSION)
    IF(GCC_VERSION VERSION_LESS 4.4)
      MESSAGE(FATAL_ERROR "GCC 4.4 or newer is required!")
    ENDIF()
  ELSEIF(CMAKE_C_COMPILER_ID MATCHES "Clang")
    CHECK_C_SOURCE_RUNS("
      int main()
      {
        return (__clang_major__ < 3) ||
               (__clang_major__ == 3 && __clang_minor__ < 3);
      }" HAVE_SUPPORTED_CLANG_VERSION)
    IF(NOT HAVE_SUPPORTED_CLANG_VERSION)
      MESSAGE(FATAL_ERROR "Clang 3.3 or newer is required!")
    ENDIF()
  ELSE()
    MESSAGE(FATAL_ERROR "Unsupported compiler!")
  ENDIF()
ENDIF()

# ISO C89, ISO C99, POSIX.1, POSIX.2, BSD, SVID, X/Open, LFS, and GNU extensions.
ADD_DEFINITIONS(-D_GNU_SOURCE)

# 64 bit file offset support flag
ADD_DEFINITIONS(-D_FILE_OFFSET_BITS=64)

# Fix CMake (< 2.8) flags. -rdynamic exports too many symbols.
FOREACH(LANG C CXX)
  STRING(REPLACE "-rdynamic" "" 
  CMAKE_SHARED_LIBRARY_LINK_${LANG}_FLAGS
  ${CMAKE_SHARED_LIBRARY_LINK_${LANG}_FLAGS}  
  )
ENDFOREACH()

# Ensure we have clean build for shared libraries
# without unresolved symbols
# Not supported with Sanitizers
IF(NOT WITH_ASAN AND NOT WITH_MSAN AND NOT WITH_UBSAN)
  SET(LINK_FLAG_NO_UNDEFINED "-Wl,--no-undefined")
ENDIF()

# Linux specific HUGETLB /large page support
CHECK_SYMBOL_EXISTS(SHM_HUGETLB sys/shm.h HAVE_LINUX_LARGE_PAGES)
