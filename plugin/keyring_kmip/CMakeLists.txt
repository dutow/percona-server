# (C) 2021 Percona LLC and/or its affiliates
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA
#

IF (NOT DEFINED WITH_KEYRING_KMIP)
  SET (WITH_KEYRING_KMIP 1)
ENDIF()
IF (NOT WITH_KEYRING_KMIP)
  MESSAGE (STATUS "Not building keyring_kmip plugin")
  RETURN()
ENDIF()

DISABLE_MISSING_PROFILE_WARNING()

INCLUDE_DIRECTORIES(SYSTEM ${BOOST_PATCHES_DIR} ${BOOST_INCLUDE_DIR})

MYSQL_ADD_PLUGIN(keyring_kmip
  keyring_kmip.cc
  MODULE_ONLY
  MODULE_OUTPUT_NAME "keyring_kmip"
)

ADD_DEFINITIONS(-DLOG_COMPONENT_TAG="keyring_kmip")
