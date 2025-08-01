#
# Copyright 2020 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#

#                                              -*- Autoconf -*-
# Process this file with autoconf to produce configure script.
#

AC_PREREQ([2.65])
AC_INIT([ovsagent], [1.0], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE([foreign])
LT_INIT
GTEST_ENABLE_FLAG = ""

AC_ARG_ENABLE([gtestapp],
              AS_HELP_STRING([--enable-gtestapp],[enable Gtest support (default is no)]),
              [
                case "${enableval}" in
                 yes) GTEST_SUPPORT_ENABLED=true
                      GTEST_ENABLE_FLAG="-DGTEST_ENABLE"
                      m4_if(m4_sysval,[0],[AC_CONFIG_FILES(source/test/Makefile source/test/OvsDbSocket/Makefile source/test/OvsDbApi/Makefile source/test/OvsAgentApi/Makefile source/test/OvsAgent/Makefile source/test/JsonParser/Makefile)]);;
                  no) GTEST_SUPPORT_ENABLED=false AC_MSG_ERROR([Gtest support is disabled]);;
                   *) AC_MSG_ERROR([bad value ${enableval} for --enable-gtestapp ]);;
                esac
              ],
              [echo "Gtestapp is disabled"])

AM_CONDITIONAL([WITH_GTEST_SUPPORT], [test x$GTEST_SUPPORT_ENABLED = xtrue])

# Checks for Core net lib Feature Support
AC_ARG_ENABLE([core_net_lib_feature_support],
[  --enable-core_net_lib_feature_support=val Turn on core_net_lib Feature, val=true or false],
[case "${enableval}" in
  yes) core_net_lib_feature_support=true ;;
  no)  core_net_lib_feature_support=false ;;
  *) AC_MSG_ERROR([bad value ${enableval} for --enable-core_net_lib_feature_support]) ;;
esac],[core_net_lib_feature_support=false])
AM_CONDITIONAL(CORE_NET_LIB_FEATURE_SUPPORT, test x"$core_net_lib_feature_support" = x"true")

AC_PREFIX_DEFAULT(`pwd`)
AC_ENABLE_SHARED
AC_DISABLE_STATIC

AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_CC_C_O
AM_PROG_LIBTOOL(libtool)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

PKG_CHECK_MODULES([DBUS],[dbus-1 >= 1.6.18])

AC_CONFIG_FILES(
    Makefile
    source/Makefile
    source/OvsAgentSsp/Makefile
    source/OvsAgentCore/Makefile
    source/OvsDbApi/Makefile
    source/OvsAction/Makefile
    source/OvsAgentApi/Makefile
)

AC_SUBST(GTEST_ENABLE_FLAG)

AC_OUTPUT

