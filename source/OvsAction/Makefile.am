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

AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES = libOvsAction.la

libOvsAction_la_CPPFLAGS = -I$(top_srcdir)/source/include -I$(top_srcdir)/source $(CPPFLAGS)
libOvsAction_la_SOURCES = ../common/log.c ovs_action.c syscfg.c
libOvsAction_la_LIBADD = ${top_builddir}/source/OvsAgentSsp/libOvsAgentSsp.la
libOvsAction_la_LDFLAGS = -ldl -rdynamic $(SYSTEMD_LDFLAGS) -lsyscfg -lpthread -lz -lrt
if CORE_NET_LIB_FEATURE_SUPPORT
libOvsAction_la_LDFLAGS += -lnet
endif
