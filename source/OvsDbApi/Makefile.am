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

lib_LTLIBRARIES = libOvsDbApi.la

libOvsDbApi_la_CPPFLAGS = -I$(top_srcdir)/source/ -I$(top_srcdir)/source/include $(CPPFLAGS)
libOvsDbApi_la_SOURCES = ../common/log.c \
						 OvsDbApi.c \
						 ovsdb_socket.c \
						 json_parser/gateway_config.c \
						 json_parser/feedback.c \
						 json_parser/receipt_parser.c \
						 json_parser/table_parser.c \
						 ovsdb_parser.c \
						 receipt_list.c \
						 mon_update_list.c

libOvsDbApi_la_LDFLAGS = -ljansson -ldl -rdynamic $(SYSTEMD_LDFLAGS) -lpthread -lz -lrt
