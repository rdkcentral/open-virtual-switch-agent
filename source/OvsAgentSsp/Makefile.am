AM_CFLAGS = -D_ANSC_LINUX
AM_CFLAGS += -D_ANSC_USER
AM_LDFLAGS = -lccsp_common

AM_CPPFLAGS = -Wall -Werror
ACLOCAL_AMFLAGS = -I m4
hardware_platform = i686-linux-gnu

lib_LTLIBRARIES = libOvsAgentSsp.la

libOvsAgentSsp_la_CPPFLAGS = -I$(top_srcdir)/source/include -I$(top_srcdir)/source $(CPPFLAGS)
libOvsAgentSsp_la_SOURCES = ../common/log.c cosa_api.c
