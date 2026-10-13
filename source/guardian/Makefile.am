#
# Guardian OpenFlow policy agent (native C port of guardian.sh).
# SPDX-License-Identifier: Apache-2.0
#

bin_PROGRAMS = guardian

guardian_SOURCES = \
	guardian_main.c \
	guardian_config.c \
	guardian_flows.c \
	guardian_ovs.c

guardian_CPPFLAGS = -Wall -Werror -I$(top_srcdir)/source/include $(OPENVSWITCH_CFLAGS)

# Links libopenvswitch for direct OpenFlow I/O (vconn/ofputil) -- no ovs-ofctl fork.
guardian_LDADD = $(OPENVSWITCH_LIBS)
