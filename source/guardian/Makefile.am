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

guardian_CPPFLAGS = -Wall -Werror -I$(top_srcdir)/source/include

# Initial port uses ovs-ofctl (Option B) and needs no OVS lib link.
# TODO(Option A): add $(OPENVSWITCH_CFLAGS)/$(OPENVSWITCH_LIBS) to link
# libopenvswitch for in-memory delta via vconn_dump_flows().
guardian_LDADD =
