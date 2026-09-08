/*
 * Guardian OVS I/O: connect to the bridge, dump live flows, apply add/del.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GUARDIAN_OVS_H
#define GUARDIAN_OVS_H

#include "guardian_flows.h"

/* Apply the desired flow set to the bridge using a delta against the live
 * flows (cookie GUARDIAN_COOKIE): only changed flows are added/deleted.
 * Returns 0 on success. */
int guardian_ovs_apply(const char *bridge, const struct guardian_flowset *desired);

/* Remove all Guardian flows (cookie GUARDIAN_COOKIE) from the bridge. */
int guardian_ovs_clear(const char *bridge);

/* Print active Guardian flows (equivalent to guardian.sh show). */
int guardian_ovs_show(const char *bridge);

#endif /* GUARDIAN_OVS_H */
