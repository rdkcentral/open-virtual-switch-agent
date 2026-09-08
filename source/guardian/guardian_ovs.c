/*
 * Guardian OVS I/O.
 *
 * Initial scaffold uses a single `ovs-ofctl` invocation (Option B in
 * PORTING.md): the whole desired flow set is streamed once via stdin, removing
 * the per-line forking of guardian.sh. This keeps the port buildable without
 * the OVS staticdev sysroot. The follow-up step swaps this for libopenvswitch
 * (vconn_open + vconn_dump_flows delta + ofputil_encode_flow_mod) per PORTING.md
 * section 2 Option A.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guardian_ovs.h"
#include "guardian.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int guardian_ovs_apply(const char *bridge, const struct guardian_flowset *desired)
{
    /* Full-table replace for the initial port: clear our cookie, then add the
     * desired set in one add-flows call. Delta comes with the Option A rewrite. */
    if (guardian_ovs_clear(bridge) != 0)
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof cmd, "ovs-ofctl add-flows %s -", bridge);
    FILE *p = popen(cmd, "w");
    if (!p) {
        perror("guardian: popen(ovs-ofctl add-flows)");
        return -1;
    }
    for (size_t i = 0; i < desired->n; i++)
        fprintf(p, "%s\n", desired->lines[i]);

    int rc = pclose(p);
    return rc == 0 ? 0 : -1;
}

int guardian_ovs_clear(const char *bridge)
{
    char cmd[256];
    snprintf(cmd, sizeof cmd,
             "ovs-ofctl del-flows %s \"cookie=0x%llx/-1\"",
             bridge, (unsigned long long)GUARDIAN_COOKIE);
    return system(cmd) == 0 ? 0 : -1;
}

int guardian_ovs_show(const char *bridge)
{
    char cmd[256];
    snprintf(cmd, sizeof cmd,
             "ovs-ofctl dump-flows %s | grep -i 0x%llx || echo 'No Guardian flows.'",
             bridge, (unsigned long long)GUARDIAN_COOKIE);
    return system(cmd) == 0 ? 0 : -1;
}
