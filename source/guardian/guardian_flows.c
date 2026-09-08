/*
 * Guardian policy -> OpenFlow flow translation (port of gen_flows).
 *
 * Initial scaffold: emits the table-0/table-1 source/dest classification flows
 * from the parsed config. Remaining tables (policy hierarchy, stateful ct path,
 * multicast delivery) are ported incrementally and validated against
 * `guardian.sh dry-run`.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guardian_flows.h"
#include "guardian.h"
#include "guardian_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Access to the parsed tables. Kept internal to config.c today; the flow
 * builder currently drives generation through the public accessors and a small
 * device iterator added here as the port grows. For now we expose just enough
 * via accessor calls. */

static int flowset_push(struct guardian_flowset *fs, const char *line)
{
    char **grown = realloc(fs->lines, (fs->n + 1) * sizeof *fs->lines);
    if (!grown) return -1;
    fs->lines = grown;
    fs->lines[fs->n] = strdup(line);
    if (!fs->lines[fs->n]) return -1;
    fs->n++;
    return 0;
}

struct guardian_flowset *guardian_flows_generate(const struct guardian_config *cfg)
{
    (void)cfg;
    struct guardian_flowset *fs = calloc(1, sizeof *fs);
    if (!fs) return NULL;

    char buf[512];

    /* Unmanaged sources still traverse the pipeline for policy evaluation. */
    snprintf(buf, sizeof buf,
             "cookie=0x%llx,table=0,priority=1,actions=resubmit(,1)",
             (unsigned long long)GUARDIAN_COOKIE);
    if (flowset_push(fs, buf)) goto fail;

    /* TODO: per-device table-0 (dl_src->reg0) and table-1 (dl_dst->reg1) flows,
     * then tables 2/3/4 policy hierarchy. Drives off cfg's group/device tables. */

    return fs;

fail:
    guardian_flowset_free(fs);
    return NULL;
}

void guardian_flowset_free(struct guardian_flowset *fs)
{
    if (!fs) return;
    for (size_t i = 0; i < fs->n; i++)
        free(fs->lines[i]);
    free(fs->lines);
    free(fs);
}
