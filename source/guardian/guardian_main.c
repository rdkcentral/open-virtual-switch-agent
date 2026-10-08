/*
 * Guardian: native C port of guardian.sh.
 * CLI argument parsing and command dispatch.
 *
 *   guardian [config_file] <command>
 *
 * Only apply/dry-run read the config; the others act on the live bridge.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "guardian.h"
#include "guardian_config.h"
#include "guardian_flows.h"
#include "guardian_ovs.h"

static const char *const DEFAULT_CONFIG = "guardian.cfg";

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [config_file] {apply|dry-run|clear|show|stats|diagnostics|load-test}\n"
        "  Config file defaults to '%s' if omitted.\n",
        prog, DEFAULT_CONFIG);
}

static enum guardian_cmd parse_cmd(const char *s)
{
    if (!strcmp(s, "apply"))       return GUARDIAN_CMD_APPLY;
    if (!strcmp(s, "dry-run"))     return GUARDIAN_CMD_DRY_RUN;
    if (!strcmp(s, "clear"))       return GUARDIAN_CMD_CLEAR;
    if (!strcmp(s, "show"))        return GUARDIAN_CMD_SHOW;
    if (!strcmp(s, "stats"))       return GUARDIAN_CMD_STATS;
    if (!strcmp(s, "diagnostics")) return GUARDIAN_CMD_DIAGNOSTICS;
    if (!strcmp(s, "load-test"))   return GUARDIAN_CMD_LOAD_TEST;
    return GUARDIAN_CMD_UNKNOWN;
}

/* Build the desired flow set from the config; caller frees. */
static struct guardian_flowset *load_desired(const char *config)
{
    char *err = NULL;
    struct guardian_config *cfg = guardian_config_load(config, &err);
    if (!cfg) {
        fprintf(stderr, "guardian: config error: %s\n", err ? err : "unknown");
        free(err);
        return NULL;
    }
    struct guardian_flowset *fs = guardian_flows_generate(cfg);
    guardian_config_free(cfg);
    if (!fs) {
        fprintf(stderr, "guardian: failed to generate flows\n");
        return NULL;
    }
    return fs;
}

int main(int argc, char *argv[])
{
    const char *config = DEFAULT_CONFIG;
    const char *cmd_str;

    /* Accept "<cmd>" or "<config> <cmd>". */
    if (argc == 2) {
        cmd_str = argv[1];
    } else if (argc == 3) {
        config = argv[1];
        cmd_str = argv[2];
    } else {
        usage(argv[0]);
        return 2;
    }

    enum guardian_cmd cmd = parse_cmd(cmd_str);
    if (cmd == GUARDIAN_CMD_UNKNOWN) {
        usage(argv[0]);
        return 2;
    }

    switch (cmd) {
    case GUARDIAN_CMD_APPLY: {
        struct guardian_flowset *fs = load_desired(config);
        if (!fs) return 1;
        int rc = guardian_ovs_apply(GUARDIAN_BRIDGE, fs);
        guardian_flowset_free(fs);
        if (rc == 0)
            printf("Guardian policy applied to %s.\n", GUARDIAN_BRIDGE);
        return rc ? 1 : 0;
    }
    case GUARDIAN_CMD_DRY_RUN: {
        struct guardian_flowset *fs = load_desired(config);
        if (!fs) return 1;
        for (size_t i = 0; i < fs->n; i++)
            puts(fs->lines[i]);
        guardian_flowset_free(fs);
        return 0;
    }
    case GUARDIAN_CMD_CLEAR:
        if (guardian_ovs_clear(GUARDIAN_BRIDGE) == 0) {
            printf("Guardian policy removed from %s.\n", GUARDIAN_BRIDGE);
            return 0;
        }
        return 1;
    case GUARDIAN_CMD_SHOW:
        return guardian_ovs_show(GUARDIAN_BRIDGE) ? 1 : 0;
    case GUARDIAN_CMD_STATS:
    case GUARDIAN_CMD_DIAGNOSTICS:
    case GUARDIAN_CMD_LOAD_TEST:
        fprintf(stderr, "guardian: '%s' not yet implemented in the C port\n", cmd_str);
        return 1;
    default:
        usage(argv[0]);
        return 2;
    }
}
