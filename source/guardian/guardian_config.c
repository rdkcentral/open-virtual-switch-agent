/*
 * Guardian config parsing + delta computation.
 *
 * Initial port scaffold: parses the INI-style guardian.cfg into in-memory
 * tables (groups, devices, services, macros, policies, defaults). The flow
 * generation (guardian_flows.c) consumes these tables instead of forking awk
 * per line as guardian.sh did.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guardian_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

/* TODO: replace fixed caps with dynamic arrays once parsing is fleshed out. */
#define MAX_GROUPS   64
#define MAX_DEVICES  512
#define MAX_NAME     64

struct group_entry {
    char     name[MAX_NAME];
    uint32_t id;
};

struct device_entry {
    char mac[MAX_NAME];
    char group[MAX_NAME];
};

struct guardian_config {
    struct group_entry  groups[MAX_GROUPS];
    size_t              n_groups;
    struct device_entry devices[MAX_DEVICES];
    size_t              n_devices;
    bool                stateful;
    /* TODO: services, service_macros, group/intra/device policy, other defaults. */
};

/* Strip inline "  # comment", leading/trailing whitespace; returns trimmed
 * start (may be empty). Modifies buf in place. */
static char *trim_line(char *buf)
{
    /* Drop an inline comment preceded by whitespace, or a full-line comment. */
    char *h = buf;
    while (*h && isspace((unsigned char)*h)) h++;
    if (*h == '#') { *h = '\0'; return h; }

    for (char *p = buf; *p; p++) {
        if (*p == '#' && p > buf && isspace((unsigned char)p[-1])) { *p = '\0'; break; }
    }
    /* Trim trailing whitespace. */
    size_t len = strlen(h);
    while (len > 0 && isspace((unsigned char)h[len - 1])) h[--len] = '\0';
    return h;
}

struct guardian_config *guardian_config_load(const char *path, char **err)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        if (err) {
            char msg[256];
            snprintf(msg, sizeof msg, "cannot open '%s'", path);
            *err = strdup(msg);
        }
        return NULL;
    }

    struct guardian_config *cfg = calloc(1, sizeof *cfg);
    if (!cfg) { fclose(fp); if (err) *err = strdup("out of memory"); return NULL; }

    char line[512];
    char section[MAX_NAME] = "";

    while (fgets(line, sizeof line, fp)) {
        char *s = trim_line(line);
        if (*s == '\0') continue;

        if (*s == '[') {
            char *end = strchr(s, ']');
            if (end) {
                size_t n = (size_t)(end - s - 1);
                if (n >= sizeof section) n = sizeof section - 1;
                memcpy(section, s + 1, n);
                section[n] = '\0';
            }
            continue;
        }

        if (!strcasecmp(section, "groups")) {
            char name[MAX_NAME]; unsigned long id;
            if (sscanf(s, "%63s %lu", name, &id) == 2 && cfg->n_groups < MAX_GROUPS) {
                struct group_entry *g = &cfg->groups[cfg->n_groups++];
                snprintf(g->name, sizeof g->name, "%s", name);
                g->id = (uint32_t)id;
            }
        } else if (!strcasecmp(section, "devices")) {
            char mac[MAX_NAME], grp[MAX_NAME];
            if (sscanf(s, "%63s %63s", mac, grp) == 2 && cfg->n_devices < MAX_DEVICES) {
                struct device_entry *d = &cfg->devices[cfg->n_devices++];
                snprintf(d->mac, sizeof d->mac, "%s", mac);
                snprintf(d->group, sizeof d->group, "%s", grp);
            }
        } else if (!strcasecmp(section, "defaults")) {
            char key[MAX_NAME], val[MAX_NAME];
            if (sscanf(s, "%63s %63s", key, val) == 2 &&
                !strcasecmp(key, "stateful")) {
                cfg->stateful = !strcasecmp(val, "true");
            }
        }
        /* TODO: services, service_macros, *_policy sections. */
    }

    fclose(fp);
    return cfg;
}

void guardian_config_free(struct guardian_config *cfg)
{
    free(cfg);
}

uint32_t guardian_config_group_id(const struct guardian_config *cfg,
                                  const char *name)
{
    for (size_t i = 0; i < cfg->n_groups; i++)
        if (!strcasecmp(cfg->groups[i].name, name))
            return cfg->groups[i].id;
    return 0;
}

bool guardian_config_stateful(const struct guardian_config *cfg)
{
    return cfg->stateful;
}
