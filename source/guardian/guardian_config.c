/*
 * Guardian config parsing.
 *
 * Parses the INI-style guardian.cfg into in-memory tables (groups, devices,
 * services, macros, policies, defaults). guardian_flows.c consumes these
 * tables via O(1)/O(n) in-process lookups instead of forking awk per line as
 * guardian.sh did.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guardian_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#define MAX_GROUPS   64
#define MAX_DEVICES  512
#define MAX_SERVICES 128
#define MAX_MACROS   64
#define MAX_POLICY   256

struct group_entry     { char name[GUARDIAN_NAME_MAX]; uint32_t id; };
struct device_entry    { char mac[GUARDIAN_NAME_MAX]; char group[GUARDIAN_NAME_MAX]; };
struct service_entry   { char name[GUARDIAN_NAME_MAX]; char proto[16]; char port[16]; };
struct macro_entry     { char name[GUARDIAN_NAME_MAX]; char expansion[256]; };
struct group_policy_row   { char src[GUARDIAN_NAME_MAX], dst[GUARDIAN_NAME_MAX], svc[GUARDIAN_NAME_MAX], action[16]; };
struct intra_policy_row   { char grp[GUARDIAN_NAME_MAX], svc[GUARDIAN_NAME_MAX], action[16]; };
struct device_policy_row  { char src[GUARDIAN_NAME_MAX], dst_mac[GUARDIAN_NAME_MAX], svc[GUARDIAN_NAME_MAX], action[16]; };

struct guardian_config {
    struct group_entry  groups[MAX_GROUPS];
    size_t              n_groups;
    struct device_entry devices[MAX_DEVICES];
    size_t              n_devices;
    struct service_entry services[MAX_SERVICES];
    size_t              n_services;
    struct macro_entry  macros[MAX_MACROS];
    size_t              n_macros;
    struct group_policy_row  group_policy[MAX_POLICY];
    size_t                    n_group_policy;
    struct intra_policy_row  intra_policy[MAX_POLICY];
    size_t                    n_intra_policy;
    struct device_policy_row device_policy[MAX_POLICY];
    size_t                    n_device_policy;

    char     src_groups[MAX_GROUPS][GUARDIAN_NAME_MAX];
    size_t   n_src_groups;

    bool stateful;
    bool drop_invalid;
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

static void remember_src_group(struct guardian_config *cfg, const char *grp)
{
    for (size_t i = 0; i < cfg->n_src_groups; i++)
        if (!strcasecmp(cfg->src_groups[i], grp))
            return;
    if (cfg->n_src_groups < MAX_GROUPS)
        snprintf(cfg->src_groups[cfg->n_src_groups++], GUARDIAN_NAME_MAX, "%s", grp);
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
    char section[GUARDIAN_NAME_MAX] = "";

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
            char name[GUARDIAN_NAME_MAX]; unsigned long id;
            if (sscanf(s, "%63s %lu", name, &id) == 2 && cfg->n_groups < MAX_GROUPS) {
                struct group_entry *g = &cfg->groups[cfg->n_groups++];
                snprintf(g->name, sizeof g->name, "%s", name);
                g->id = (uint32_t)id;
            }
        } else if (!strcasecmp(section, "devices")) {
            char mac[GUARDIAN_NAME_MAX], grp[GUARDIAN_NAME_MAX];
            if (sscanf(s, "%63s %63s", mac, grp) == 2 && cfg->n_devices < MAX_DEVICES) {
                struct device_entry *d = &cfg->devices[cfg->n_devices++];
                snprintf(d->mac, sizeof d->mac, "%s", mac);
                snprintf(d->group, sizeof d->group, "%s", grp);
                remember_src_group(cfg, grp);
            }
        } else if (!strcasecmp(section, "services")) {
            char name[GUARDIAN_NAME_MAX], proto[16], port[16];
            if (sscanf(s, "%63s %15s %15s", name, proto, port) == 3 &&
                cfg->n_services < MAX_SERVICES) {
                struct service_entry *e = &cfg->services[cfg->n_services++];
                snprintf(e->name, sizeof e->name, "%s", name);
                snprintf(e->proto, sizeof e->proto, "%s", proto);
                snprintf(e->port, sizeof e->port, "%s", port);
            }
        } else if (!strcasecmp(section, "service_macros")) {
            char name[GUARDIAN_NAME_MAX], expansion[256];
            if (sscanf(s, "%63s %255s", name, expansion) == 2 &&
                cfg->n_macros < MAX_MACROS) {
                struct macro_entry *m = &cfg->macros[cfg->n_macros++];
                snprintf(m->name, sizeof m->name, "%s", name);
                snprintf(m->expansion, sizeof m->expansion, "%s", expansion);
            }
        } else if (!strcasecmp(section, "group_policy")) {
            char src[GUARDIAN_NAME_MAX], dst[GUARDIAN_NAME_MAX], svc[GUARDIAN_NAME_MAX], act[16];
            if (sscanf(s, "%63s %63s %63s %15s", src, dst, svc, act) == 4 &&
                cfg->n_group_policy < MAX_POLICY) {
                struct group_policy_row *r = &cfg->group_policy[cfg->n_group_policy++];
                snprintf(r->src, sizeof r->src, "%s", src);
                snprintf(r->dst, sizeof r->dst, "%s", dst);
                snprintf(r->svc, sizeof r->svc, "%s", svc);
                snprintf(r->action, sizeof r->action, "%s", act);
            }
        } else if (!strcasecmp(section, "intra_group_policy")) {
            char grp[GUARDIAN_NAME_MAX], svc[GUARDIAN_NAME_MAX], act[16];
            if (sscanf(s, "%63s %63s %15s", grp, svc, act) == 3 &&
                cfg->n_intra_policy < MAX_POLICY) {
                struct intra_policy_row *r = &cfg->intra_policy[cfg->n_intra_policy++];
                snprintf(r->grp, sizeof r->grp, "%s", grp);
                snprintf(r->svc, sizeof r->svc, "%s", svc);
                snprintf(r->action, sizeof r->action, "%s", act);
            }
        } else if (!strcasecmp(section, "device_policy")) {
            char src[GUARDIAN_NAME_MAX], dst[GUARDIAN_NAME_MAX], svc[GUARDIAN_NAME_MAX], act[16];
            if (sscanf(s, "%63s %63s %63s %15s", src, dst, svc, act) == 4 &&
                cfg->n_device_policy < MAX_POLICY) {
                struct device_policy_row *r = &cfg->device_policy[cfg->n_device_policy++];
                snprintf(r->src, sizeof r->src, "%s", src);
                snprintf(r->dst_mac, sizeof r->dst_mac, "%s", dst);
                snprintf(r->svc, sizeof r->svc, "%s", svc);
                snprintf(r->action, sizeof r->action, "%s", act);
            }
        } else if (!strcasecmp(section, "defaults")) {
            char key[GUARDIAN_NAME_MAX], val[GUARDIAN_NAME_MAX];
            if (sscanf(s, "%63s %63s", key, val) == 2) {
                if (!strcasecmp(key, "stateful"))
                    cfg->stateful = !strcasecmp(val, "true");
                else if (!strcasecmp(key, "drop_invalid"))
                    cfg->drop_invalid = !strcasecmp(val, "true");
            }
        }
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

bool guardian_config_drop_invalid(const struct guardian_config *cfg)
{
    return cfg->drop_invalid;
}

size_t guardian_config_n_devices(const struct guardian_config *cfg)
{
    return cfg->n_devices;
}

void guardian_config_device(const struct guardian_config *cfg, size_t i,
                            const char **mac, const char **group)
{
    *mac = cfg->devices[i].mac;
    *group = cfg->devices[i].group;
}

const char *guardian_config_group_of_mac(const struct guardian_config *cfg,
                                         const char *mac)
{
    for (size_t i = 0; i < cfg->n_devices; i++)
        if (!strcasecmp(cfg->devices[i].mac, mac))
            return cfg->devices[i].group;
    return NULL;
}

size_t guardian_config_n_src_groups(const struct guardian_config *cfg)
{
    return cfg->n_src_groups;
}

const char *guardian_config_src_group(const struct guardian_config *cfg, size_t i)
{
    return cfg->src_groups[i];
}

size_t guardian_config_n_group_policy(const struct guardian_config *cfg)
{
    return cfg->n_group_policy;
}

void guardian_config_group_policy(const struct guardian_config *cfg, size_t i,
                                  const char **src, const char **dst,
                                  const char **svc, const char **action)
{
    *src = cfg->group_policy[i].src;
    *dst = cfg->group_policy[i].dst;
    *svc = cfg->group_policy[i].svc;
    *action = cfg->group_policy[i].action;
}

size_t guardian_config_n_intra_policy(const struct guardian_config *cfg)
{
    return cfg->n_intra_policy;
}

void guardian_config_intra_policy(const struct guardian_config *cfg, size_t i,
                                  const char **grp, const char **svc,
                                  const char **action)
{
    *grp = cfg->intra_policy[i].grp;
    *svc = cfg->intra_policy[i].svc;
    *action = cfg->intra_policy[i].action;
}

size_t guardian_config_n_device_policy(const struct guardian_config *cfg)
{
    return cfg->n_device_policy;
}

void guardian_config_device_policy(const struct guardian_config *cfg, size_t i,
                                   const char **src, const char **dst_mac,
                                   const char **svc, const char **action)
{
    *src = cfg->device_policy[i].src;
    *dst_mac = cfg->device_policy[i].dst_mac;
    *svc = cfg->device_policy[i].svc;
    *action = cfg->device_policy[i].action;
}

static size_t expand_basic(const struct guardian_config *cfg, const char *svc,
                           struct guardian_service *out, size_t max)
{
    for (size_t i = 0; i < cfg->n_services && max > 0; i++) {
        if (!strcasecmp(cfg->services[i].name, svc)) {
            snprintf(out->proto, sizeof out->proto, "%s", cfg->services[i].proto);
            snprintf(out->port, sizeof out->port, "%s", cfg->services[i].port);
            return 1;
        }
    }
    return 0;
}

size_t guardian_config_expand_service(const struct guardian_config *cfg,
                                      const char *svc,
                                      struct guardian_service *out, size_t max)
{
    for (size_t i = 0; i < cfg->n_macros; i++) {
        if (strcasecmp(cfg->macros[i].name, svc)) continue;

        /* Macro: comma-separated list of basic service names. */
        char buf[256];
        snprintf(buf, sizeof buf, "%s", cfg->macros[i].expansion);
        size_t n = 0;
        char *save = NULL;
        for (char *tok = strtok_r(buf, ",", &save); tok && n < max;
             tok = strtok_r(NULL, ",", &save)) {
            n += expand_basic(cfg, tok, &out[n], max - n);
        }
        return n;
    }
    /* Not a macro: look up as a basic service. */
    return expand_basic(cfg, svc, out, max);
}

bool guardian_config_policy_is_drop(const struct guardian_config *cfg,
                                    const char *src_grp, const char *dst_grp)
{
    for (size_t i = 0; i < cfg->n_group_policy; i++) {
        const struct group_policy_row *r = &cfg->group_policy[i];
        if (!strcasecmp(r->src, src_grp) && !strcasecmp(r->dst, dst_grp) &&
            !strcasecmp(r->svc, "any") && !strcasecmp(r->action, "drop"))
            return true;
    }
    return false;
}

bool guardian_config_service_allows_port(const struct guardian_config *cfg,
                                         const char *src_grp, const char *dst_grp,
                                         const char *proto, const char *port)
{
    for (size_t i = 0; i < cfg->n_group_policy; i++) {
        const struct group_policy_row *r = &cfg->group_policy[i];
        if (strcasecmp(r->src, src_grp) || strcasecmp(r->dst, dst_grp) ||
            strcasecmp(r->action, "allow") || !strcasecmp(r->svc, "any"))
            continue;

        struct guardian_service svcs[16];
        size_t n = guardian_config_expand_service(cfg, r->svc, svcs, 16);
        for (size_t j = 0; j < n; j++)
            if (!strcmp(svcs[j].proto, proto) && !strcmp(svcs[j].port, port))
                return true;
    }
    return false;
}
