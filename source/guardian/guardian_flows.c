/*
 * Guardian policy -> OpenFlow flow translation (port of gen_flows).
 *
 * Emits the same flow-mod text lines guardian.sh's gen_flows() produces:
 *   table 0: dl_src -> reg0 classification
 *   table 1: dl_dst -> reg1 classification; multicast/broadcast -> table 3
 *   table 2/4: priority hierarchy 160/150/140/110/105/100 (+ stateful ct path)
 *   table 3: group-scoped multicast delivery (mc2uc), via live FDB snapshot
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guardian_flows.h"
#include "guardian.h"
#include "guardian_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <sys/types.h>

/* libopenvswitch exports these (see utilities/ovs-appctl.c), but their headers
 * (daemon.h/dirs.h/unixctl.h/jsonrpc.h) are OVS-internal and not shipped in the
 * dev sysroot, so declare the few prototypes we use here. */
struct jsonrpc;
extern const char *ovs_rundir(void);
extern pid_t read_pidfile(const char *name);
extern int unixctl_client_create(const char *path, struct jsonrpc **client);
extern int unixctl_client_transact(struct jsonrpc *client, const char *command,
                                   int argc, char *argv[],
                                   char **result, char **error);
extern void jsonrpc_close(struct jsonrpc *);

#define MAX_FDB 1024

struct fdb_entry {
    char port[16];
    char mac[GUARDIAN_NAME_MAX];
};

static int flowset_push(struct guardian_flowset *fs, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);

    char **grown = realloc(fs->lines, (fs->n + 1) * sizeof *fs->lines);
    if (!grown) return -1;
    fs->lines = grown;
    fs->lines[fs->n] = strdup(buf);
    if (!fs->lines[fs->n]) return -1;
    fs->n++;
    return 0;
}

/* Resolve a group name to its numeric id, falling back to the raw name (as
 * guardian.sh does) if it isn't found in [groups]. */
static const char *group_id_str(const struct guardian_config *cfg,
                                const char *name, char *buf, size_t len)
{
    uint32_t id = guardian_config_group_id(cfg, name);
    if (id == 0) {
        snprintf(buf, len, "%s", name);
        return buf;
    }
    snprintf(buf, len, "%u", id);
    return buf;
}

static bool is_allow(const char *action)
{
    return !strcasecmp(action, "allow");
}

static bool is_any(const char *svc)
{
    return !strcasecmp(svc, "any");
}

/* Emit table-0/1 classification flows for every configured device. */
static int gen_device_tables(const struct guardian_config *cfg, struct guardian_flowset *fs)
{
    size_t n = guardian_config_n_devices(cfg);
    for (size_t i = 0; i < n; i++) {
        const char *mac, *grp;
        guardian_config_device(cfg, i, &mac, &grp);
        char idbuf[16];
        const char *id = group_id_str(cfg, grp, idbuf, sizeof idbuf);
        if (flowset_push(fs,
                "cookie=0x%llx,table=0,priority=100,dl_src=%s,actions=load:%s->NXM_NX_REG0[],resubmit(,1)",
                (unsigned long long)GUARDIAN_COOKIE, mac, id))
            return -1;
    }
    if (flowset_push(fs, "cookie=0x%llx,table=0,priority=1,actions=resubmit(,1)",
                     (unsigned long long)GUARDIAN_COOKIE))
        return -1;

    for (size_t i = 0; i < n; i++) {
        const char *mac, *grp;
        guardian_config_device(cfg, i, &mac, &grp);
        char idbuf[16];
        const char *id = group_id_str(cfg, grp, idbuf, sizeof idbuf);
        if (flowset_push(fs,
                "cookie=0x%llx,table=1,priority=100,dl_dst=%s,actions=load:%s->NXM_NX_REG1[],resubmit(,2)",
                (unsigned long long)GUARDIAN_COOKIE, mac, id))
            return -1;
    }
    if (flowset_push(fs,
            "cookie=0x%llx,table=1,priority=200,dl_dst=01:00:00:00:00:00/01:00:00:00:00:00,actions=resubmit(,3)",
            (unsigned long long)GUARDIAN_COOKIE))
        return -1;
    if (flowset_push(fs, "cookie=0x%llx,table=1,priority=0,actions=resubmit(,2)",
                     (unsigned long long)GUARDIAN_COOKIE))
        return -1;
    return 0;
}

/* Emit priority-160 device-specific policy (table 2/4). */
static int gen_device_policy(const struct guardian_config *cfg, struct guardian_flowset *fs,
                             int pt, const char *newm, const char *allowa)
{
    unsigned long long cookie = (unsigned long long)GUARDIAN_COOKIE;
    size_t n = guardian_config_n_device_policy(cfg);
    for (size_t i = 0; i < n; i++) {
        const char *src, *dst_mac, *svc, *action;
        guardian_config_device_policy(cfg, i, &src, &dst_mac, &svc, &action);
        char idbuf[16];
        const char *src_id = group_id_str(cfg, src, idbuf, sizeof idbuf);

        if (is_any(svc)) {
            if (is_allow(action)) {
                if (pt == 4) {
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=160,ct_state=+new,ip,reg0=%s,dl_dst=%s,actions=%s",
                                     cookie, src_id, dst_mac, allowa)) return -1;
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=160,ct_state=+new,ipv6,reg0=%s,dl_dst=%s,actions=%s",
                                     cookie, src_id, dst_mac, allowa)) return -1;
                } else {
                    if (flowset_push(fs, "cookie=0x%llx,table=2,priority=160,reg0=%s,dl_dst=%s,actions=NORMAL",
                                     cookie, src_id, dst_mac)) return -1;
                }
            } else {
                if (flowset_push(fs, "cookie=0x%llx,table=2,priority=160,reg0=%s,dl_dst=%s,actions=drop",
                                 cookie, src_id, dst_mac)) return -1;
                if (pt == 4) {
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=160,ct_state=+new,ip,reg0=%s,dl_dst=%s,actions=drop",
                                     cookie, src_id, dst_mac)) return -1;
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=160,ct_state=+new,ipv6,reg0=%s,dl_dst=%s,actions=drop",
                                     cookie, src_id, dst_mac)) return -1;
                }
            }
            continue;
        }

        struct guardian_service svcs[16];
        size_t ns = guardian_config_expand_service(cfg, svc, svcs, 16);
        for (size_t j = 0; j < ns; j++) {
            const char *proto = svcs[j].proto, *port = svcs[j].port;
            const char *pf = !strcmp(proto, "sctp") ? "sctp_dst" : "tp_dst";
            const char *act = is_allow(action) ? allowa : "drop";
            if (flowset_push(fs, "cookie=0x%llx,table=%d,priority=160%s,ip,%s,dl_dst=%s,%s=%s,reg0=%s,actions=%s",
                             cookie, pt, newm, proto, dst_mac, pf, port, src_id, act)) return -1;
            if (flowset_push(fs, "cookie=0x%llx,table=%d,priority=160%s,%s6,dl_dst=%s,%s=%s,reg0=%s,actions=%s",
                             cookie, pt, newm, proto, dst_mac, pf, port, src_id, act)) return -1;
        }
    }
    return 0;
}

/* Emit priority-150 group service policy (table 2/4). */
static int gen_group_service_policy(const struct guardian_config *cfg, struct guardian_flowset *fs,
                                    int pt, const char *newm, const char *allowa)
{
    unsigned long long cookie = (unsigned long long)GUARDIAN_COOKIE;
    size_t n = guardian_config_n_group_policy(cfg);
    for (size_t i = 0; i < n; i++) {
        const char *src, *dst, *svc, *action;
        guardian_config_group_policy(cfg, i, &src, &dst, &svc, &action);
        if (is_any(svc)) continue; /* handled at priority 100 */

        char sidbuf[16], didbuf[16];
        const char *src_id = group_id_str(cfg, src, sidbuf, sizeof sidbuf);
        const char *dst_id = group_id_str(cfg, dst, didbuf, sizeof didbuf);

        struct guardian_service svcs[16];
        size_t ns = guardian_config_expand_service(cfg, svc, svcs, 16);
        for (size_t j = 0; j < ns; j++) {
            const char *proto = svcs[j].proto, *port = svcs[j].port;
            const char *pf = !strcmp(proto, "sctp") ? "sctp_dst" : "tp_dst";
            const char *act = is_allow(action) ? allowa : "drop";
            if (flowset_push(fs, "cookie=0x%llx,table=%d,priority=150%s,ip,%s,reg0=%s,reg1=%s,%s=%s,actions=%s",
                             cookie, pt, newm, proto, src_id, dst_id, pf, port, act)) return -1;
            if (flowset_push(fs, "cookie=0x%llx,table=%d,priority=150%s,%s6,reg0=%s,reg1=%s,%s=%s,actions=%s",
                             cookie, pt, newm, proto, src_id, dst_id, pf, port, act)) return -1;
        }
    }
    return 0;
}

/* Emit priority-140 intra-group policy (table 2/4). */
static int gen_intra_policy(const struct guardian_config *cfg, struct guardian_flowset *fs,
                            int pt, const char *newm, const char *allowa)
{
    unsigned long long cookie = (unsigned long long)GUARDIAN_COOKIE;
    size_t n = guardian_config_n_intra_policy(cfg);
    for (size_t i = 0; i < n; i++) {
        const char *grp, *svc, *action;
        guardian_config_intra_policy(cfg, i, &grp, &svc, &action);
        char idbuf[16];
        const char *id = group_id_str(cfg, grp, idbuf, sizeof idbuf);

        if (is_any(svc)) {
            if (is_allow(action)) {
                if (pt == 4) {
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=140,ct_state=+new,ip,reg0=%s,reg1=%s,actions=%s",
                                     cookie, id, id, allowa)) return -1;
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=140,ct_state=+new,ipv6,reg0=%s,reg1=%s,actions=%s",
                                     cookie, id, id, allowa)) return -1;
                } else {
                    if (flowset_push(fs, "cookie=0x%llx,table=2,priority=140,reg0=%s,reg1=%s,actions=NORMAL",
                                     cookie, id, id)) return -1;
                }
            } else {
                if (flowset_push(fs, "cookie=0x%llx,table=2,priority=140,reg0=%s,reg1=%s,actions=drop",
                                 cookie, id, id)) return -1;
                if (pt == 4) {
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=140,ct_state=+new,ip,reg0=%s,reg1=%s,actions=drop",
                                     cookie, id, id)) return -1;
                    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=140,ct_state=+new,ipv6,reg0=%s,reg1=%s,actions=drop",
                                     cookie, id, id)) return -1;
                }
            }
            continue;
        }

        struct guardian_service svcs[16];
        size_t ns = guardian_config_expand_service(cfg, svc, svcs, 16);
        for (size_t j = 0; j < ns; j++) {
            const char *proto = svcs[j].proto, *port = svcs[j].port;
            const char *pf = !strcmp(proto, "sctp") ? "sctp_dst" : "tp_dst";
            const char *act = is_allow(action) ? allowa : "drop";
            if (flowset_push(fs, "cookie=0x%llx,table=%d,priority=140%s,ip,%s,reg0=%s,reg1=%s,%s=%s,actions=%s",
                             cookie, pt, newm, proto, id, id, pf, port, act)) return -1;
            if (flowset_push(fs, "cookie=0x%llx,table=%d,priority=140%s,%s6,reg0=%s,reg1=%s,%s=%s,actions=%s",
                             cookie, pt, newm, proto, id, id, pf, port, act)) return -1;
        }
    }
    return 0;
}

/* Emit priority-110 ARP/ND allowance, 105 reflexive return, 100 group ANY. */
static int gen_group_any_policy(const struct guardian_config *cfg, struct guardian_flowset *fs,
                                int pt)
{
    unsigned long long cookie = (unsigned long long)GUARDIAN_COOKIE;
    size_t n = guardian_config_n_group_policy(cfg);

    for (size_t i = 0; i < n; i++) {
        const char *src, *dst, *svc, *action;
        guardian_config_group_policy(cfg, i, &src, &dst, &svc, &action);
        if (!is_allow(action)) continue;
        char sidbuf[16], didbuf[16];
        const char *src_id = group_id_str(cfg, src, sidbuf, sizeof sidbuf);
        const char *dst_id = group_id_str(cfg, dst, didbuf, sizeof didbuf);

        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=110,arp,reg0=%s,reg1=%s,actions=NORMAL", cookie, src_id, dst_id)) return -1;
        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=110,arp,reg0=%s,reg1=%s,actions=NORMAL", cookie, dst_id, src_id)) return -1;
        for (int t = 135; t <= 136; t++) {
            if (flowset_push(fs, "cookie=0x%llx,table=2,priority=110,icmp6,icmpv6_type=%d,reg0=%s,reg1=%s,actions=NORMAL", cookie, t, src_id, dst_id)) return -1;
            if (flowset_push(fs, "cookie=0x%llx,table=2,priority=110,icmp6,icmpv6_type=%d,reg0=%s,reg1=%s,actions=NORMAL", cookie, t, dst_id, src_id)) return -1;
        }
        (void)svc;
    }

    for (size_t i = 0; i < n; i++) {
        const char *src, *dst, *svc, *action;
        guardian_config_group_policy(cfg, i, &src, &dst, &svc, &action);
        if (!is_any(svc) || !is_allow(action)) continue;
        char sidbuf[16], didbuf[16];
        const char *src_id = group_id_str(cfg, src, sidbuf, sizeof sidbuf);
        const char *dst_id = group_id_str(cfg, dst, didbuf, sizeof didbuf);

        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=105,icmp,reg0=%s,reg1=%s,icmp_type=0,actions=NORMAL", cookie, dst_id, src_id)) return -1;
        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=105,icmp6,reg0=%s,reg1=%s,icmpv6_type=129,actions=NORMAL", cookie, dst_id, src_id)) return -1;
        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=105,tcp,reg0=%s,reg1=%s,tcp_flags=+ack,actions=NORMAL", cookie, dst_id, src_id)) return -1;
        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=105,tcp6,reg0=%s,reg1=%s,tcp_flags=+ack,actions=NORMAL", cookie, dst_id, src_id)) return -1;
    }

    for (size_t i = 0; i < n; i++) {
        const char *src, *dst, *svc, *action;
        guardian_config_group_policy(cfg, i, &src, &dst, &svc, &action);
        if (!is_any(svc)) continue;
        char sidbuf[16], didbuf[16];
        const char *src_id = group_id_str(cfg, src, sidbuf, sizeof sidbuf);
        const char *dst_id = group_id_str(cfg, dst, didbuf, sizeof didbuf);

        if (!is_allow(action)) {
            if (flowset_push(fs, "cookie=0x%llx,table=2,priority=100,reg0=%s,reg1=%s,actions=drop", cookie, src_id, dst_id)) return -1;
            if (pt == 4) {
                if (flowset_push(fs, "cookie=0x%llx,table=4,priority=100,ct_state=+new,ip,reg0=%s,reg1=%s,actions=drop", cookie, src_id, dst_id)) return -1;
                if (flowset_push(fs, "cookie=0x%llx,table=4,priority=100,ct_state=+new,ipv6,reg0=%s,reg1=%s,actions=drop", cookie, src_id, dst_id)) return -1;
            }
        }
    }
    return 0;
}

static int gen_stateful_table4(const struct guardian_config *cfg, struct guardian_flowset *fs, int pt)
{
    if (pt != 4) return 0;
    unsigned long long cookie = (unsigned long long)GUARDIAN_COOKIE;

    if (guardian_config_drop_invalid(cfg)) {
        if (flowset_push(fs, "cookie=0x%llx,table=4,priority=210,ip,ct_state=+inv,actions=drop", cookie)) return -1;
        if (flowset_push(fs, "cookie=0x%llx,table=4,priority=210,ipv6,ct_state=+inv,actions=drop", cookie)) return -1;
    }
    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=200,ip,ct_state=+est,actions=NORMAL", cookie)) return -1;
    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=200,ipv6,ct_state=+est,actions=NORMAL", cookie)) return -1;
    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=200,ip,ct_state=+rel,actions=NORMAL", cookie)) return -1;
    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=200,ipv6,ct_state=+rel,actions=NORMAL", cookie)) return -1;
    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=1,ip,ct_state=+new,actions=ct(commit,zone=%d),NORMAL", cookie, GUARDIAN_CT_ZONE)) return -1;
    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=1,ipv6,ct_state=+new,actions=ct(commit,zone=%d),NORMAL", cookie, GUARDIAN_CT_ZONE)) return -1;
    if (flowset_push(fs, "cookie=0x%llx,table=4,priority=0,actions=NORMAL", cookie)) return -1;
    return 0;
}

/* Read the live FDB (port, mac) snapshot for a bridge via the same unixctl
 * path ovs-appctl uses: read ovs-vswitchd's pidfile, build its .ctl socket,
 * and transact "fdb/show" -- directly against libopenvswitch, no shell fork. */
static size_t read_fdb(const char *bridge, struct fdb_entry *out, size_t max)
{
    char pidfile[256];
    snprintf(pidfile, sizeof pidfile, "%s/ovs-vswitchd.pid", ovs_rundir());
    pid_t pid = read_pidfile(pidfile);
    if (pid < 0)
        return 0;

    char sock[256];
    snprintf(sock, sizeof sock, "%s/ovs-vswitchd.%ld.ctl", ovs_rundir(), (long)pid);
    struct jsonrpc *client = NULL;
    if (unixctl_client_create(sock, &client) || !client)
        return 0;

    char *result = NULL, *cmd_error = NULL;
    char *argv[] = { (char *)bridge };
    int error = unixctl_client_transact(client, "fdb/show", 1, argv,
                                        &result, &cmd_error);
    jsonrpc_close(client);
    if (error || cmd_error || !result) {
        free(result);
        free(cmd_error);
        return 0;
    }

    size_t n = 0;
    char *save = NULL;
    for (char *line = strtok_r(result, "\n", &save); line && n < max;
         line = strtok_r(NULL, "\n", &save)) {
        char port[16], mac[GUARDIAN_NAME_MAX];
        int vlan; long age;
        if (sscanf(line, "%15s %d %63s %ld", port, &vlan, mac, &age) != 4)
            continue;
        (void)vlan;
        (void)age;
        if (!strcmp(port, "port")) continue; /* header row */
        bool numeric = true;
        for (char *c = port; *c; c++) if (!isdigit((unsigned char)*c)) { numeric = false; break; }
        if (!numeric) continue;
        snprintf(out[n].port, sizeof out[n].port, "%s", port);
        snprintf(out[n].mac, sizeof out[n].mac, "%s", mac);
        n++;
    }
    free(result);
    free(cmd_error);
    return n;
}

/* Table 3: multicast/broadcast delivered as per-recipient unicast (mc2uc). */
static int gen_multicast_table(const struct guardian_config *cfg, struct guardian_flowset *fs,
                               const char *bridge)
{
    unsigned long long cookie = (unsigned long long)GUARDIAN_COOKIE;

    struct fdb_entry fdb[MAX_FDB];
    size_t n_fdb = read_fdb(bridge, fdb, MAX_FDB);

    size_t n_sg = guardian_config_n_src_groups(cfg);
    for (size_t s = 0; s < n_sg; s++) {
        const char *sg = guardian_config_src_group(cfg, s);
        uint32_t sg_id = guardian_config_group_id(cfg, sg);

        char actions[2048];
        size_t alen = 0;
        for (size_t f = 0; f < n_fdb; f++) {
            const char *rgrp = guardian_config_group_of_mac(cfg, fdb[f].mac);
            if (rgrp && guardian_config_policy_is_drop(cfg, sg, rgrp)) continue;
            if (alen >= sizeof actions) break;
            int w = snprintf(actions + alen, sizeof actions - alen,
                             "%smod_dl_dst:%s,output:%s",
                             alen ? "," : "", fdb[f].mac, fdb[f].port);
            if (w < 0 || (size_t)w >= sizeof actions - alen) { alen = sizeof actions; break; }
            alen += (size_t)w;
        }
        if (flowset_push(fs, "cookie=0x%llx,table=3,priority=100,reg0=%u,actions=%s",
                         cookie, sg_id, alen ? actions : "drop"))
            return -1;

        /* Service-scoped multicast exceptions (re-include recipients allowed
         * for a specific service even if the coarse group policy is DROP). */
        size_t n_gp = guardian_config_n_group_policy(cfg);
        for (size_t i = 0; i < n_gp; i++) {
            const char *src, *dst, *svc, *action;
            guardian_config_group_policy(cfg, i, &src, &dst, &svc, &action);
            if (strcasecmp(src, sg) || !is_allow(action) || is_any(svc)) continue;

            struct guardian_service svcs[16];
            size_t ns = guardian_config_expand_service(cfg, svc, svcs, 16);
            for (size_t j = 0; j < ns; j++) {
                const char *proto = svcs[j].proto, *port = svcs[j].port;
                const char *pf = !strcmp(proto, "sctp") ? "sctp_dst" : "tp_dst";

                char pacts[2048];
                size_t plen = 0;
                for (size_t f = 0; f < n_fdb; f++) {
                    const char *rgrp = guardian_config_group_of_mac(cfg, fdb[f].mac);
                    if (rgrp && guardian_config_policy_is_drop(cfg, sg, rgrp) &&
                        !guardian_config_service_allows_port(cfg, sg, rgrp, proto, port))
                        continue;
                    if (plen >= sizeof pacts) break;
                    int w = snprintf(pacts + plen, sizeof pacts - plen,
                                     "%smod_dl_dst:%s,output:%s",
                                     plen ? "," : "", fdb[f].mac, fdb[f].port);
                    if (w < 0 || (size_t)w >= sizeof pacts - plen) { plen = sizeof pacts; break; }
                    plen += (size_t)w;
                }
                const char *acts = plen ? pacts : "drop";
                if (flowset_push(fs, "cookie=0x%llx,table=3,priority=110,reg0=%u,%s,%s=%s,actions=%s",
                                 cookie, sg_id, proto, pf, port, acts)) return -1;
                if (flowset_push(fs, "cookie=0x%llx,table=3,priority=110,reg0=%u,%s6,%s=%s,actions=%s",
                                 cookie, sg_id, proto, pf, port, acts)) return -1;
            }
        }
    }
    if (flowset_push(fs, "cookie=0x%llx,table=3,priority=0,actions=NORMAL", cookie))
        return -1;
    return 0;
}

struct guardian_flowset *guardian_flows_generate(const struct guardian_config *cfg)
{
    struct guardian_flowset *fs = calloc(1, sizeof *fs);
    if (!fs) return NULL;

    bool stateful = guardian_config_stateful(cfg);
    int pt = stateful ? 4 : 2;
    const char *newm = stateful ? ",ct_state=+new" : "";
    char allowa[64];
    if (stateful)
        snprintf(allowa, sizeof allowa, "ct(commit,zone=%d),NORMAL", GUARDIAN_CT_ZONE);
    else
        snprintf(allowa, sizeof allowa, "NORMAL");

    if (gen_device_tables(cfg, fs)) goto fail;

    if (pt == 4) {
        unsigned long long cookie = (unsigned long long)GUARDIAN_COOKIE;
        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=200,ip,ct_state=-trk,actions=ct(table=4,zone=%d)", cookie, GUARDIAN_CT_ZONE)) goto fail;
        if (flowset_push(fs, "cookie=0x%llx,table=2,priority=200,ipv6,ct_state=-trk,actions=ct(table=4,zone=%d)", cookie, GUARDIAN_CT_ZONE)) goto fail;
    }

    if (gen_device_policy(cfg, fs, pt, newm, allowa)) goto fail;
    if (gen_group_service_policy(cfg, fs, pt, newm, allowa)) goto fail;
    if (gen_intra_policy(cfg, fs, pt, newm, allowa)) goto fail;
    if (gen_group_any_policy(cfg, fs, pt)) goto fail;

    if (flowset_push(fs, "cookie=0x%llx,table=2,priority=0,actions=NORMAL", (unsigned long long)GUARDIAN_COOKIE)) goto fail;

    if (gen_stateful_table4(cfg, fs, pt)) goto fail;
    if (gen_multicast_table(cfg, fs, GUARDIAN_BRIDGE)) goto fail;

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
