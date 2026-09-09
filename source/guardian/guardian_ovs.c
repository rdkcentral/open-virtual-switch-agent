/*
 * Guardian OVS I/O via libopenvswitch (PORTING.md Option A).
 *
 * Opens a management vconn to the bridge and drives flow changes over
 * OpenFlow directly -- no ovs-ofctl fork. apply/clear use flow-mods parsed
 * with parse_ofp_flow_mod_str(); show uses vconn_dump_flows() filtered by our
 * cookie.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "guardian_ovs.h"
#include "guardian.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <openflow/openflow.h>
#include <openvswitch/vconn.h>
#include <openvswitch/ofpbuf.h>
#include <openvswitch/ofp-flow.h>
#include <openvswitch/ofp-protocol.h>
#include <openvswitch/match.h>
#include <openvswitch/dynamic-string.h>
#include <openvswitch/types.h>
#include <openvswitch/util.h>

/* OVS runtime dir holding the <bridge>.mgmt punix socket. Override at build. */
#ifndef GUARDIAN_OVS_RUNDIR
#define GUARDIAN_OVS_RUNDIR "/var/run/openvswitch"
#endif

/* Endian-safe host uint64 -> ovs_be64 (network byte order). */
static ovs_be64 host_to_be64(uint64_t v)
{
    uint8_t b[8];
    for (int i = 0; i < 8; i++)
        b[7 - i] = (uint8_t)(v >> (8 * i));
    ovs_be64 r;
    memcpy(&r, b, sizeof r);
    return r;
}

/* Open a management vconn to the bridge and negotiate a protocol. */
static int open_bridge(const char *bridge, struct vconn **vconnp,
                       enum ofputil_protocol *protocolp)
{
    char name[256];
    snprintf(name, sizeof name, "unix:%s/%s.mgmt", GUARDIAN_OVS_RUNDIR, bridge);

    int error = vconn_open(name, OFPUTIL_DEFAULT_VERSIONS, 0 /*dscp*/, vconnp);
    if (error) {
        fprintf(stderr, "guardian: vconn_open(%s) failed: %s\n",
                name, strerror(error));
        return -1;
    }
    error = vconn_connect_block(*vconnp, -1);
    if (error) {
        fprintf(stderr, "guardian: connect to %s failed: %s\n",
                name, strerror(error));
        vconn_close(*vconnp);
        return -1;
    }
    *protocolp = ofputil_protocol_from_ofp_version(vconn_get_version(*vconnp));
    if (!*protocolp) {
        fprintf(stderr, "guardian: unsupported OpenFlow version on %s\n", bridge);
        vconn_close(*vconnp);
        return -1;
    }
    return 0;
}

/* Parse one flow-mod string and send it over the vconn. */
static int send_flow_mod(struct vconn *vconn, enum ofputil_protocol protocol,
                         const char *str, int command)
{
    struct ofputil_flow_mod fm;
    enum ofputil_protocol usable;
    char *err = parse_ofp_flow_mod_str(&fm, str, NULL, NULL, command, &usable);
    if (err) {
        fprintf(stderr, "guardian: bad flow '%s': %s\n", str, err);
        free(err);
        return -1;
    }

    struct ofpbuf *msg = ofputil_encode_flow_mod(&fm, protocol);
    struct ofpbuf *reply = NULL;
    int error = vconn_transact_noreply(vconn, msg, &reply);
    if (reply) {
        ofpbuf_delete(reply);
    }
    free(fm.ofpacts);
    minimatch_destroy(&fm.match);

    if (error) {
        fprintf(stderr, "guardian: send flow failed: %s\n", strerror(error));
        return -1;
    }
    return 0;
}

/* "cookie=0x9110/-1" match string selecting all Guardian flows. */
static void cookie_match(char *buf, size_t len)
{
    snprintf(buf, len, "cookie=0x%llx/-1", (unsigned long long)GUARDIAN_COOKIE);
}

int guardian_ovs_apply(const char *bridge, const struct guardian_flowset *desired)
{
    struct vconn *vconn;
    enum ofputil_protocol protocol;
    if (open_bridge(bridge, &vconn, &protocol))
        return -1;

    /* Full-table replace for now: delete our cookie, then add the desired set.
     * TODO: in-memory delta via vconn_dump_flows() (add/del only what changed). */
    char del[64];
    cookie_match(del, sizeof del);
    int rc = send_flow_mod(vconn, protocol, del, OFPFC_DELETE);

    for (size_t i = 0; rc == 0 && i < desired->n; i++)
        rc = send_flow_mod(vconn, protocol, desired->lines[i], OFPFC_ADD);

    vconn_close(vconn);
    return rc;
}

int guardian_ovs_clear(const char *bridge)
{
    struct vconn *vconn;
    enum ofputil_protocol protocol;
    if (open_bridge(bridge, &vconn, &protocol))
        return -1;

    char del[64];
    cookie_match(del, sizeof del);
    int rc = send_flow_mod(vconn, protocol, del, OFPFC_DELETE);

    vconn_close(vconn);
    return rc;
}

int guardian_ovs_show(const char *bridge)
{
    struct vconn *vconn;
    enum ofputil_protocol protocol;
    if (open_bridge(bridge, &vconn, &protocol))
        return -1;

    struct ofputil_flow_stats_request fsr;
    memset(&fsr, 0, sizeof fsr);
    fsr.aggregate = false;
    match_init_catchall(&fsr.match);
    fsr.cookie = host_to_be64(GUARDIAN_COOKIE);
    fsr.cookie_mask = OVS_BE64_MAX;
    fsr.out_port = OFPP_ANY;
    fsr.out_group = OFPG_ANY;
    fsr.table_id = OFPTT_ALL;

    struct ofputil_flow_stats *fses = NULL;
    size_t n = 0;
    int error = vconn_dump_flows(vconn, &fsr, protocol, &fses, &n);
    if (error) {
        fprintf(stderr, "guardian: dump-flows failed: %s\n", strerror(error));
        vconn_close(vconn);
        return -1;
    }

    if (n == 0) {
        printf("No Guardian flows.\n");
    } else {
        for (size_t i = 0; i < n; i++) {
            struct ds ds = DS_EMPTY_INITIALIZER;
            ofputil_flow_stats_format(&ds, &fses[i], NULL, NULL, true);
            printf("%s\n", ds_cstr(&ds));
            ds_destroy(&ds);
        }
    }

    free(fses);
    vconn_close(vconn);
    return 0;
}
