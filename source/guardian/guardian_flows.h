/*
 * Guardian policy -> OpenFlow flow translation (port of gen_flows).
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GUARDIAN_FLOWS_H
#define GUARDIAN_FLOWS_H

#include <stddef.h>

struct guardian_config;

/* A desired flow set, as flow-mod text lines (one flow per line), matching the
 * format guardian.sh emits. Kept as text for the initial port so it can be
 * validated against `guardian.sh dry-run` before switching to in-memory
 * ofputil_flow_mod encoding. */
struct guardian_flowset {
    char **lines;
    size_t n;
};

/* Build the desired flow set from a parsed config. Returns NULL on error. */
struct guardian_flowset *guardian_flows_generate(const struct guardian_config *cfg);
void guardian_flowset_free(struct guardian_flowset *fs);

#endif /* GUARDIAN_FLOWS_H */
