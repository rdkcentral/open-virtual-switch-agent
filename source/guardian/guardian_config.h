/*
 * Guardian config parsing + accessors.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GUARDIAN_CONFIG_H
#define GUARDIAN_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define GUARDIAN_NAME_MAX 64

/* Parsed configuration. Populated from the INI-style guardian.cfg. */
struct guardian_config;

/* Load and validate a config file. Returns NULL and sets *err (malloc'd) on
 * failure; caller frees the returned config with guardian_config_free(). */
struct guardian_config *guardian_config_load(const char *path, char **err);
void guardian_config_free(struct guardian_config *cfg);

/* Resolve a group name to its numeric bitmask id; returns 0 if unknown. */
uint32_t guardian_config_group_id(const struct guardian_config *cfg,
                                  const char *name);

/* [defaults] */
bool guardian_config_stateful(const struct guardian_config *cfg);
bool guardian_config_drop_invalid(const struct guardian_config *cfg);

/* [devices]: mac -> group name. */
size_t guardian_config_n_devices(const struct guardian_config *cfg);
void guardian_config_device(const struct guardian_config *cfg, size_t i,
                            const char **mac, const char **group);

/* Return the configured group of a MAC, or NULL if unmanaged. */
const char *guardian_config_group_of_mac(const struct guardian_config *cfg,
                                         const char *mac);

/* Unique source groups seen in [devices], for table-3 multicast generation. */
size_t guardian_config_n_src_groups(const struct guardian_config *cfg);
const char *guardian_config_src_group(const struct guardian_config *cfg, size_t i);

/* [group_policy]: SRC_GROUP DST_GROUP SERVICE ACTION. */
size_t guardian_config_n_group_policy(const struct guardian_config *cfg);
void guardian_config_group_policy(const struct guardian_config *cfg, size_t i,
                                  const char **src, const char **dst,
                                  const char **svc, const char **action);

/* [intra_group_policy]: GROUP SERVICE ACTION. */
size_t guardian_config_n_intra_policy(const struct guardian_config *cfg);
void guardian_config_intra_policy(const struct guardian_config *cfg, size_t i,
                                  const char **grp, const char **svc,
                                  const char **action);

/* [device_policy]: SRC_GROUP DST_MAC SERVICE ACTION. */
size_t guardian_config_n_device_policy(const struct guardian_config *cfg);
void guardian_config_device_policy(const struct guardian_config *cfg, size_t i,
                                   const char **src, const char **dst_mac,
                                   const char **svc, const char **action);

/* A single protocol/port pair a service expands to. */
struct guardian_service {
    char proto[16];
    char port[16];
};

/* Expand a service name (handles [service_macros]) to one or more basic
 * proto/port pairs. Returns the number written into out (capped at max). */
size_t guardian_config_expand_service(const struct guardian_config *cfg,
                                      const char *svc,
                                      struct guardian_service *out, size_t max);

/* True if an explicit "src dst ANY DROP" group_policy row exists. */
bool guardian_config_policy_is_drop(const struct guardian_config *cfg,
                                    const char *src_grp, const char *dst_grp);

/* True if group_policy explicitly ALLOWs proto/port from src to dst. */
bool guardian_config_service_allows_port(const struct guardian_config *cfg,
                                         const char *src_grp, const char *dst_grp,
                                         const char *proto, const char *port);

#endif /* GUARDIAN_CONFIG_H */
