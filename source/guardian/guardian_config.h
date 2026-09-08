/*
 * Guardian config parsing + delta computation.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GUARDIAN_CONFIG_H
#define GUARDIAN_CONFIG_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Parsed configuration. Populated from the INI-style guardian.cfg. */
struct guardian_config;

/* Load and validate a config file. Returns NULL and sets *err (malloc'd) on
 * failure; caller frees the returned config with guardian_config_free(). */
struct guardian_config *guardian_config_load(const char *path, char **err);
void guardian_config_free(struct guardian_config *cfg);

/* Resolve a group name to its numeric bitmask id; returns 0 if unknown. */
uint32_t guardian_config_group_id(const struct guardian_config *cfg,
                                  const char *name);

/* Whether stateful (conntrack) mode is enabled in [defaults]. */
bool guardian_config_stateful(const struct guardian_config *cfg);

#endif /* GUARDIAN_CONFIG_H */
