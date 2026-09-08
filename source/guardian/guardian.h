/*
 * Guardian: native C port of guardian.sh.
 * Shared constants and core data structures.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef GUARDIAN_H
#define GUARDIAN_H

#include <stdint.h>
#include <stdbool.h>

/* Match the live values used by guardian.sh so existing tooling keeps working. */
#define GUARDIAN_BRIDGE   "brlan0"
#define GUARDIAN_COOKIE   0x9110ULL
#define GUARDIAN_CT_ZONE  9110

/* Commands accepted on the CLI. */
enum guardian_cmd {
    GUARDIAN_CMD_UNKNOWN = 0,
    GUARDIAN_CMD_APPLY,
    GUARDIAN_CMD_DRY_RUN,
    GUARDIAN_CMD_CLEAR,
    GUARDIAN_CMD_SHOW,
    GUARDIAN_CMD_STATS,
    GUARDIAN_CMD_DIAGNOSTICS,
    GUARDIAN_CMD_LOAD_TEST,
};

#endif /* GUARDIAN_H */
