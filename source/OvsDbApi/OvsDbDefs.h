/*
* Copyright 2020 Comcast Cable Communications Management, LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* SPDX-License-Identifier: Apache-2.0
*/


#ifndef OVS_DB_DEFS_H_
#define OVS_DB_DEFS_H_

#include <stdbool.h>
#include "OvsConfig.h"

#define OVSDB_DEF_DB "Open_vSwitch"
#define OVSDB_ERROR_RECEIPT_SIZE 64

#define GATEWAY_CONFIG_TABLE_NAME "Gateway_Config"
#define FEEDBACK_TABLE_NAME       "Feedback"

#define OVSDB_TABLE_UUID     "uuid"
#define OVSDB_TABLE_UUID_ALT "_uuid"

typedef enum {
    OVSDB_UNKNOWN_RECEIPT_ID = 0,
    OVSDB_INSERT_RECEIPT_ID,
    OVSDB_MONITOR_RECEIPT_ID,
    OVSDB_MONITOR_CANCEL_RECEIPT_ID,
    OVSDB_DELETE_RECEIPT_ID
} OVSDB_RECEIPT_ID;

#define OVSDB_BASE_RECEIPT \
    OVSDB_RECEIPT_ID receipt_id; \
    char error[OVSDB_ERROR_RECEIPT_SIZE]

typedef struct {
    OVSDB_BASE_RECEIPT;
} OvsDb_Base_Receipt;

typedef struct {
    OVSDB_BASE_RECEIPT;
    char uuid[MAX_UUID_LEN + 1];
} OvsDb_Insert_Receipt;

/** Turn this into a count, and a list of Rdkb_Table_Config? **/
typedef struct {
    OVSDB_BASE_RECEIPT;
    int update_count;
} OvsDb_Monitor_Receipt;

/** what should be in this struct **/
typedef struct{
    OVSDB_BASE_RECEIPT;
    bool is_successful;
} OvsDb_Monitor_Cancel_Receipt;

typedef struct {
    OVSDB_BASE_RECEIPT;
    int count;
} OvsDb_Delete_Receipt;

typedef void (*ovsdb_receipt_cb) (const char* rID, const OvsDb_Base_Receipt* receipt_result);
typedef ovs_interact_cb ovsdb_mon_cb;

#endif /* OVS_DB_DEFS_H_ */
