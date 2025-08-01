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

#include <jansson.h>
#include <string.h>
#include "common/OvsAgentLog.h"
#include "OvsDbApi/OvsDbDefs.h"

typedef OvsDb_Base_Receipt*(*receipt_parser)(json_t* receipt);

static OvsDb_Base_Receipt* insert_receipt_parser(json_t* receipt);
static OvsDb_Base_Receipt* monitor_receipt_parser(json_t* receipt);
static OvsDb_Base_Receipt* monitor_cancel_receipt_parser(json_t* receipt);
static OvsDb_Base_Receipt* delete_receipt_parser(json_t* receipt);

const static receipt_parser parser_lkup_tbl[] = {
    [OVSDB_INSERT_RECEIPT_ID] = insert_receipt_parser,
    [OVSDB_MONITOR_RECEIPT_ID] = monitor_receipt_parser,
    [OVSDB_MONITOR_CANCEL_RECEIPT_ID] = monitor_cancel_receipt_parser,
    [OVSDB_DELETE_RECEIPT_ID] = delete_receipt_parser
};

OvsDb_Base_Receipt* ovsdb_parse_result(OVSDB_RECEIPT_ID type, json_t* receipt)
{
    //TODO: Add a check to make sure type is within range

    if (!receipt)
    {
        OvsDbApiError("%s called with NULL receipt.\n", __func__);
        return NULL;
    }

    return parser_lkup_tbl[type](receipt);
}

static OvsDb_Base_Receipt* insert_receipt_parser(json_t* receipt)
{
    if (!receipt){
        OvsDbApiError("%s called with NULL receipt.\n", __func__);
        return NULL;
    }

    if (json_is_array(receipt) == 0)
    {
        OvsDbApiError("%s receipt object is not an array\n", __func__);
        return NULL;
    }

    json_t* json_obj = json_array_get(receipt, 0);
    json_t* json_uuid = json_object_get(json_obj, OVSDB_TABLE_UUID);

    if (json_is_array(json_uuid) == 0)
    {
        OvsDbApiError("%s json_uuid is not an array\n", __func__);
        return NULL;
    }

    json_t* json_uuid2 = json_array_get(json_uuid, 0);
    if (!json_uuid2 || json_is_string(json_uuid2) == 0)
    {
        OvsDbApiError("%s json_uuid2 is not correct.\n", __func__);
        return NULL;
    }

    if (strcmp(json_string_value(json_uuid2), OVSDB_TABLE_UUID) != 0)
    {
        OvsDbApiError("json_uuid2 is not 'uuid'.\n");
        return NULL;
    }

    OvsDb_Insert_Receipt* insert_receipt = (OvsDb_Insert_Receipt*) malloc(sizeof(OvsDb_Insert_Receipt));
    if (!insert_receipt)
    {
        OvsDbApiError("%s memory allocation failed!\n", __func__);
        return NULL;
    }

    memset(insert_receipt, 0, sizeof(OvsDb_Insert_Receipt));
    insert_receipt->receipt_id = OVSDB_INSERT_RECEIPT_ID;
    strcpy(insert_receipt->uuid, json_string_value(json_array_get(json_uuid,1)));

    return (OvsDb_Base_Receipt*)insert_receipt;
}

static OvsDb_Base_Receipt* monitor_receipt_parser(json_t* receipt)
{
    if (!receipt)
    {
        OvsDbApiError("%s called with NULL receipt.\n", __func__);
        return NULL;
    }

    //TODO: Implement this to actually parse monitor receipts
    OvsDb_Monitor_Receipt* update_receipt = (OvsDb_Monitor_Receipt*) malloc(sizeof(OvsDb_Monitor_Receipt));
    if (!update_receipt)
    {
        OvsDbApiError("%s memory allocation failed!\n", __func__);
        return NULL;
    }

    memset(update_receipt, 0, sizeof(OvsDb_Monitor_Receipt));
    update_receipt->receipt_id = OVSDB_MONITOR_RECEIPT_ID;
    update_receipt->update_count = 0; // TODO Figure out why this is not used.
    return (OvsDb_Base_Receipt*)update_receipt;
}

static OvsDb_Base_Receipt* monitor_cancel_receipt_parser(json_t* receipt)
{
    if (!receipt)
    {
        OvsDbApiError("%s called with NULL receipt.\n", __func__);
        return NULL;
    }

    OvsDb_Monitor_Cancel_Receipt* mon_cancel_receipt = (OvsDb_Monitor_Cancel_Receipt*) malloc(sizeof(OvsDb_Monitor_Cancel_Receipt));
    if (!mon_cancel_receipt)
    {
        OvsDbApiError("%s memory allocation failed!\n", __func__);
        return NULL;
    }

    memset(mon_cancel_receipt, 0, sizeof(OvsDb_Monitor_Cancel_Receipt));
    mon_cancel_receipt->is_successful = true; // TODO Figure out why this is not used.
    mon_cancel_receipt->receipt_id = OVSDB_MONITOR_CANCEL_RECEIPT_ID;
    return (OvsDb_Base_Receipt*)mon_cancel_receipt;
}

static OvsDb_Base_Receipt* delete_receipt_parser(json_t* receipt)
{
    if (!receipt){
        OvsDbApiError("%s called with NULL receipt.\n", __func__);
        return NULL;
    }

    if (json_is_array(receipt) == 0)
    {
        OvsDbApiError("%s receipt object is not an array\n", __func__);
        return NULL;
    }

    json_t* json_obj = json_array_get(receipt, 0);
    json_t* json_count = json_object_get(json_obj, "count");
    if (!json_count || json_is_integer(json_count) == 0)
    {
        OvsDbApiError("%s count is not correct.\n", __func__);
        return NULL;
    }

    OvsDb_Delete_Receipt* delete_receipt = (OvsDb_Delete_Receipt*) malloc(sizeof(OvsDb_Delete_Receipt));
    if (!delete_receipt)
    {
        OvsDbApiError("%s memory allocation failed!\n", __func__);
        return NULL;
    }

    memset(delete_receipt, 0, sizeof(OvsDb_Delete_Receipt));
    delete_receipt->receipt_id = OVSDB_DELETE_RECEIPT_ID;
    delete_receipt->count = (int)json_integer_value(json_count);

    return (OvsDb_Base_Receipt*)delete_receipt;
}
