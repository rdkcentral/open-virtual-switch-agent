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

#include <stdio.h>
#include <string.h>
#include "OvsDbApi/receipt_list.h"
#include "OvsDbApi/OvsDbDefs.h"
#include "common/OvsAgentLog.h"
#include "OvsDbApi/json_parser/receipt_parser.h"

//TODO: Update later to hash table?
//TODO: Add clean up to this list in deinit
typedef struct receipt_node_t
{
    char rid[MAX_UUID_LEN+1];           //Unique ID to identify messages
    ovsdb_receipt_cb callback;          //Callback to invoke when message is found
    OVSDB_RECEIPT_ID receipt_type;
    struct receipt_node_t* next;        //Next in the list
} receipt_node_t;

static receipt_node_t* msg_list = NULL;

OVS_STATUS receipt_list_add(const char* rid, OVSDB_RECEIPT_ID receipt_type, ovsdb_receipt_cb cb)
{
    OvsDbApiDebug("%s adding rid %s with receipt type %d to list...\n",
        __func__, rid, receipt_type);

    if (!rid)
    {
        OvsDbApiError("%s 'rid' is NULL", __func__);
        return OVS_FAILED_STATUS;
    }

    receipt_node_t* new_node = malloc(sizeof(receipt_node_t));
    if (!new_node)
    {
        OvsDbApiError("%s failed to allocate new receipt node for rid: %s\n",
            __func__, rid);
        return OVS_FAILED_STATUS;
    }

    memset(new_node->rid, 0, sizeof(new_node->rid));
    strncpy(new_node->rid, rid, MAX_UUID_LEN);
    new_node->callback = cb;
    new_node->receipt_type = receipt_type;
    new_node->next = NULL;

    if (!msg_list)
    {
        msg_list = new_node;
        return OVS_SUCCESS_STATUS;
    }

    receipt_node_t* temp = msg_list;
    while (temp->next != NULL)
    {
        temp = temp->next;
    }
    temp->next = new_node;
    return OVS_SUCCESS_STATUS;
}

OVS_STATUS receipt_list_process(const char* rid, json_t* result)
{
    receipt_node_t* curr = NULL;
    receipt_node_t* next = NULL;

    OvsDbApiDebug("%s parsing rid: %s\n", __func__, rid);

    if (!rid)
    {
        OvsDbApiError("%s 'rid' is NULL", __func__);
        return OVS_FAILED_STATUS;
    }

    if (!msg_list)
    {
        OvsDbApiError("%s Cannot process receipt with rid: %s as receipt list is empty.\n",
            __func__, rid);
        return OVS_FAILED_STATUS;
    }

    if (strncmp(rid, msg_list->rid, sizeof(msg_list->rid)) == 0)
    {
        OvsDb_Base_Receipt* parsed_result = ovsdb_parse_result(msg_list->receipt_type, result);
        if (!parsed_result)  //TODO: Call callback with error rather than exit
        {
            OvsDbApiError("%s failed to parse result of receipt with rid: %s\n",
                __func__, rid);
            return OVS_FAILED_STATUS;
        }

        msg_list->callback(rid, parsed_result);
        free(parsed_result);

        curr = msg_list;
        msg_list = msg_list->next;
        free(curr);
        return OVS_SUCCESS_STATUS;
    }

    curr = msg_list;
    next = curr->next;
    while (next != NULL)
    {
        if (strncmp(rid, next->rid, sizeof(next->rid)) == 0)
        {
            OvsDb_Base_Receipt* parsed_result = ovsdb_parse_result(next->receipt_type, result); //Table lookup
            if (!parsed_result)
            {
                OvsDbApiError("%s failed to parse result of receipt with rid: %s\n",
                    __func__, rid);
                return OVS_FAILED_STATUS;
            }

            next->callback(rid, parsed_result);
            free(parsed_result);
            curr->next = next->next;
            free(next);
            return OVS_SUCCESS_STATUS;
        }

        curr = curr->next;
        next = curr->next;
    }

    OvsDbApiWarning("%s rid: %s is not present inside receipt list.\n",
        __func__, rid);
    return OVS_FAILED_STATUS;
}

OVS_STATUS receipt_list_clear()
{
    receipt_node_t* curr = msg_list;
    receipt_node_t* next = NULL;

    OvsDbApiDebug("%s clearing the receipt list.\n", __func__);

    while (curr != NULL)
    {
        OvsDbApiDebug("%s clearing rid: %s, Receipt Id: %d, from list.\n",
            __func__, curr->rid, curr->receipt_type);
        next = curr->next;
        free(curr);
        curr = next;
    }

    msg_list = NULL;
    return OVS_SUCCESS_STATUS;
}

