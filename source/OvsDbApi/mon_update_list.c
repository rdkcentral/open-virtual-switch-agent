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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "OvsDbApi/mon_update_list.h"
#include "OvsDbApi/OvsDbDefs.h"
#include "common/OvsAgentLog.h"

//TODO: Update later to hash table?
//TODO: Add cleanup to all of this in deinit
typedef struct mon_node_t
{
    char uuid[MAX_UUID_LEN+1];       //Unique ID to identify messages
    ovsdb_mon_cb callback;           //Callback to invoke when message is found
    struct mon_node_t* next;         //Next in the list
} mon_node_t;

static mon_node_t* msg_list = NULL;

OVS_STATUS mon_list_add(const char* uuid, ovsdb_mon_cb cb)
{
    OvsDbApiDebug("%s adding UUID to list: %s\n", __func__, uuid);

    mon_node_t* new_node = (mon_node_t*) malloc( sizeof( mon_node_t) );
    if (!new_node)
    {
        OvsDbApiError("%s failed to allocate new mon_node_t node.\n",
            __func__);
        return OVS_FAILED_STATUS;
    }

    memset(new_node->uuid, 0, sizeof(new_node->uuid));
    strncpy(new_node->uuid, uuid, MAX_UUID_LEN);
    new_node->callback = cb;
    new_node->next = NULL;

    if (!msg_list)
    {
        msg_list = new_node;
        return OVS_SUCCESS_STATUS;
    }

    mon_node_t* temp = msg_list;
    while (temp->next != NULL)
    {
        temp = temp->next;
    }
    temp->next = new_node;
    return OVS_SUCCESS_STATUS;
}

OVS_STATUS mon_list_process(const char* uuid, Rdkb_Table_Config* table_config)
{
    mon_node_t* temp = NULL;

    OvsDbApiDebug("%s parsing UUID: %s\n", __func__, uuid);

    for (temp = msg_list; temp != NULL; temp = temp->next)
    {
        if (strncmp(uuid, temp->uuid, sizeof(temp->uuid)) == 0)
        {
            temp->callback( OVS_SUCCESS_STATUS, table_config );
            return OVS_SUCCESS_STATUS;
        }
    }

    OvsDbApiWarning("%s UUID: %s is not present inside monitor update list.\n",
        __func__, uuid);
    return OVS_FAILED_STATUS;
}

OVS_STATUS mon_list_remove(const char * uuid)
{
    mon_node_t* curr = NULL;
    mon_node_t* next = NULL;

    if (!uuid || !msg_list)
    {
        OvsDbApiError("%s removing monitor node with either list empty or uuid NULL.\n",
            __func__);
        return OVS_FAILED_STATUS;
    }

    OvsDbApiDebug("%s UUID: %s from list.\n", __func__, uuid);

    /** Check head of list **/
    if (strncmp(uuid, msg_list->uuid, sizeof(msg_list->uuid)) == 0)
    {
        curr = msg_list;
        msg_list = msg_list->next;
        free(curr);
        return OVS_SUCCESS_STATUS;
    }

    for (curr = msg_list; next != NULL; curr = curr->next)
    {
        next = curr->next;

        if (strncmp(uuid, next->uuid, sizeof(next->uuid)) == 0)
        {
            curr->next = next->next;
            free(next);
            return OVS_SUCCESS_STATUS;
        }
    }

    OvsDbApiError("%s Cannot find UUID: %s in the mon_update list.\n",
        __func__, uuid);
    return OVS_FAILED_STATUS;
}

OVS_STATUS mon_list_clear()
{
    mon_node_t* curr = msg_list;
    mon_node_t* next = NULL;

    OvsDbApiDebug("%s clearing the monitor list.\n", __func__);

    while (curr != NULL)
    {
        OvsDbApiDebug("%s UUID: %s from list.\n", __func__, curr->uuid);
        next = curr->next;
        free(curr);
        curr = next;
    }

    msg_list = NULL;
    return OVS_SUCCESS_STATUS;
}
