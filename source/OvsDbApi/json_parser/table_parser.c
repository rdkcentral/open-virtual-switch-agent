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

#include <string.h>
#include <jansson.h>
#include "common/OvsAgentLog.h"
#include "OvsDbApi/OvsDbDefs.h"
#include "table_parser.h"

static const char * json_fetch_string (json_t * root, const char *key);
static OVS_STATUS gateway_config_parser(json_t * json, Rdkb_Table_Config* table_config);
static OVS_STATUS feedback_config_parser(json_t * json, Rdkb_Table_Config* table_config);

OVS_STATUS parse_table(const char * table_name, json_t* update, Rdkb_Table_Config* table_config)
{
    OVS_STATUS status = OVS_FAILED_STATUS;
    char* str_json = NULL;

    if (!table_name || !update || !table_config)
    {
        OvsDbApiError("%s error!\n", __func__);
        return OVS_FAILED_STATUS;
    }

    str_json = json_dumps(update, JSON_COMPACT);
    OvsDbApiDebug("%s: table_name: %s, update: %s\n", __func__, table_name, str_json);
    free(str_json);

    /** TODO: Replace this later with some kind of table, try hsearch **/
    if (strcmp(table_name, GATEWAY_CONFIG_TABLE_NAME) == 0)
    {
        status = gateway_config_parser(update, table_config);
    }
    else if (strcmp(table_name, FEEDBACK_TABLE_NAME) == 0)
    {
        status = feedback_config_parser(update, table_config);
    }

    return status;
}

static OVS_STATUS gateway_config_parser(json_t * json, Rdkb_Table_Config* table_config)
{
    //TODO: Add checks on returns
    if (!json)
    {
        OvsDbApiError("%s error!\n", __func__);
        return OVS_FAILED_STATUS;
    }

    Gateway_Config* config = malloc(sizeof(Gateway_Config));
    if (!config)
    {
        OvsDbApiError("%s memory allocation failed!\n", __func__);
        return OVS_FAILED_STATUS;
    }
    memset(config, 0, sizeof(Gateway_Config));

    const char * if_name = json_fetch_string (json, "if_name");
    if (if_name)
    {
        strncpy(config->if_name, if_name, sizeof(config->if_name)-1);
        config->if_name[ sizeof(config->if_name)-1 ] = '\0';
    }

    config->if_type = (int) json_integer_value (json_object_get (json, "if_type"));
    config->if_cmd = (int) json_integer_value (json_object_get (json, "if_cmd"));

    const char * inet_addr = json_fetch_string (json, "inet_addr");
    if (inet_addr)
    {
        strncpy(config->inet_addr, inet_addr, sizeof(config->inet_addr)-1);
        config->inet_addr[ sizeof(config->inet_addr) -1 ] = '\0';
    }

    const char * netmask = json_fetch_string (json, "netmask");
    if (netmask)
    {
        strncpy(config->netmask, netmask, sizeof(config->netmask)-1);
        config->netmask[ sizeof(config->netmask)-1 ] = '\0';
    }

    const char * gre_remote_inet_addr = json_fetch_string (json, "gre_remote_inet_addr");
    if (gre_remote_inet_addr)
    {
        strncpy(config->gre_remote_inet_addr, gre_remote_inet_addr, sizeof(config->gre_remote_inet_addr)-1);
        config->gre_remote_inet_addr[ sizeof(config->gre_remote_inet_addr)-1 ] = '\0';
    }

    const char * gre_local_inet_addr = json_fetch_string (json, "gre_local_inet_addr");
    if (gre_local_inet_addr)
    {
        strncpy(config->gre_local_inet_addr, gre_local_inet_addr, sizeof(config->gre_local_inet_addr)-1);
        config->gre_local_inet_addr[ sizeof(config->gre_local_inet_addr)-1 ] = '\0';
    }

    const char * parent_ifname = json_fetch_string (json, "parent_ifname");
    if (parent_ifname)
    {
        strncpy(config->parent_ifname, parent_ifname, sizeof(config->parent_ifname)-1);
        config->parent_ifname[ sizeof(config->parent_ifname) -1 ] = '\0';
    }

    config->mtu = (int) json_integer_value (json_object_get (json, "mtu"));

    const char * parent_bridge = json_fetch_string (json, "parent_bridge");
    if (parent_bridge)
    {
        strncpy(config->parent_bridge, parent_bridge, sizeof(config->parent_bridge)-1);
        config->parent_bridge[ sizeof(config->parent_bridge)-1 ] = '\0';
    }

    config->vlan_id = (int) json_integer_value (json_object_get (json, "vlan_id"));

    table_config->table.id = OVS_GW_CONFIG_TABLE;
    table_config->config = (void*) config;

    return OVS_SUCCESS_STATUS;
}

static OVS_STATUS feedback_config_parser(json_t * json, Rdkb_Table_Config* table_config){

    if (!json)
    {
        OvsDbApiError("%s error!\n", __func__);
        return OVS_FAILED_STATUS;
    }

    Feedback* feedback = malloc(sizeof(Feedback));
    if (!feedback)
    {
        OvsDbApiError("%s memory allocation failed!\n", __func__);
        return OVS_FAILED_STATUS;
    }
    memset(feedback->req_uuid, 0, sizeof(feedback->req_uuid));

    const char * req_uuid = json_fetch_string(json, "req_uuid");
    if (req_uuid)
    {
        strncpy(feedback->req_uuid, req_uuid, sizeof(feedback->req_uuid)-1);
        feedback->req_uuid[ sizeof(feedback->req_uuid)-1 ] = '\0';
    }

    feedback->status = (int) json_integer_value(json_object_get(json, "status"));

    table_config->table.id = OVS_FEEDBACK_TABLE;
    table_config->config = feedback;

    return OVS_SUCCESS_STATUS;
}

static const char * json_fetch_string(json_t * root, const char *key)
{
    json_t *obj = NULL;

    if (!root || !key)
    {
        OvsDbApiError("%s error for key %s!\n", __func__, key);
        return NULL;
    }

    obj = json_object_get (root, key);
    if (!obj)
    {
        OvsDbApiError("%s Error fetching %s\n", __func__, key);
        return NULL;
    }

    return json_string_value (obj);
}
