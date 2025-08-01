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
#include <jansson.h>
#include "OvsDbApi/OvsDbDefs.h"
#include "common/OvsAgentLog.h"
#include "OvsDataTypes.h"

char * gc_insert_to_json(Gateway_Config * config, const char * unique_id)
{
    json_t *js_row = NULL;
    json_t *js_mainObj = NULL;
    json_t *js_params = NULL;
    json_t *js_main = NULL;
    char *str_out = NULL;

    if (!config || !unique_id)
    {
        OvsDbApiError("Unable to create JSON string because of incomplete parameters\n");
        return NULL;
    }

    js_row = json_object ();
    js_mainObj = json_object ();
    js_params = json_array ();
    js_main = json_object ();

    json_array_append_new (js_params, json_string (OVSDB_DEF_DB));
    json_object_set_new (js_mainObj, "op", json_string ("insert"));
    json_object_set_new (js_mainObj, "table", json_string (GATEWAY_CONFIG_TABLE_NAME));

    if(0 < json_object_set_new (js_row, "gre_ifname", json_string ("null")))
    {
        OvsDbApiError("Error adding GRE ifname.\n");
    }

    if(0 < json_object_set_new (js_row, "if_name", json_string (config->if_name)))
    {
        OvsDbApiError("Error adding ifname.\n");
    }

    if(0 < json_object_set_new (js_row, "if_type", json_integer (config->if_type)))
    {
        OvsDbApiError("Error adding iftype.\n");
    }

    if(0 < json_object_set_new (js_row, "if_cmd", json_integer (config->if_cmd)))
    {
        OvsDbApiError("Error adding if_cmd\n");
    }

    if(0 < json_object_set_new (js_row, "inet_addr",
                              json_string (config->inet_addr)))
    {
        OvsDbApiError ("Error adding inet_addr.\n");
    }

    if(0 < json_object_set_new (js_row, "netmask", json_string (config->netmask)))
    {
        OvsDbApiError ("Error adding ifname netmask.\n");
    }

    if(0 < json_object_set_new (js_row, "gre_remote_inet_addr",
                              json_string (config->gre_remote_inet_addr)))
    {
        OvsDbApiError ("Error adding gre remote addr.\n");
    }

    if(0 < json_object_set_new (js_row, "gre_local_inet_addr",
                              json_string (config->gre_local_inet_addr)))
    {
        OvsDbApiError ("Error adding gre local addr.\n");
    }

    if(0 < json_object_set_new (js_row, "parent_ifname",
                              json_string (config->parent_ifname)))
    {
        OvsDbApiError ("Error adding parent ifname.\n");
    }

    if(0 < json_object_set_new (js_row, "mtu", json_integer (config->mtu)))
    {
        OvsDbApiError ("Error adding mtu.\n");
    }

    if(0 < json_object_set_new (js_row, "parent_bridge",
                              json_string (config->parent_bridge)))
    {
        OvsDbApiError ("Error adding parent bridge.\n");
    }

    if(0 < json_object_set_new (js_row, "vlan_id", json_integer (config->vlan_id)))
    {
        OvsDbApiError ("Error adding vlan ID.\n");
    }

    json_object_set_new (js_mainObj, "row", js_row);
    json_array_append_new (js_params, js_mainObj);
    json_object_set_new (js_main, "method", json_string ("transact"));
    json_object_set_new (js_main, "id", json_string (unique_id));
    json_object_set_new (js_main, "params", js_params);

    str_out = json_dumps(js_main, JSON_COMPACT);
    json_decref(js_main);
    return str_out;
}
