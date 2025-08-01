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
#include <stdlib.h>
#include <string.h>
#include "OvsAgentDefs.h"
#include "OvsAgentApi.h"
#include "OvsAction/ovs_action.h"
#include "OvsAgentCore/OvsAgentLog.h"
#include "OvsAgentCore/OvsAgent.h"
#include "OvsAgentSsp/cosa_api.h"
#include <sys/stat.h>

static void gwconf_mon_cb(OVS_STATUS status, Rdkb_Table_Config * table_config)
{
    OVS_STATUS ret;

    OvsAgent_Table_Config * ovs_table_config = NULL;
    if (!table_config || !table_config->config)
    {
        OvsAgentError("%s Table Config is NULL!\n", __func__);
        return;
    }

    ovs_table_config = (OvsAgent_Table_Config *) table_config;
    Gateway_Config* config = (Gateway_Config *)table_config->config;
    OvsAgentInfo("%s received for Table: %d, Config: %p, Uuid: %s\n", __func__,
        table_config->table.id, table_config->config, ovs_table_config->uuid);
    OvsAgentDebug(
        "Gateway Config if_name: %s, if_type: %d, if_cmd: %d, inet_addr: %s, netmask: %s, gre_(remote_inet_addr: %s, local_inet_addr: %s), parent_(ifname: %s, bridge: %s), mtu: %d, vlan_id: %d\n",
        config->if_name, config->if_type, config->if_cmd, config->inet_addr,
        config->netmask, config->gre_remote_inet_addr, config->gre_local_inet_addr,
        config->parent_ifname, config->parent_bridge, config->mtu, config->vlan_id);

    ret = ovs_action_gateway_config(config);

    Feedback fb = {0};
    strncpy(fb.req_uuid, ovs_table_config->uuid, sizeof(fb.req_uuid)-1);
    fb.req_uuid[ sizeof(fb.req_uuid)-1 ] = '\0';
    fb.status = ret;

    ovs_interact_request request = {0};
    request.method = OVS_TRANSACT_METHOD;
    request.operation = OVS_INSERT_OPERATION;
    request.table_config.table.id = OVS_FEEDBACK_TABLE;
    request.table_config.config = &fb;
    if (!ovs_agent_api_interact(&request, NULL))
    {
        OvsAgentError("%s interact Table: %d, Config: %p failed for Uuid: %s\n",
            __func__, request.table_config.table.id, request.table_config.config,
            fb.req_uuid);
        return;
    }

    OvsAgentInfo("%s interact Table: %d, Config: %p succeeded for Uuid: %s\n",
        __func__, request.table_config.table.id, request.table_config.config,
        fb.req_uuid);
}

bool OvsAgentDeinit()
{
    bool rtn = true;
    OvsAgentInfo("Ovs Agent de-initializing...\n");

    Cosa_Shutdown();

    /* De-initialize OvsAgentApi*/
    if (!ovs_agent_api_deinit())
    {
        OvsAgentError("Ovs Agent API De-init failed!\n");
        rtn = false;
    }

    if (!OvsAgentLogDeinit())
    {
        fprintf(stderr, "Ovs Agent Log De-init failed!\n");
        rtn = false;
    }
    return rtn;
}

bool OvsAgentInit()
{
    ovs_interact_request request = {0};

    /* Initialize OvsAgent RDK Logger*/
    if (!OvsAgentLogInit())
    {
        fprintf(stderr, "Ovs Agent Log Initialization failed!\n");
        (void)OvsAgentLogDeinit();
        return false;
    }
    OvsAgentInfo("Ovs Agent Log Initialized\n");

    if (!Cosa_Init())
    {
        OvsAgentError("Failed to initialize Ovs Agent Cosa Api!\n");
        return false;
    }
    OvsAgentInfo("Ovs Agent Cosa Api Initialized\n");

    /* Initialize OvsAgentApi*/
    if (!ovs_agent_api_init(OVS_AGENT_COMPONENT_ID))
    {
        OvsAgentError("Ovs Agent API Init failed for Component Id %d!\n",
            OVS_AGENT_COMPONENT_ID);
        Cosa_Shutdown();
        (void)OvsAgentLogDeinit();
        return false;
    }
    OvsAgentInfo("Ovs Agent Api Initialized for Component Id %d\n",
        OVS_AGENT_COMPONENT_ID);

    /* Initialize OvsAction*/
    if (ovs_action_init() != OVS_SUCCESS_STATUS)
    {
        OvsAgentError("Failed to initialize Ovs Action!\n");
        (void)ovs_agent_api_deinit();
        Cosa_Shutdown();
        (void)OvsAgentLogDeinit();
        return false;
    }
    OvsAgentInfo("Ovs Action Initialized\n");

    request.method = OVS_MONITOR_METHOD;
    request.operation = OVS_INSERT_OPERATION;
    request.table_config.table.id = OVS_GW_CONFIG_TABLE;
    if (!ovs_agent_api_interact(&request, gwconf_mon_cb))
    {
        OvsAgentError("Ovs Agent interact monitor table %d failed!\n",
            request.table_config.table.id);
        (void)ovs_agent_api_deinit();
        Cosa_Shutdown();
        (void)OvsAgentLogDeinit();
        return false;
    }

    OvsAgentInfo("Ovs Agent interact monitor table %d succeeded.\n",
        request.table_config.table.id);

    int fd = creat(OVSAGENT_INIT_FILE,S_IRUSR | S_IWUSR | S_IRGRP);
    if(fd != -1)
    {
        close(fd);
    }

    return true;
}

