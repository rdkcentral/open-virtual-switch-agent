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
#include "OvsAgentApi.h"

static bool g_rcvd = false;

struct Gateway_Config g_gwConfig[10] =
    {
        {"Brlan0", "10.0.0.1", "255.255.255.0", "10.100.0.1", "10.0.100.1", "Brlan0PIface", "Brlan0PBridge", 1480, 100, OVS_BRIDGE_IF_TYPE, OVS_IF_UP_CMD},
        {"Brlan1", "11.0.0.1", "255.255.255.1", "11.100.0.1", "11.0.100.1", "Brlan1PIface", "Brlan1PBridge", 1481, 101, OVS_BRIDGE_IF_TYPE, OVS_IF_DOWN_CMD},
        {"Brlan2", "12.0.0.1", "255.255.255.2", "12.100.0.1", "12.0.100.1", "Brlan2PIface", "Brlan2PBridge", 1482, 102, OVS_BRIDGE_IF_TYPE, OVS_IF_DELETE_CMD},
        {"Brlan3", "13.0.0.1", "255.255.255.3", "13.100.0.1", "13.0.100.1", "Brlan3PIface", "Brlan3PBridge", 1483, 103, OVS_BRIDGE_IF_TYPE, OVS_IF_UP_CMD},
        {"Brlan4", "14.0.0.1", "255.255.255.4", "14.100.0.1", "14.0.100.1", "Brlan4PIface", "Brlan4PBridge", 1484, 104, OVS_BRIDGE_IF_TYPE, OVS_IF_DOWN_CMD},
        {"Brlan5", "15.0.0.1", "255.255.255.5", "15.100.0.1", "15.0.100.1", "Brlan5PIface", "Brlan5PBridge", 1485, 105, OVS_BRIDGE_IF_TYPE, OVS_IF_DELETE_CMD},
        {"Brlan6", "16.0.0.1", "255.255.255.6", "16.100.0.1", "16.0.100.1", "Brlan6PIface", "Brlan6PBridge", 1486, 106, OVS_BRIDGE_IF_TYPE, OVS_IF_UP_CMD},
        {"Brlan7", "17.0.0.1", "255.255.255.7", "17.100.0.1", "17.0.100.1", "Brlan7PIface", "Brlan7PBridge", 1487, 107, OVS_BRIDGE_IF_TYPE, OVS_IF_DOWN_CMD},
        {"Brlan8", "18.0.0.1", "255.255.255.8", "18.100.0.1", "18.0.100.1", "Brlan8PIface", "Brlan8PBridge", 1488, 108, OVS_BRIDGE_IF_TYPE, OVS_IF_DELETE_CMD},
        {"Brlan9", "19.0.0.1", "255.255.255.9", "19.100.0.1", "19.0.100.1", "Brlan9PIface", "Brlan9PBridge", 1489, 109, OVS_BRIDGE_IF_TYPE, OVS_BR_REMOVE_CMD}
    };

static void ovs_agent_interact_callback(OVS_STATUS status,
    Rdkb_Table_Config * table_config)
{
    fprintf(stderr, "%s Rcvd Interact callback Status: %d, table config=%p\n",
        __func__, status, table_config);
    if (!table_config || !table_config->config)
    {
        fprintf(stderr, "%s Callback table config is NULL\n", __func__);
    }
    else
    {
        fprintf(stderr, "%s Rcvd Status: %d, Table: %d, config: %p\n", __func__,
            status, table_config->table.id, table_config->config);
        print_rdkb_table_config(table_config);
    }
    g_rcvd = true;
}

int main(int argc, char* argv[])
{
    int count = 0;
    const numBridges = sizeof(g_gwConfig) / sizeof(Gateway_Config);
    Gateway_Config * pGwConfig = NULL;
    const OVS_BLOCK_MODE blockMode = (argc>1 && (strncmp(argv[1], "blocked=true", 13)==0)) ?
        OVS_ENABLE_BLOCK_MODE : OVS_DISABLE_BLOCK_MODE;

    fprintf(stderr, "%s bridges=%d, blocked=%d\n", __func__, numBridges, blockMode);

    if (!ovs_agent_api_init(OVS_TEST_APP_COMPONENT_ID))
    {
        fprintf(stderr, "%s failed to initialize API!\n", __func__);
        return 1;
    }

    while (++count <= numBridges)
    {
        fprintf(stderr, "\n");
        if (!ovs_agent_api_get_config(OVS_GW_CONFIG_TABLE, (void **)&pGwConfig))
        {
            fprintf(stderr, "%s failed to allocate and initialize config\n", __func__);
            return 2;
        }
        print_gateway_config(pGwConfig);

        strncpy(pGwConfig->if_name, g_gwConfig[count-1].if_name, MAX_IF_NAME_SIZE-1);
        strncpy(pGwConfig->inet_addr, g_gwConfig[count-1].inet_addr, MAX_IP_ADDR_SIZE-1);
        strncpy(pGwConfig->netmask, g_gwConfig[count-1].netmask, MAX_IP_ADDR_SIZE-1);
        strncpy(pGwConfig->gre_remote_inet_addr, g_gwConfig[count-1].gre_remote_inet_addr, MAX_IP_ADDR_SIZE-1);
        strncpy(pGwConfig->gre_local_inet_addr, g_gwConfig[count-1].gre_local_inet_addr, MAX_IP_ADDR_SIZE-1);
        strncpy(pGwConfig->parent_ifname, g_gwConfig[count-1].parent_ifname, MAX_IF_NAME_SIZE-1);
        strncpy(pGwConfig->parent_bridge, g_gwConfig[count-1].parent_bridge, MAX_BRIDGE_NAME_SIZE-1);
        pGwConfig->mtu = g_gwConfig[count-1].mtu;
        pGwConfig->vlan_id = g_gwConfig[count-1].vlan_id;
        pGwConfig->if_type = g_gwConfig[count-1].if_type;
        pGwConfig->if_cmd = g_gwConfig[count-1].if_cmd;

        /*Feedback fbConfig = {0};
        strncpy(fbConfig.req_uuid, "84ee5b25-ebfd-4faf-88d7-7484f3e9b071", MAX_UUID_LEN);
        fbConfig.req_uuid[MAX_UUID_LEN] = '\0';
        fbConfig.status = OVS_SUCCESS_STATUS;
        printf("GW Config=%p, FB Config=%p\n", pGwConfig, &fbConfig);

        Feedback_Table_Config fbTableConfig = {0};
        fbTableConfig.table.id = OVS_FEEDBACK_TABLE;
        fbTableConfig.config = &fbConfig;
        printf("Feedback_Table_Config Config: %p, Size: %u\n",
            fbTableConfig.config, sizeof(Feedback_Table_Config));*/

        // Option 2
        ovs_interact_request request = {0};
        request.block_mode = blockMode;
        //request.method = OVS_TRANSACT_METHOD; // now optional
        //request.operation = OVS_INSERT_OPERATION; // now optional
        request.table_config.table.id = OVS_GW_CONFIG_TABLE;
        request.table_config.config = (void *) pGwConfig;
        fprintf(stderr,
            "Request #%d, Method: %d, Operation: %d, Block Mode: %d, Table: %d, Table Config: %p, Config: %p=%p, Size: %u\n",
            count, request.method, request.operation, request.block_mode,
            request.table_config.table.id, &request.table_config,
            request.table_config.config, pGwConfig, sizeof(ovs_interact_request));

        g_rcvd = false;
        if (ovs_agent_api_interact(&request, ovs_agent_interact_callback))
        {
            fprintf(stderr, "%s ovs api interact #%d SUCCESS\n", __func__, count);
        }
        else
        {
            fprintf(stderr, "%s ovs api interact #%d FAILED!\n", __func__, count);
            continue;
        }

        if (request.block_mode == OVS_ENABLE_BLOCK_MODE)
        {
            continue;
        }
        while (!g_rcvd)
        {
            fprintf(stderr, "%s waiting for interact #%d callback...\n",
                __func__, count);
            sleep(1); // TODO Use condition variable instead
        }
    }

    ovs_agent_api_deinit();

    fprintf(stderr, "Exiting %s...\n", __FUNCTION__);

    return 0;
}
