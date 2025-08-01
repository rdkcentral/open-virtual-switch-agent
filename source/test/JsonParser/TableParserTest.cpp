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
#include <string>
#include <gtest/gtest.h>

extern "C" {
#include "OvsDbApi/OvsDbApi.h"
#include "common/OvsAgentLog.h"
#include "OvsDbApi/json_parser/table_parser.h"
}

TEST(TableParserTest, gwconfig_test)
{
    const char* example_table_name = "Gateway_Config";
    json_t* example_update = json_loads("{\"if_name\":\"brmine_cli2\",\"_version\":[\"uuid\",\"f47e0d9d-e529-46f8-99d3-922fa3fa9584\"],\"mtu\":1500,\"parent_ifname\":\"null\",\"if_type\":1,\"parent_bridge\":\"null\",\"gre_ifname\":\"null\",\"vlan_id\":2,\"netmask\":\"255.255.255.0\",\"if_cmd\":0,\"gre_remote_inet_addr\":\"null\",\"gre_local_inet_addr\":\"null\",\"inet_addr\":\"192.168.106.1\"}", 0, NULL);

    Rdkb_Table_Config table_config;
    ASSERT_EQ(OVS_SUCCESS_STATUS, parse_table(example_table_name, example_update, &table_config));
    ASSERT_EQ(OVS_GW_CONFIG_TABLE, table_config.table.id);

    Gateway_Config* gw_config = (Gateway_Config*) table_config.config;
    EXPECT_STREQ("brmine_cli2", gw_config->if_name);
    EXPECT_EQ(1500, gw_config->mtu);
    EXPECT_STREQ("null", gw_config->parent_ifname);
    EXPECT_STREQ("null", gw_config->parent_bridge);
    EXPECT_EQ(2, gw_config->vlan_id);
    EXPECT_STREQ("255.255.255.0", gw_config->netmask);
    EXPECT_EQ(0, gw_config->if_cmd);
    EXPECT_STREQ("null", gw_config->gre_remote_inet_addr);
    EXPECT_STREQ("null", gw_config->gre_local_inet_addr);
    EXPECT_STREQ("192.168.106.1", gw_config->inet_addr);
}

TEST(TableParserTest, feedback_test)
{
    const char* example_table_name = "Feedback";
    json_t* example_update = json_loads("{\"_version\":[\"uuid\",\"570e2da2-2adb-4dd7-bc2d-944d065c53c0\"],\"req_uuid\":\"18ca5061-c9ef-42dc-9579-f9e3167a1ae7\",\"status\":0}", 0, NULL);

    Rdkb_Table_Config table_config;
    ASSERT_EQ(OVS_SUCCESS_STATUS, parse_table(example_table_name, example_update, &table_config));
    ASSERT_EQ(OVS_FEEDBACK_TABLE, table_config.table.id);

    Feedback* fb = (Feedback*) table_config.config;
    EXPECT_STREQ("18ca5061-c9ef-42dc-9579-f9e3167a1ae7", fb->req_uuid);
    EXPECT_EQ(OVS_SUCCESS_STATUS, fb->status);
}

// RDKB-41589
TEST(TableParserTest, gwconfig_vlan_test)
{
    const char* example_table_name = "Gateway_Config";

    json_t* example_update = json_loads("{\"_version\":[\"uuid\",\"02b8db48-f290-4f68-8410-43f4fd91ff2d\"],\"if_name\":\"pgd0-91.200\",\"mtu\":[\"set\",[]],\"inet_addr\":[\"set\",[]],\"gre_local_inet_addr\":[\"set\",[]],\"parent_ifname\":\"pgd0-91\",\"vlan_id\":200,\"if_type\":4,\"parent_bridge\":\"dummy\",\"gre_ifname\":[\"set\",[]],\"netmask\":[\"set\",[]],\"if_cmd\":0,\"gre_remote_inet_addr\":[\"set\",[]]}", 0, NULL);

    Rdkb_Table_Config table_config;
    ASSERT_EQ(OVS_SUCCESS_STATUS, parse_table(example_table_name, example_update, &table_config));
    ASSERT_EQ(OVS_GW_CONFIG_TABLE, table_config.table.id);

    Gateway_Config* gw_config = (Gateway_Config*) table_config.config;
    EXPECT_STREQ("pgd0-91.200", gw_config->if_name);
    EXPECT_EQ(0, gw_config->mtu);
    EXPECT_STREQ("pgd0-91", gw_config->parent_ifname);
    EXPECT_STREQ("dummy", gw_config->parent_bridge);
    EXPECT_EQ(200, gw_config->vlan_id);
    EXPECT_STREQ("", gw_config->netmask);
    EXPECT_EQ(0, gw_config->if_cmd);
    EXPECT_STREQ("", gw_config->gre_remote_inet_addr);
    EXPECT_STREQ("", gw_config->gre_local_inet_addr);
    EXPECT_STREQ("", gw_config->inet_addr);
}
