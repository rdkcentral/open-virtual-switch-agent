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
#include "OvsDbApi/mon_update_list.h"
}

namespace{
    const char* g_rID = "ABCD1234";
    const char* g_uuid = "f8ecdbd4-0c07-42a9-91ff-819bbf2f4196";
}

TEST(MonitorList, MonitorUpdateSingle)
{
    Feedback feedback = {OVS_SUCCESS_STATUS, {}};
    strncpy(feedback.req_uuid, g_uuid, sizeof(feedback.req_uuid));
    Rdkb_Table_Config table_config = {OVS_FEEDBACK_TABLE, &feedback};

    ovsdb_mon_cb mon_cb = [](OVS_STATUS status, Rdkb_Table_Config* table_config){
        ASSERT_EQ(OVS_SUCCESS_STATUS, status);
        ASSERT_EQ(OVS_FEEDBACK_TABLE, table_config->table.id);
        Feedback* fb = (Feedback*) table_config->config;
        EXPECT_EQ(OVS_SUCCESS_STATUS, fb->status);
        EXPECT_STREQ(g_uuid,fb->req_uuid);
    };

    ASSERT_EQ(OVS_SUCCESS_STATUS, mon_list_add(g_rID, mon_cb));
    EXPECT_EQ(OVS_SUCCESS_STATUS, mon_list_process(g_rID, &table_config));
}
