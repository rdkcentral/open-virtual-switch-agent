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
#include <stdbool.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "test/mocks/MockOvsDbApi.h"

extern "C" {
#include "OvsAgentApi.h"
#include "OvsAgentApi/transaction_interface.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

OvsDbApiMock * g_ovsDbApiMock = NULL;  /* This is the actual definition of the mock obj */

class OvsAgentApiTestFixture : public ::testing::Test
{
    protected:
        OvsDbApiMock mockedOvsDbApi;

        OvsAgentApiTestFixture()
        {
            g_ovsDbApiMock = &mockedOvsDbApi;
        }
        virtual ~OvsAgentApiTestFixture()
        {
            g_ovsDbApiMock = NULL;
        }

        virtual void SetUp()
        {
            printf("%s\n", __func__);
        }

        virtual void TearDown()
        {
            printf("%s\n", __func__);
        }

        static void SetUpTestCase()
        {
            printf("%s\n", __func__);
        }

        static void TearDownTestCase()
        {
            printf("%s\n", __func__);
        }
    public:
        static void OvsAgentInteractCallback(OVS_STATUS status,
            Rdkb_Table_Config * table_config)
        {
        }
};

TEST(OvsAgentApi, ovs_agent_api_get_config_null)
{
    ASSERT_EQ(false, ovs_agent_api_get_config(OVS_GW_CONFIG_TABLE, NULL));
}

TEST(OvsAgentApi, ovs_agent_api_interact_request_null)
{
    ASSERT_EQ(false, ovs_agent_api_interact(NULL, NULL));
}

TEST_F(OvsAgentApiTestFixture, ovs_agent_api_init_deinit)
{
    // TODO: Use OVS_STARTING_ID_MULTIPLIER instead
    const unsigned int startingId = OVS_TEST_APP_COMPONENT_ID * 1000;

    EXPECT_CALL(*g_ovsDbApiMock, ovsdb_init(startingId))
        .Times(1)
        .WillOnce(Return(OVS_SUCCESS_STATUS));
    EXPECT_CALL(*g_ovsDbApiMock, ovsdb_deinit())
        .Times(1)
        .WillOnce(Return(OVS_SUCCESS_STATUS));

    ASSERT_EQ(true, ovs_agent_api_init(OVS_TEST_APP_COMPONENT_ID));
    ASSERT_EQ(true, ovs_agent_api_deinit());
}

