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
#include <queue>
#include <mutex>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "test/mocks/mock_ovsdb_socket.h"
#include "test/mocks/MockOvsDbReceiptCallback.h"

extern "C" {
#include "OvsDbApi/OvsDbApi.h"
#include "common/OvsAgentLog.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

OvsDbSocketMock * g_ovsDbSocketMock = NULL; /* This is the actual definition of the mock obj */
OvsDbReceiptCallbackMock * g_ovsDbReceiptCallbackMock = NULL;

class OvsDbApiTestFixture : public ::testing::Test
{
    protected:
        OvsDbSocketMock mockedOvsDbSocket;
        OvsDbReceiptCallbackMock mockedOvsDbReceiptCallback;
        std::queue<std::string> m_responseQueue;
        std::mutex m_lock;

        OvsDbApiTestFixture()
        {
            g_ovsDbSocketMock = &mockedOvsDbSocket;
            g_ovsDbReceiptCallbackMock = &mockedOvsDbReceiptCallback;
        }
        virtual ~OvsDbApiTestFixture()
        {
            g_ovsDbSocketMock = NULL;
            g_ovsDbReceiptCallbackMock = NULL;
        }

        virtual void SetUp()
        {
            OvsDbApiInfo("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        virtual void TearDown()
        {
            OvsDbApiInfo("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        static void SetUpTestCase()
        {
            OvsDbApiInfo("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());

        }

        static void TearDownTestCase()
        {
            OvsDbApiInfo("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
        }
    public:
        static void OvsDbMonitorCallback(OVS_STATUS status,
            Rdkb_Table_Config * table_config)
        {
            OvsDbApiInfo("%s received status %d for table id %d\n", __func__, status,
                table_config->table.id);
        }
        static void OvsDbReceiptCallback(const char* rID,
            const OvsDb_Base_Receipt* receipt_result)
        {
            OvsDb_Insert_Receipt* insertReceipt = (OvsDb_Insert_Receipt*)receipt_result;
            OvsDbApiInfo("%s received rId=%s, Receipt Id=%d, Uuid=%s\n", __func__,
                rID, insertReceipt->receipt_id, insertReceipt->uuid);
            g_ovsDbReceiptCallbackMock->OvsDbReceiptCallback(rID,
                insertReceipt->receipt_id, insertReceipt->uuid);

            g_ovsDbReceiptCallbackMock->notify();
        }
        void SendMessage(const std::string& json_msg)
        {
            m_lock.lock();
            m_responseQueue.push(json_msg);
            m_lock.unlock();
        }
};

TEST_F(OvsDbApiTestFixture, ovsdb_api_init_deinit)
{
    const int sock_fd = 10;

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_connect())
        .Times(1)
        .WillOnce(Return(sock_fd));
    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_listen(sock_fd, _, _, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_disconnect(sock_fd))
        .Times(1)
        .WillOnce(Return(0));

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_init(0));
    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_deinit());
}

TEST_F(OvsDbApiTestFixture, ovsdb_api_id_generate)
{
    const unsigned int startingId = 0;
    const int sock_fd = 10;

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_connect())
        .Times(1)
        .WillOnce(Return(sock_fd));
    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_listen(sock_fd, _, _, _))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_disconnect(sock_fd))
        .Times(1)
        .WillOnce(Return(0));

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_init(startingId));
    ASSERT_EQ(startingId + 1, id_generate());
    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_deinit());
}

ACTION_TEMPLATE(CopyStringFromQueue, HAS_1_TEMPLATE_PARAMS(unsigned, uIndex), AND_3_VALUE_PARAMS(pQueue, pLock, pSize))
{
    if(pQueue->empty())
    {
        *pSize = 0;
    }
    else
    {
        pLock->lock();
        std::string json_msg = pQueue->front();
        pQueue->pop();
        memcpy(std::get<uIndex>(args), json_msg.c_str(), json_msg.size());
        *pSize = json_msg.size();
        pLock->unlock();
    }
}

TEST_F(OvsDbApiTestFixture, ovsdb_api_write_gateway_config_table_with_receipt_cb)
{
    const int sock_fd = 10;
    const unsigned int startingId = 0;
    const char* rId = "1";
    struct Gateway_Config gatewayConfig = {
        "Brlan0", "10.0.0.1", "255.255.255.0", "10.100.0.1", "10.0.100.1",
        "Brlan0PIface", "Brlan0PBridge", 1480, 100, OVS_BRIDGE_IF_TYPE, OVS_IF_UP_CMD};
    const std::string actualJsonReq = "{\"method\":\"transact\",\"id\":\"1\",\"params\":[\"Open_vSwitch\",{\"op\":\"insert\",\"table\":\"Gateway_Config\",\"row\":{\"gre_ifname\":\"null\",\"if_name\":\"Brlan0\",\"if_type\":1,\"if_cmd\":0,\"inet_addr\":\"10.0.0.1\",\"netmask\":\"255.255.255.0\",\"gre_remote_inet_addr\":\"10.100.0.1\",\"gre_local_inet_addr\":\"10.0.100.1\",\"parent_ifname\":\"Brlan0PIface\",\"mtu\":1480,\"parent_bridge\":\"Brlan0PBridge\",\"vlan_id\":100}}]}";
    const std::string expectedJsonResp = "{\"id\":\"1\",\"result\":[{\"uuid\":[\"uuid\",\"f2381729-42ac-40a8-aa38-50d6d7805f2b\"]}],\"error\":null}";
    ssize_t json_len = 0;

    Rdkb_Table_Config tableConfig;
    tableConfig.table.id = OVS_GW_CONFIG_TABLE;
    tableConfig.config = &gatewayConfig;

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_connect())
        .Times(1)
        .WillOnce(Return(sock_fd));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_write(sock_fd, StrEq(actualJsonReq.c_str()), actualJsonReq.length()))
        .Times(1)
        .WillOnce(Return(actualJsonReq.length()));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_listen(sock_fd, _, _, _))
        .Times(::testing::AtLeast(1))
        .WillRepeatedly(::testing::DoAll(
            CopyStringFromQueue<1>(&m_responseQueue, &m_lock, &json_len),
            ::testing::ReturnPointee(&json_len)
            ));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_disconnect(sock_fd))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_ovsDbReceiptCallbackMock,
            OvsDbReceiptCallback(StrEq("1"), OVSDB_INSERT_RECEIPT_ID, StrEq("f2381729-42ac-40a8-aa38-50d6d7805f2b")))
        .Times(1);

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_init(startingId));

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_write(rId, &tableConfig, OvsDbReceiptCallback));

    SendMessage(expectedJsonResp);

    // Wait for the Receipt callback to be invoked
    g_ovsDbReceiptCallbackMock->wait(10);

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_deinit());
}

TEST_F(OvsDbApiTestFixture, ovsdb_api_write_feedback_table_with_receipt_cb)
{
    const int sock_fd = 10;
    const unsigned int startingId = 1;
    const char * rID = "2";
    struct Feedback feedback = {OVS_SUCCESS_STATUS, "f7d3d0e6-4ce7-4164-9134-0b5af9ce1b86"};
    ssize_t json_len = 0;
    const std::string actualJsonReq =
        "{\"method\":\"transact\",\"id\":\"2\",\"params\":[\"Open_vSwitch\",{\"op\":\"insert\",\"table\":\"Feedback\",\"row\":{\"req_uuid\":\"f7d3d0e6-4ce7-4164-9134-0b5af9ce1b86\",\"status\":0}}]}";
    std::string expectedJsonResp = "{\"id\":\"2\",\"result\":[{\"uuid\":[\"uuid\",\"f2381729-42ac-40a8-aa39-50d6d7805f2b\"]}],\"error\":null}";

    Rdkb_Table_Config tableConfig;
    tableConfig.table.id = OVS_FEEDBACK_TABLE;
    tableConfig.config = &feedback;

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_connect())
        .Times(1)
        .WillOnce(Return(sock_fd));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_write(sock_fd, StrEq(actualJsonReq.c_str()), actualJsonReq.length()))
        .Times(1)
        .WillOnce(Return(actualJsonReq.length()));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_listen(sock_fd, _, _, _))
        .Times(::testing::AtLeast(1))
        .WillRepeatedly(::testing::DoAll(
            CopyStringFromQueue<1>(&m_responseQueue, &m_lock, &json_len),
            ::testing::ReturnPointee(&json_len)
            ));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_disconnect(sock_fd))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_ovsDbReceiptCallbackMock,
            OvsDbReceiptCallback(StrEq("2"), OVSDB_INSERT_RECEIPT_ID, StrEq("f2381729-42ac-40a8-aa39-50d6d7805f2b")))
        .Times(1);

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_init(startingId));

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_write(rID, &tableConfig, OvsDbReceiptCallback));

    SendMessage(expectedJsonResp);

    // Wait for the Receipt callback to be invoked
    g_ovsDbReceiptCallbackMock->wait(10);

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_deinit());
}


TEST_F(OvsDbApiTestFixture, ovsdb_multiple_write)
{
    const int sock_fd = 10;
    const unsigned int startingId = 1;
    const char * rID = "2";
    const char * rID2 = "3";
    const char * rID3 = "4";
    ssize_t json_len = 0;

    struct Feedback feedback = {OVS_SUCCESS_STATUS, "f7d3d0e6-4ce7-4164-9134-0b5af9ce1b86"};
    struct Feedback feedback2 = {OVS_SUCCESS_STATUS, "g7d3d0e6-4ce7-4164-9134-0b5af9ce1b86"};
    struct Feedback feedback3 = {OVS_SUCCESS_STATUS, "h7d3d0e6-4ce7-4164-9134-0b5af9ce1b86"};

    const std::string actualJsonReq =
        "{\"method\":\"transact\",\"id\":\"2\",\"params\":[\"Open_vSwitch\",{\"op\":\"insert\",\"table\":\"Feedback\",\"row\":{\"req_uuid\":\"f7d3d0e6-4ce7-4164-9134-0b5af9ce1b86\",\"status\":0}}]}";
    const std::string actualJsonReq2 =
        "{\"method\":\"transact\",\"id\":\"3\",\"params\":[\"Open_vSwitch\",{\"op\":\"insert\",\"table\":\"Feedback\",\"row\":{\"req_uuid\":\"g7d3d0e6-4ce7-4164-9134-0b5af9ce1b86\",\"status\":0}}]}";
    const std::string actualJsonReq3 =
        "{\"method\":\"transact\",\"id\":\"4\",\"params\":[\"Open_vSwitch\",{\"op\":\"insert\",\"table\":\"Feedback\",\"row\":{\"req_uuid\":\"h7d3d0e6-4ce7-4164-9134-0b5af9ce1b86\",\"status\":0}}]}";

    const std::string expectedJsonResp = "{\"id\":\"2\",\"result\":[{\"uuid\":[\"uuid\",\"f2381729-42ac-40a8-aa39-50d6d7805f2b\"]}],\"error\":null}";
    const std::string expectedJsonResp2 = "{\"id\":\"3\",\"result\":[{\"uuid\":[\"uuid\",\"g2381729-42ac-40a8-aa39-50d6d7805f2b\"]}],\"error\":null}";
    const std::string expectedJsonResp3 = "{\"id\":\"4\",\"result\":[{\"uuid\":[\"uuid\",\"h2381729-42ac-40a8-aa39-50d6d7805f2b\"]}],\"error\":null}";

    Rdkb_Table_Config tableConfig;
    tableConfig.table.id = OVS_FEEDBACK_TABLE;
    tableConfig.config = &feedback;

    Rdkb_Table_Config tableConfig2;
    tableConfig2.table.id = OVS_FEEDBACK_TABLE;
    tableConfig2.config = &feedback2;

    Rdkb_Table_Config tableConfig3;
    tableConfig3.table.id = OVS_FEEDBACK_TABLE;
    tableConfig3.config = &feedback3;

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_connect())
        .Times(1)
        .WillOnce(Return(sock_fd));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_write(sock_fd, StrEq(actualJsonReq.c_str()), actualJsonReq.length()))
        .Times(1)
        .WillOnce(Return(actualJsonReq.length()));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_write(sock_fd, StrEq(actualJsonReq2.c_str()), actualJsonReq2.length()))
        .Times(1)
        .WillOnce(Return(actualJsonReq2.length()));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_write(sock_fd, StrEq(actualJsonReq3.c_str()), actualJsonReq3.length()))
        .Times(1)
        .WillOnce(Return(actualJsonReq3.length()));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_listen(sock_fd, _, _, _))
        .Times(::testing::AtLeast(1))
        .WillRepeatedly(::testing::DoAll(
            CopyStringFromQueue<1>(&m_responseQueue, &m_lock, &json_len),
            ::testing::ReturnPointee(&json_len)
            ));

    EXPECT_CALL(*g_ovsDbSocketMock, ovsdb_socket_disconnect(sock_fd))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_ovsDbReceiptCallbackMock,
            OvsDbReceiptCallback(StrEq("2"), OVSDB_INSERT_RECEIPT_ID, StrEq("f2381729-42ac-40a8-aa39-50d6d7805f2b")))
        .Times(1);

    EXPECT_CALL(*g_ovsDbReceiptCallbackMock,
            OvsDbReceiptCallback(StrEq("3"), OVSDB_INSERT_RECEIPT_ID, StrEq("g2381729-42ac-40a8-aa39-50d6d7805f2b")))
        .Times(1);

    EXPECT_CALL(*g_ovsDbReceiptCallbackMock,
            OvsDbReceiptCallback(StrEq("4"), OVSDB_INSERT_RECEIPT_ID, StrEq("h2381729-42ac-40a8-aa39-50d6d7805f2b")))
        .Times(1);

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_init(startingId));

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_write(rID, &tableConfig, OvsDbReceiptCallback));
    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_write(rID2, &tableConfig2, OvsDbReceiptCallback));
    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_write(rID3, &tableConfig3, OvsDbReceiptCallback));

    SendMessage(expectedJsonResp3);
    g_ovsDbReceiptCallbackMock->wait(10); // Wait for the Receipt callback to be invoked
    SendMessage(expectedJsonResp2);
    g_ovsDbReceiptCallbackMock->wait(10); // Wait for the Receipt callback to be invoked
    SendMessage(expectedJsonResp);
    g_ovsDbReceiptCallbackMock->wait(10); // Wait for the Receipt callback to be invoked

    ASSERT_EQ(OVS_SUCCESS_STATUS, ovsdb_deinit());
}
