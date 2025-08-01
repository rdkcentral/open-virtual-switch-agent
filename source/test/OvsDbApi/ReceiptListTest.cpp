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
#include "OvsDbApi/receipt_list.h"
}

namespace{
    const char* g_rID = "ABCD1234";
    const char* g_uuid = "f8ecdbd4-0c07-42a9-91ff-819bbf2f4196";
    const std::string insert_receipt = std::string("[{\"uuid\":[\"uuid\",\"") + g_uuid + "\"]}]";
    ovsdb_receipt_cb receipt_cb = [](const char* rID, const OvsDb_Base_Receipt* receipt)
    {
        ASSERT_EQ(receipt->receipt_id, OVSDB_INSERT_RECEIPT_ID);
        EXPECT_STREQ(g_rID, rID);
        OvsDb_Insert_Receipt* insert_receipt = (OvsDb_Insert_Receipt*) receipt;
        EXPECT_STREQ("", receipt->error);
        EXPECT_STREQ(g_uuid, insert_receipt->uuid);
    };
}

TEST(ReceiptListTest, OvsDbWriteReceiptSingle)
{
    json_t* result = json_loads(insert_receipt.c_str(), 0, NULL);

    ASSERT_EQ(OVS_FAILED_STATUS, receipt_list_process("WRONGRID", result));
    ASSERT_EQ(OVS_SUCCESS_STATUS, receipt_list_add(g_rID, OVSDB_INSERT_RECEIPT_ID, receipt_cb));
    ASSERT_EQ(OVS_FAILED_STATUS, receipt_list_process("WRONGRID", result));
    ASSERT_EQ(OVS_SUCCESS_STATUS, receipt_list_process(g_rID, result));
    ASSERT_EQ(OVS_FAILED_STATUS, receipt_list_process(g_rID, result));
}

TEST(ReceiptListTest, OvsDbWriteReceiptMultiple)
{
    json_t* result = json_loads(insert_receipt.c_str(), 0, NULL);

    EXPECT_EQ(OVS_SUCCESS_STATUS, receipt_list_add("WRONGRID", OVSDB_INSERT_RECEIPT_ID, receipt_cb));
    EXPECT_EQ(OVS_SUCCESS_STATUS, receipt_list_add("WRONGRID2", OVSDB_INSERT_RECEIPT_ID, receipt_cb));
    EXPECT_EQ(OVS_SUCCESS_STATUS, receipt_list_add(g_rID, OVSDB_INSERT_RECEIPT_ID, receipt_cb));
    EXPECT_EQ(OVS_SUCCESS_STATUS, receipt_list_add("WRONGRID3", OVSDB_INSERT_RECEIPT_ID, receipt_cb));

    EXPECT_EQ(OVS_FAILED_STATUS, receipt_list_process("WRONGRID4", result));
    EXPECT_EQ(OVS_SUCCESS_STATUS, receipt_list_process(g_rID, result));
    EXPECT_EQ(OVS_FAILED_STATUS, receipt_list_process(g_rID, result));
}
