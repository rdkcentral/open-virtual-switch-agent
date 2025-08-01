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
#include "OvsDbApi/json_parser/receipt_parser.h"
}

TEST(ReceiptParserTest, insert_receipt_parser_test)
{
    json_t* example_result = json_loads("[{\"uuid\":[\"uuid\",\"f8ecdbd4-0c07-42a9-91ff-819bbf2f4196\"]}]", 0, NULL);
    const OvsDb_Base_Receipt* base_receipt =  ovsdb_parse_result(OVSDB_INSERT_RECEIPT_ID, example_result);
    ASSERT_EQ(OVSDB_INSERT_RECEIPT_ID, base_receipt->receipt_id);

    const OvsDb_Insert_Receipt* insert_receipt = (OvsDb_Insert_Receipt*) base_receipt;
    ASSERT_STREQ("", insert_receipt->error);
    ASSERT_STREQ("f8ecdbd4-0c07-42a9-91ff-819bbf2f4196", insert_receipt->uuid);
}

TEST(ReceiptParserTest, delete_receipt_parser_test)
{
    json_t* example_result = json_loads("[{\"count\":1}]", 0, NULL);
    const OvsDb_Base_Receipt* base_receipt =  ovsdb_parse_result(OVSDB_DELETE_RECEIPT_ID, example_result);
    ASSERT_EQ(OVSDB_DELETE_RECEIPT_ID, base_receipt->receipt_id);

    const OvsDb_Delete_Receipt* delete_receipt = (OvsDb_Delete_Receipt*) base_receipt;
    ASSERT_STREQ("", delete_receipt->error);
    ASSERT_EQ(1, delete_receipt->count);
}
