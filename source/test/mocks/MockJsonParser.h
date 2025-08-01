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

#ifndef MOCK_JSON_PARSER_H
#define MOCK_JSON_PARSER_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <jansson.h>
#include "OvsDbApi/OvsDbDefs.h"

class JsonParserInterface
{
    public:
        virtual ~JsonParserInterface() {}
        virtual OVS_STATUS receipt_list_process(const char*, json_t*) = 0;
        virtual OVS_STATUS ovsdb_parse_params(json_t*) = 0;
        virtual OVS_STATUS ovsdb_parse_monitor_update(const char*, json_t*) = 0;
        virtual OVS_STATUS mon_list_process(const char*, Rdkb_Table_Config*) = 0;
};

class JsonParserMock : public JsonParserInterface
{
    public:
        virtual ~JsonParserMock() {}
        MOCK_METHOD2(receipt_list_process, OVS_STATUS(const char*, json_t*));
        MOCK_METHOD1(ovsdb_parse_params, OVS_STATUS(json_t*));
        MOCK_METHOD2(ovsdb_parse_monitor_update, OVS_STATUS(const char*, json_t*));
        MOCK_METHOD2(mon_list_process, OVS_STATUS(const char*, Rdkb_Table_Config*));
};

#endif
