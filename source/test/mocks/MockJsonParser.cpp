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

#include <jansson.h>
#include "test/mocks/MockJsonParser.h"

extern JsonParserMock * g_jsonParserMock;

extern "C" OVS_STATUS receipt_list_process(const char* rid, json_t* result)
{
    if(!g_jsonParserMock)
    {
        return OVS_FAILED_STATUS;
    }
    return g_jsonParserMock->receipt_list_process(rid, result);
}

extern "C" OVS_STATUS ovsdb_parse_params(json_t* params)
{
    if(!g_jsonParserMock)
    {
        return OVS_FAILED_STATUS;
    }
    return g_jsonParserMock->ovsdb_parse_params(params);
}

extern "C" OVS_STATUS ovsdb_parse_monitor_update(const char * uuid, json_t* update)
{
    if(!g_jsonParserMock)
    {
        return OVS_FAILED_STATUS;
    }
    return g_jsonParserMock->ovsdb_parse_monitor_update(uuid, update);
}

extern "C" OVS_STATUS mon_list_process(const char* rid, Rdkb_Table_Config* table_config)
{
    if(!g_jsonParserMock)
    {
        return OVS_FAILED_STATUS;
    }
    return g_jsonParserMock->mon_list_process(rid, table_config);
}
