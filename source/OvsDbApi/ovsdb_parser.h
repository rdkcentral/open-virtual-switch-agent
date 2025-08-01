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

#ifndef OVSDB_PARSER_H
#define OVSDB_PARSER_H

#include "OvsDbApi/OvsDbDefs.h"

char * ovsdb_insert_to_json(Rdkb_Table_Config * config, const char * unique_id);
char * ovsdb_monitor_to_json(OVS_TABLE ovsdb_table, const char * rID,
    const char * unique_id);
char * ovsdb_monitor_cancel_to_json(const char * old_id, const char * rID);
char * ovsdb_delete_to_json(OVS_TABLE ovsdb_table, const char * rID,
    const char * key, const char * value);
OVS_STATUS ovsdb_parse_msg(const char* str_json, size_t size);
#endif
