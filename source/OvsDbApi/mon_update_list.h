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

#ifndef MON_UPDATE_LIST_H
#define MON_UPDATE_LIST_H

#include "OvsDbApi/OvsDbDefs.h"
#include "OvsDataTypes.h"

OVS_STATUS mon_list_add(const char* uuid, ovsdb_mon_cb cb);
OVS_STATUS mon_list_process(const char* uuid, Rdkb_Table_Config* table_config);
OVS_STATUS mon_list_remove(const char* uuid);
OVS_STATUS mon_list_clear();

#endif
