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

#ifndef OVSDBAPI_H
#define OVSDBAPI_H

#include "OvsDbApi/OvsDbDefs.h"

OVS_STATUS ovsdb_init(unsigned int startingId);
OVS_STATUS ovsdb_deinit();
OVS_STATUS ovsdb_write(const char* rID, Rdkb_Table_Config * table_config,
    ovsdb_receipt_cb receipt_cb);
OVS_STATUS ovsdb_monitor(OVS_TABLE ovsdb_table, ovsdb_mon_cb mon_cb,
    ovsdb_receipt_cb receipt_cb);
OVS_STATUS ovsdb_monitor_cancel(const char * rID, ovsdb_receipt_cb receipt_cb);
OVS_STATUS ovsdb_delete(OVS_TABLE ovsdb_table, const char * key,
    const char * value);
unsigned int id_generate();

#endif
