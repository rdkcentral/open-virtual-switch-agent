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

#ifndef RECEIPT_LIST_H
#define RECEIPT_LIST_H

#include <jansson.h>
#include "OvsDbApi/OvsDbDefs.h"

OVS_STATUS receipt_list_add(const char* rid, OVSDB_RECEIPT_ID receipt_id, ovsdb_receipt_cb cb);
OVS_STATUS receipt_list_process(const char* rid, json_t* result);
OVS_STATUS receipt_list_clear();

#endif
