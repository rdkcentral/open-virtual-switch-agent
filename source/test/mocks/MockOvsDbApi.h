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

#ifndef MOCK_OVS_DB_API_H
#define MOCK_OVS_DB_API_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "OvsDbApi/OvsDbDefs.h"

class OvsDbApiInterface
{
    public:
        virtual ~OvsDbApiInterface() {}
        virtual OVS_STATUS ovsdb_init(unsigned int) = 0;
        virtual OVS_STATUS ovsdb_deinit() = 0;
        virtual OVS_STATUS ovsdb_write(const char *, Rdkb_Table_Config *, ovsdb_receipt_cb) = 0;
        virtual OVS_STATUS ovsdb_monitor(OVS_TABLE, ovsdb_mon_cb, ovsdb_receipt_cb) = 0;
        virtual OVS_STATUS ovsdb_monitor_cancel(const char *, ovsdb_receipt_cb) = 0;
        virtual OVS_STATUS ovsdb_delete(OVS_TABLE, const char *, const char *) = 0;
        virtual unsigned int id_generate() = 0;
};

class OvsDbApiMock : public OvsDbApiInterface
{
    public:
        virtual ~OvsDbApiMock() {}
        MOCK_METHOD1(ovsdb_init, OVS_STATUS(unsigned int));
        MOCK_METHOD0(ovsdb_deinit, OVS_STATUS());
        MOCK_METHOD3(ovsdb_write, OVS_STATUS(const char *, Rdkb_Table_Config *, ovsdb_receipt_cb));
        MOCK_METHOD3(ovsdb_monitor, OVS_STATUS(OVS_TABLE, ovsdb_mon_cb, ovsdb_receipt_cb));
        MOCK_METHOD2(ovsdb_monitor_cancel, OVS_STATUS(const char *, ovsdb_receipt_cb));
        MOCK_METHOD3(ovsdb_delete, OVS_STATUS(OVS_TABLE, const char *, const char *));
        MOCK_METHOD0(id_generate, unsigned int());
};

#endif
