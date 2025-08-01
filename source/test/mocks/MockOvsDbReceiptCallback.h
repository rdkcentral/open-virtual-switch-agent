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

#ifndef OVS_DB_RECEIPT_CALLBACK_MOCK_H
#define OVS_DB_RECEIPT_CALLBACK_MOCK_H

#include <condition_variable>
#include <mutex>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

extern "C" {
#include "OvsDbApi/OvsDbDefs.h"
}

class OvsDbReceiptCallbackInterface
{
public:
    virtual ~OvsDbReceiptCallbackInterface() {}
    virtual void OvsDbReceiptCallback(const char*, const OVSDB_RECEIPT_ID, const char*) = 0;
};

class OvsDbReceiptCallbackMock: public OvsDbReceiptCallbackInterface
{
public:
    virtual ~OvsDbReceiptCallbackMock() {}
    MOCK_METHOD3(OvsDbReceiptCallback, void(const char*, const OVSDB_RECEIPT_ID, const char*));

    void notify()
    {
        cv.notify_one();
    };
    void wait(int msecs)
    {
        std::unique_lock<std::mutex> lock(mtx);
        cv.wait_for(lock, std::chrono::milliseconds(msecs));
    };

private:
    std::condition_variable cv;
    std::mutex mtx;
};

#endif
