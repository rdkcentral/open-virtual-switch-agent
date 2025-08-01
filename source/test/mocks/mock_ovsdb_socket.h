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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

class OvsDbSocketInterface
{
    public:
        virtual ~OvsDbSocketInterface() {}
        virtual int ovsdb_socket_connect() = 0;
        virtual ssize_t ovsdb_socket_write(int, const char *, size_t) = 0;
        virtual ssize_t ovsdb_socket_listen(int, char *, size_t, int) = 0;
        virtual int ovsdb_socket_disconnect(int) = 0;
};

class OvsDbSocketMock : public OvsDbSocketInterface
{
    public:
        virtual ~OvsDbSocketMock() {}
        MOCK_METHOD0(ovsdb_socket_connect, int());
        MOCK_METHOD3(ovsdb_socket_write, ssize_t(int, const char *, size_t));
        MOCK_METHOD4(ovsdb_socket_listen, ssize_t(int, char *, size_t, int));
        MOCK_METHOD1(ovsdb_socket_disconnect, int(int));
};
