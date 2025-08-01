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
#include <stdbool.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "test/mocks/mock_fd.h"
#include "test/mocks/mock_socket.h"

extern "C" {
#include "OvsDbApi/ovsdb_socket.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

/* This is the actual definition of the mock obj */
FileDescriptorMock * g_fdMock = NULL;
SocketMock * g_socketMock = NULL;

class OvsDbSocketTestFixture : public ::testing::Test
{
    protected:
        FileDescriptorMock mockedFd;
        SocketMock mockedSocket;

        OvsDbSocketTestFixture()
        {
            g_fdMock = &mockedFd;
            g_socketMock = &mockedSocket;
        }
        virtual ~OvsDbSocketTestFixture()
        {
            g_fdMock = NULL;
            g_socketMock = NULL;
        }

        virtual void SetUp()
        {
            printf("%s\n", __func__);
        }

        virtual void TearDown()
        {
            printf("%s\n", __func__);
        }

        static void SetUpTestCase()
        {
            printf("%s\n", __func__);
        }

        static void TearDownTestCase()
        {
            printf("%s\n", __func__);
        }
};

TEST_F(OvsDbSocketTestFixture, ovsdb_socket_connect_disconnect)
{
    int sock_fd = 10;

    EXPECT_CALL(*g_socketMock, socket(_, _, _))
        .Times(1)
        .WillOnce(Return(sock_fd));
    EXPECT_CALL(*g_socketMock, connect(sock_fd, _, _))
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_fdMock, fcntl(sock_fd, _, _))
        .Times(2)
        .WillOnce(Return(0))
        .WillOnce(Return(0));
    EXPECT_CALL(*g_socketMock, close(sock_fd))
        .Times(1)
        .WillOnce(Return(0));

    ASSERT_EQ(sock_fd, ovsdb_socket_connect());
    ASSERT_EQ(0, ovsdb_socket_disconnect(sock_fd));
}

