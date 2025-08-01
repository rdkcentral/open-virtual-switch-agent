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

class SocketInterface
{
    public:
        virtual ~SocketInterface() {}
        virtual int socket(int, int, int) = 0;
        virtual int connect(int, const struct sockaddr *, socklen_t) = 0;
        virtual ssize_t send(int, const void *, size_t, int) = 0;
        virtual int select(int nfds, fd_set *, fd_set *,
                           fd_set *, struct timeval *) = 0;
        virtual ssize_t recv(int, void *, size_t, int) = 0;
        virtual int close(int) = 0;
};

class SocketMock : public SocketInterface
{
    public:
        virtual ~SocketMock() {}
        MOCK_METHOD3(socket, int(int, int, int));
        MOCK_METHOD3(connect, int(int, const struct sockaddr *, socklen_t));
        MOCK_METHOD4(send, ssize_t(int, const void *, size_t, int));
        MOCK_METHOD5(select, int(int, fd_set *, fd_set *, fd_set *,
                     struct timeval *));
        MOCK_METHOD4(recv, ssize_t(int, void*, size_t, int));
        MOCK_METHOD1(close, int(int));

};
