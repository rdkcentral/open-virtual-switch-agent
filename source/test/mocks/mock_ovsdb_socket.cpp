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

#include <iostream>
#include "test/mocks/mock_ovsdb_socket.h"

using namespace std;

extern OvsDbSocketMock * g_ovsDbSocketMock;   /* This is just a declaration! The actual mock
                                                 obj is defined globally in the test file. */

// Mock Method
extern "C" int ovsdb_socket_connect()
{
    cout << __FILE__ << ":" << __FUNCTION__ << endl;
    if (!g_ovsDbSocketMock)
    {
        return -1;
    }
    return g_ovsDbSocketMock->ovsdb_socket_connect();
}

extern "C" ssize_t ovsdb_socket_write(int fd, const char *buffer, size_t len)
{
    cout << __FILE__ << ":" << __FUNCTION__ << " fd=" << fd << ", len=" << len
         << ", strlen=" << strlen(buffer) << ", buffer=" << buffer << endl;
    if (!g_ovsDbSocketMock)
    {
        return -1;
    }
    return g_ovsDbSocketMock->ovsdb_socket_write(fd, buffer, len);
}

extern "C" ssize_t ovsdb_socket_listen(int fd, char *buffer, size_t size, int timeout)
{
    cout << __FILE__ << ":" << __FUNCTION__ << " fd=" << fd << ", size=" << size
         << ", len=" << strlen(buffer) << ", buffer=" << buffer << endl;
    if (!g_ovsDbSocketMock)
    {
        return -1;
    }
    return g_ovsDbSocketMock->ovsdb_socket_listen(fd, buffer, size, timeout);
}

extern "C" int ovsdb_socket_disconnect(int fd)
{
    cout << __FILE__ << ":" << __FUNCTION__ << " fd=" << fd << endl;
    if (!g_ovsDbSocketMock)
    {
        return -1;
    }
    return g_ovsDbSocketMock->ovsdb_socket_disconnect(fd);
}

