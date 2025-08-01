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

//#include <iostream>
#include "test/mocks/mock_socket.h"

using namespace std;

extern SocketMock * g_socketMock;   /* This is just a declaration! The actual mock
                                       obj is defined globally in the test file. */

// Mock Method
extern "C" int socket(int domain, int type, int protocol)
{
    //cout << __FILE__ << ":" << __FUNCTION__ << endl;
    if (!g_socketMock)
    {
        return -1;
    }
    return g_socketMock->socket(domain, type, protocol);
}

extern "C" int connect(int sockfd, const struct sockaddr* addr, socklen_t addrlen)
{
    //cout << __FILE__ << ":" << __FUNCTION__ << " fd=" << sockfd << endl;
    if (!g_socketMock)
    {
        return -1;
    }
    return g_socketMock->connect(sockfd, addr, addrlen);
}

extern "C" ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    //cout << __FILE__ << ":" << __FUNCTION__ << " fd=" << sockfd << " buf="
    //     << buf << ", len=" << len << endl;
    if (!g_socketMock)
    {
        return -1;
    }
    return g_socketMock->send(sockfd, buf, len, flags);
}

extern "C" int select(int nfds, fd_set *readfds, fd_set *writefds,
                      fd_set *exceptfds, struct timeval *timeout)
{
    //cout << __FILE__ << ":" << __FUNCTION__ << " nfds=" << nfds << endl;
    if (!g_socketMock)
    {
        return -1;
    }
    return g_socketMock->select(nfds, readfds, writefds, exceptfds, timeout);
}

extern "C" ssize_t recv(int sockfd, void *buf, size_t len, int flags)
{
    //cout << __FILE__ << ":" << __FUNCTION__ << " fd=" << sockfd << endl;
    if (!g_socketMock)
    {
        return -1;
    }
    return g_socketMock->recv(sockfd, buf, len, flags);
}

extern "C" int close(int sockfd)
{
    if (!g_socketMock)
    {
        return -1;
    }
    return g_socketMock->close(sockfd);
}

/*extern "C"
{
    extern int __real_close(int sockfd);
    int __wrap_close(int sockfd)
    {
        //icout << __FILE__ << ":" << __FUNCTION__ << " fd = " << sockfd << endl;
        if (sockfd != 10)
        {
            //cout  << __FILE__ << ":" << __FUNCTION__ << " Calling real close..." << endl;
            return __real_close(sockfd);
        }
        //cout  << __FILE__ << ":" << __FUNCTION__ << " Calling mock close... %d" << STDERR_FILENO << endl;
        return g_socketMock->close(sockfd);
    }
}*/

