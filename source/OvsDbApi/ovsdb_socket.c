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
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <string.h>
#include "OvsDbApi/OvsDbDefs.h"
#include "OvsDbApi/ovsdb_socket.h"
#include "common/OvsAgentLog.h"

#define OVSDB_SOCK_PATH "/var/run/openvswitch/db.sock"

static bool msecs_to_timeval(int msecs, struct timeval* tv)
{
    if (!tv){
        return false;
    }
    tv->tv_sec = msecs / 1000;
    tv->tv_usec = (msecs % 1000) * 1000;
    return true;
}

/**
 * Disconnect from the OVSDB socket
**/
int ovsdb_socket_disconnect(int fd)
{
    int ret = 0;

    if (fd < 0)
    {
        OvsDbApiDebug("%s invalid fd=%d\n", __func__, fd);
        return 0;
    }

    OvsDbApiInfo("%s closing fd=%d\n", __func__, fd);
    ret = close(fd);
    if (ret < 0){
        OvsDbApiError("%s socket close error. %s\n", __func__, strerror(errno));
        return -1;
    }
    return 0;
}

static int ovsdb_socket_set_mode(int fd, int flag)
{
    int status = 0;

    if (fd < 0)
    {
        OvsDbApiDebug("%s invalid fd=%d\n", __func__, fd);
        return 0;
    }

    /* get current status */
    status = fcntl(fd, F_GETFL, 0);
    if (status < 0){
        OvsDbApiError("%s get file status flags error. %s\n", __func__, strerror(errno));
        return status;
    }

    /* change to non-blocking mode */
    status = fcntl(fd, F_SETFL, status | flag);
    if (status < 0){
        OvsDbApiError("%s set file status flags error. %s\n", __func__, strerror(errno));
    }
    return status;
}

/**
 * Connect to the OVSDB socket
**/
int ovsdb_socket_connect()
{
    struct sockaddr_un peer_addr;
    int sock_fd;
    int ret;
    socklen_t addrlen;

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0){
        OvsDbApiError("OVSDB connect, opening socket::error=%s\n", strerror(errno));
        return sock_fd;
    }

    memset (&peer_addr, 0, sizeof (peer_addr));
    peer_addr.sun_family = AF_UNIX;
    strcpy (peer_addr.sun_path, OVSDB_SOCK_PATH);
    addrlen = strlen (peer_addr.sun_path) + sizeof (peer_addr.sun_family);

    ret = connect(sock_fd, (const struct sockaddr *) &peer_addr, addrlen);
    if (0 != ret){
        OvsDbApiError("OVSDB connect, connection socket::error=%s\n", strerror(errno));
        close(sock_fd);
        return ret;
    }

    /* Sets the socket's fd to non-blocking mode of operation */
    ret = ovsdb_socket_set_mode(sock_fd, O_NONBLOCK);
    if (0 != ret){
        OvsDbApiError("OVSDB connect, connection error::error=%s\n", strerror(errno));
        close(sock_fd);
        return ret;
    }

    OvsDbApiInfo("Socket connected successfully, fd=%d.\n", sock_fd);
    return sock_fd;
}

/**
 * Write sz bytes in buf to OVSDB socket
**/
ssize_t ovsdb_socket_write(int fd, const char *buffer, size_t len)
{
    ssize_t nwr = send(fd, buffer, len, 0);
    if (nwr < 0)
    {
        OvsDbApiError("OVSDB-API: JSON RPC: Error writing to socket.::error=%s|errno=%d\n",
            strerror(errno), errno);
        return -1;
    }
    return nwr;
}

/**
 * Check for data on the OVSDB socket for the specified timeout in msecs.
**/
ssize_t ovsdb_socket_listen(int fd, char * buffer, size_t size, int timeout)
{
    int ret = 0;
    ssize_t len = 0;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    const char * UUID = NULL;
    fd_set read_flags;
    struct timeval tv = {0};

    if (!msecs_to_timeval(timeout, &tv))
    {
        return -1;
    }

    FD_ZERO(&read_flags);
    FD_SET(fd, &read_flags);

    ret = select(fd + 1, &read_flags, NULL, NULL, &tv);
    if(ret == 0){
        //OvsDbApiDebug("OVSDB-API: Socket select timeout %d msecs.\n", timeout);
        return 0; // TODO: Use more meaningful OVS_STATUS code
    }
    else if(ret < 0){
        OvsDbApiError("OVSDB-API: Select socket::error=%s|errno=%d\n", strerror(errno), errno);
        return -2; // TODO: Use more meaningful OVS_STATUS code
    }

    if (FD_ISSET(fd, &read_flags))
    {
        FD_CLR(fd, &read_flags);

        memset(buffer, 0, size);
        len = recv(fd, (void*)buffer, size - 1, 0);
        if(len <= 0){
            if(len < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)){
                OvsDbApiDebug("OVSDB-API: No data received from socket::error=%s|errno=%d\n",
                    strerror(errno), errno);
                return 0; // TODO: Use more meaningful OVS_STATUS code
            }

            OvsDbApiError("OVSDB-API: Socket fd=%d connection was closed. Len: %zd\n", fd, len);
            return -3; // TODO: Use more meaningful OVS_STATUS code
        }

        buffer[len] = 0;
        OvsDbApiDebug("%s received %zd bytes, bufSize: %zd, msg: %s\n",
            __func__, len, size, buffer);
    }

    return len;
}

