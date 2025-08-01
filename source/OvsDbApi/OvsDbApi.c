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

#include <string.h>
#include <pthread.h>
#include <stdio.h>
#include "OvsDbApi/OvsDbDefs.h"
#include "OvsDbApi/OvsDbApi.h"
#include "OvsDbApi/ovsdb_parser.h"
#include "OvsDbApi/receipt_list.h"
#include "OvsDbApi/mon_update_list.h"
#include "OvsDbApi/ovsdb_socket.h"
#include "common/OvsAgentLog.h"

#define OVSDB_SOCKET_LISTEN_TIMEOUT_MSECS 100

static void dummy_receipt_cb(const char* rid, const OvsDb_Base_Receipt* result);

// TODO: Context structure used to generate a handle to this context
/*typedef struct ovs_db_sock_context
{
    int fd;
    int timeout;
    int status;
} ovs_db_sock_context;*/

static unsigned int id = 0;
static pthread_t listen_thread;
static int ovsdb_sock_fd = -1;
static volatile bool g_terminate = false;

static void* ovsdb_listen(void* data)
{
    char recv_buffer[128 * 1024] = {0};
    int ret = 0;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    int timeout = OVSDB_SOCKET_LISTEN_TIMEOUT_MSECS;

    if (!data){
        timeout = *(int*)data;
    }
    OvsDbApiDebug("%s thread timeout %d\n", __func__, timeout);

    while(!g_terminate){
        ret = ovsdb_socket_listen(ovsdb_sock_fd, recv_buffer,
                                  sizeof(recv_buffer), timeout);
        if(ret < 0){
            OvsDbApiError("%s thread received ret=%d\n", __func__, ret);
            status = OVS_FAILED_STATUS;
            break;
        }
        if (ret != 0){
            OvsDbApiDebug("%s thread read %d bytes\n", __func__, ret);
        }
        /**
          TODO:
        - READS ONE BYTE FROM SOCKET AT A TIME
        - Doesn't support non-blocking sockets: https://github.com/akheron/jansson/issues/410
        json_error_t error;
        json_t* ovsdb_msg = json_loadfd(ovsdb_fd, JSON_DISABLE_EOF_CHECK, &error);
        if(ovsdb_msg == NULL){
            OvsDbApiError("%s Failed to load JRPC over socket: %s\n", __func__, error.text);
            continue;
        }
        **/

        if(ret > 0){
            status = ovsdb_parse_msg(recv_buffer, ret);
            if (status != OVS_SUCCESS_STATUS){
                OvsDbApiError("%s failed to parse json message: %s\n",
                    __func__, recv_buffer);
            }
        }
    }

    if (ovsdb_socket_disconnect(ovsdb_sock_fd) < 0){
        status = OVS_FAILED_STATUS;
    }
    ovsdb_sock_fd = -1;

    OvsDbApiDebug("%s thread exiting with status %d\n", __func__, status);
    pthread_exit(&status);
}

/**
 * Initialize the OVSDB Abstraction layer
 * Must use this function before any other OVSDB APIs
**/
OVS_STATUS ovsdb_init(unsigned int startingId)
{
    int timeout = OVSDB_SOCKET_LISTEN_TIMEOUT_MSECS;

    // sets the starting value for the id generator
    id = startingId;

    if (ovsdb_sock_fd >= 0){
        OvsDbApiDebug("%s socket already initialized, fd=%d\n", __func__, ovsdb_sock_fd);
        return OVS_SUCCESS_STATUS;
    }

    int ret = ovsdb_socket_connect();
    if(ret < 0){
        OvsDbApiError("Failed to connect to OVSDB socket.\n");
        return OVS_FAILED_STATUS;
    }
    ovsdb_sock_fd = ret;

    g_terminate = false;

    ret = pthread_create(&listen_thread, NULL, ovsdb_listen, &timeout);
    if(ret != 0){
        OvsDbApiError("Failed to create ovsdb_listen thread.\n");
        (void)ovsdb_socket_disconnect(ovsdb_sock_fd);
        ovsdb_sock_fd = -1;
        return OVS_FAILED_STATUS;
    }

    return OVS_SUCCESS_STATUS;
}

OVS_STATUS ovsdb_deinit()
{
    int ret;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    void * ptrStatus = (void*)&status;

    g_terminate = true;

    OvsDbApiDebug("%s calling join on thread...\n", __func__);
    ret = pthread_join(listen_thread, (void**)&ptrStatus);
    if (ret != 0){
        OvsDbApiError("%s thread join error, ret=%d", __func__, ret);
        status = OVS_FAILED_STATUS;
    }

    if(mon_list_clear() != OVS_SUCCESS_STATUS){
        status = OVS_FAILED_STATUS;
        OvsDbApiError("%s failed to clear monitor list.\n", __func__);
    }

    if(receipt_list_clear() != OVS_SUCCESS_STATUS){
        status = OVS_FAILED_STATUS;
        OvsDbApiError("%s failed to clear receipt list.\n", __func__);
    }


    OvsDbApiDebug("%s returning status %d\n", __func__, status);
    return status;
}

/**
 * Sends a message to the OVSDB table.  Calls the callback with the generated UUID when OVSDB responds.
**/
OVS_STATUS ovsdb_write(const char* rID, Rdkb_Table_Config* config, ovsdb_receipt_cb receipt_cb)
{
    size_t len = 0;
    ssize_t size = 0;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    char * str_json = NULL;

    if (!rID || !config){
        OvsDbApiError("%s Invalid NULL parameter.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    OvsDbApiDebug("%s rId: %s\n", __func__, rID);

    str_json = ovsdb_insert_to_json(config, rID);
    if (!str_json){
        OvsDbApiError("Failed to convert GW config to JSON string.\n");
        return OVS_FAILED_STATUS;
    }
    OvsDbApiDebug("Successfully converted GC to JSON str: %s\n", str_json);

    // Add to the receipt list before writing to socket to avoid any race condition issues
    status = receipt_list_add(rID, OVSDB_INSERT_RECEIPT_ID,
            (receipt_cb != NULL) ? receipt_cb : dummy_receipt_cb);
    if(status != OVS_SUCCESS_STATUS){
        OvsDbApiError("%s failed to add to the receipt list.\n", __func__);
        free(str_json);
        return status;
    }

    len = strlen(str_json);
    size = ovsdb_socket_write(ovsdb_sock_fd, str_json, len);
    if(size < 0){
        OvsDbApiError("Failed to write rId %s to socket.\n", rID);
        free(str_json);
        return OVS_FAILED_STATUS;
    }

    free(str_json);
    OvsDbApiDebug("%s successfully wrote %zd/%zu bytes for rId %s to socket.\n",
        __func__, size, len, rID);
    return status;
}

/**
 * Send the monitor message to OVSDB and calls the callback whenever we get a response
**/
OVS_STATUS ovsdb_monitor(OVS_TABLE ovsdb_table, ovsdb_mon_cb mon_cb, ovsdb_receipt_cb receipt_cb)
{
    //TODO: Implement proper unique ID, use ID generator
    size_t len = 0;
    ssize_t size = 0;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    char * str_json = NULL;
    char unique_id[MAX_UUID_LEN+1] = { 0 };
    char rID[MAX_UUID_LEN+1] = { 0 };

    if (!mon_cb){
        OvsDbApiError("Provided monitor callback is NULL.\n");
        return OVS_FAILED_STATUS;
    }

    snprintf(unique_id, sizeof(unique_id), "%u", id_generate());
    snprintf(rID, sizeof(rID), "%u", id_generate());
    OvsDbApiDebug("%s table: %d, rId: %s, Unique Id: %s\n",
        __func__, ovsdb_table, rID, unique_id);

    //Create the JSON string
    str_json = ovsdb_monitor_to_json(ovsdb_table, rID, unique_id);
    if (!str_json){
        OvsDbApiError("%s unable to convert to JSON string.\n", __func__);
        return OVS_FAILED_STATUS;
    }
    OvsDbApiDebug("%s generated monitor json string: %s\n",
        __func__, str_json);

    status = receipt_list_add(rID, OVSDB_MONITOR_RECEIPT_ID,
            (receipt_cb != NULL) ? receipt_cb : dummy_receipt_cb);
    if(status != OVS_SUCCESS_STATUS){
        OvsDbApiError("%s failed to register receipt callback.\n", __func__);
        free(str_json);
        return status;
    }

    status = mon_list_add(unique_id, mon_cb);
    if(status != OVS_SUCCESS_STATUS){
        OvsDbApiError("%s failed to register monitor callback.\n", __func__);
        free(str_json);
        return status;
    }

    //Write it to the OVSDB socket
    len = strlen(str_json);
    size = ovsdb_socket_write(ovsdb_sock_fd, str_json, len);
    if(size < 0){
        OvsDbApiError("%s failed to write to OVSDB socket.\n", __func__);
        mon_list_remove(unique_id);
        free(str_json);
        return OVS_FAILED_STATUS;
    }

    free(str_json);
    OvsDbApiInfo("%s successfully wrote %zd/%zu bytes for rId %s to socket.\n",
        __func__, size, len, rID);
    return status;
}

//TODO: Call this from the associated OvsAgentApi.c (in deinit)
OVS_STATUS ovsdb_monitor_cancel(const char * rID, ovsdb_receipt_cb receipt_cb)
{
    size_t len = 0;
    ssize_t size = 0;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    char * str_json = NULL;
    char new_id[MAX_UUID_LEN+1] = { 0 };

    if (!rID){
        OvsDbApiError("%s cannot have NULL as rId.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    snprintf(new_id, sizeof(new_id), "%u", id_generate());
    OvsDbApiDebug("%s rId: %s, New Id: %s\n", __func__, rID, new_id);

    str_json = ovsdb_monitor_cancel_to_json(rID, new_id);
    if (!str_json){
        OvsDbApiError("Failed to build monitor cancel JSON string\n");
        return OVS_FAILED_STATUS;
    }

    status = receipt_list_add(new_id, OVSDB_MONITOR_CANCEL_RECEIPT_ID, receipt_cb);
    if(status != OVS_SUCCESS_STATUS){
        OvsDbApiError("Failed to add receipt_cb to receipt list.\n");
        free(str_json);
        return status;
    }

    len = strlen(str_json);
    size = ovsdb_socket_write(ovsdb_sock_fd, str_json, len);
    if(size < 0){
        OvsDbApiError("%s failed to write JSON to socket\n", __func__);
        free(str_json);
        return OVS_FAILED_STATUS;
    }

    status = mon_list_remove(rID);
    if(status != OVS_SUCCESS_STATUS){
        OvsDbApiError("Failed to remove node from monitor list.\n");
        free(str_json);
        return status;
    }

    free(str_json);
    OvsDbApiInfo("%s successfully wrote %zd/%zu bytes to socket.\n", __func__,
        size, len);
    return status;
}

OVS_STATUS ovsdb_delete(OVS_TABLE ovsdb_table, const char * key, const char * value)
{
    size_t len = 0;
    ssize_t size = 0;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    char * str_json = NULL;
    char new_id[MAX_UUID_LEN+1] = { 0 };

    if (!key || !value)
    {
        OvsDbApiError("%s Invalid NULL parameter.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    snprintf(new_id, sizeof(new_id), "%u", id_generate());

    OvsDbApiDebug("%s Table: %d, New Id: %s, Key: %s, Value: %s\n", __func__,
        ovsdb_table, new_id, key, value);

    str_json = ovsdb_delete_to_json(ovsdb_table, new_id, key, value);
    if (!str_json)
    {
        OvsDbApiError("%s Failed to convert GW config to JSON string.\n",
            __func__);
        return OVS_FAILED_STATUS;
    }
    OvsDbApiDebug("%s Converted to JSON str: %s\n", __func__, str_json);

    status = receipt_list_add(new_id, OVSDB_DELETE_RECEIPT_ID,
        dummy_receipt_cb);
    if(status != OVS_SUCCESS_STATUS){
        OvsDbApiError("%s failed to add to the receipt list.\n", __func__);
        free(str_json);
        return status;
    }

    len = strlen(str_json);
    size = ovsdb_socket_write(ovsdb_sock_fd, str_json, len);
    if (size < 0)
    {
        OvsDbApiError("%s failed to write JSON to socket\n", __func__);
        free(str_json);
        return OVS_FAILED_STATUS;
    }

    free(str_json);
    OvsDbApiDebug("%s successfully wrote %zd/%zu bytes to socket.\n", __func__,
        size, len);
    return status;
}

unsigned int id_generate()
{
    return ++id;
}

/** Dummy callback used to print data when not provided by API consumer **/
static void dummy_receipt_cb(const char* rid, const OvsDb_Base_Receipt* result) //TODO: Change signature and print receipt id
{
    if (!rid || !result)
    {
        return;
    }
    OvsDbApiDebug("%s, rid: %s, Receipt Id: %d, error: %s\n", __func__,
        rid, result->receipt_id, result->error);
}
