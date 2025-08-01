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
#include <jansson.h>
#include "OvsDataTypes.h"
#include "common/OvsAgentLog.h"
#include "OvsDbApi/OvsDbDefs.h"
#include "OvsDbApi/ovsdb_parser.h"
#include "OvsDbApi/json_parser/table_parser.h"
#include "OvsDbApi/json_parser/json_parser.h"
#include "OvsDbApi/mon_update_list.h"
#include "OvsDbApi/receipt_list.h"

static OVS_STATUS ovsdb_parse_monitor_update(const char * uuid, json_t* update);
static OVS_STATUS ovsdb_parse_params(json_t* params);

char * ovsdb_insert_to_json(Rdkb_Table_Config * table_config, const char * unique_id)
{
    char * str_json = NULL;

    switch(table_config->table.id)
    {
        case OVS_GW_CONFIG_TABLE:
            str_json = gc_insert_to_json((Gateway_Config*) table_config->config, unique_id);
            break;

        case OVS_FEEDBACK_TABLE:
            str_json = fb_insert_to_json((Feedback*) table_config->config, unique_id);
            break;

         default:
            OvsDbApiError("%s Failed to identify config with table id %d\n",
                __func__, table_config->table.id);
            break;
    }

    return str_json;
}

char * ovsdb_monitor_to_json(OVS_TABLE ovsdb_table, const char * rID, const char * unique_id)
{
  char * table = NULL;
  json_t *js = NULL;
  json_t *jparams;
  json_t *jtbl;
  json_t *jo_col;
  char * str_json = NULL;

  if(ovsdb_table == OVS_GW_CONFIG_TABLE)
  {
      table = GATEWAY_CONFIG_TABLE_NAME;
  }
  else if(ovsdb_table == OVS_FEEDBACK_TABLE)
  {
      table = FEEDBACK_TABLE_NAME;
  }
  else
  {
     OvsDbApiError("%s Failed to identify config with table id %d\n",
        __func__, ovsdb_table);
      return NULL;
  }

  jparams = json_array();
  json_array_append_new(jparams, json_string (OVSDB_DEF_DB));
  json_array_append_new(jparams, json_string (unique_id));

  jtbl = json_object();
  jo_col = json_object();

  json_object_set_new(jtbl, table, jo_col);

  json_array_append_new(jparams, jtbl);

  js = json_object();

  if (json_object_set_new(js, "method", json_string("monitor")) < 0)
  {
      OvsDbApiError("%s Error adding method key.\n", __func__);
      return NULL;
  }

  if (json_object_set_new(js, "params", jparams) < 0)
  {
      OvsDbApiError("%s Error adding params array.\n", __func__);
      return NULL;
  }

  if (json_object_set_new(js, "id", json_string(rID)) < 0)
  {
      OvsDbApiError("%s Error adding ID key.\n", __func__);
      return NULL;
  }

  str_json = json_dumps(js, JSON_COMPACT);
  json_decref(js);
  return str_json;

  //TODO: Check to make sure we are releasing all JSON objects and this isn't memory leak.
}

char * ovsdb_monitor_cancel_to_json(const char * old_id, const char * rID)
{
  json_t *js = NULL;
  json_t *jparams = NULL;
  char * str_json = NULL;

  jparams = json_array();
  json_array_append_new(jparams, json_string (old_id));
  js = json_object();

  if (json_object_set_new(js, "method", json_string("monitor_cancel")) < 0)
  {
      OvsDbApiError("%s Error adding method key.\n", __func__);
      return NULL;
  }

  if (json_object_set_new(js, "params", jparams) < 0)
  {
      OvsDbApiError("%s Error adding params array.\n", __func__);
      return NULL;
  }

  if (json_object_set_new(js, "id", json_string(rID)) < 0)
  {
      OvsDbApiError("%s Error adding ID key.\n", __func__);
      return NULL;
  }

  str_json = json_dumps(js, JSON_COMPACT);
  json_decref(js);
  return str_json;
}

char * ovsdb_delete_to_json(OVS_TABLE ovsdb_table, const char * rID,
    const char * key, const char * value)
{
    char * table = NULL;
    json_t *js = NULL;
    json_t *jparams;
    //json_t *jtbl;
    //json_t *jo_col;
    json_t * where_json;
    char * str_json = NULL;

    if(ovsdb_table == OVS_GW_CONFIG_TABLE)
    {
        table = GATEWAY_CONFIG_TABLE_NAME;
    }
    else if(ovsdb_table == OVS_FEEDBACK_TABLE)
    {
        table = FEEDBACK_TABLE_NAME;
    }
    else
    {
        OvsDbApiError("%s Failed to identify config with table id %d\n",
            __func__, ovsdb_table);
        return NULL;
    }

    jparams = json_array();
    json_array_append_new(jparams, json_string (OVSDB_DEF_DB));
    js = json_object();

    if (json_object_set_new(js, "method", json_string("transact")) < 0)
    {
        OvsDbApiError("%s Error adding method key.\n", __func__);
        return NULL;
    }
    if (json_object_set_new(js, "params", jparams) < 0)
    {
        OvsDbApiError("%s Error adding params array.\n", __func__);
        return NULL;
    }

    json_t * json = json_object();
    if (json_object_set_new(json, "op", json_string("delete")) < 0)
    {
        OvsDbApiError("%s Error adding op key.\n", __func__);
        return NULL;
    }

    if (json_object_set_new(json, "table", json_string(table)) < 0)
    {
        OvsDbApiError("%s Error adding table key.\n", __func__);
        return NULL;
    }

    if ((strcmp(OVSDB_TABLE_UUID, key) == 0) ||
        (strcmp(OVSDB_TABLE_UUID_ALT, key)== 0))
    {
        json_t * uuid_json = json_pack("[s,s]", OVSDB_TABLE_UUID, value);
        where_json = json_pack("[[s,s,o]]", OVSDB_TABLE_UUID_ALT, "==", uuid_json);
    }
    else
    {
        where_json = json_pack("[[s,s,s]]", key, "==", value);
    }
    if (json_object_set_new(json, "where", where_json) < 0)
    {
        OvsDbApiError("%s Error adding where key.\n", __func__);
        return NULL;
    }
    json_array_append_new(jparams, json);

    if (json_object_set_new(js, "id", json_string(rID)) < 0)
    {
        OvsDbApiError("%s Error adding ID key.\n", __func__);
        return NULL;
    }

    str_json = json_dumps(js, JSON_COMPACT);
    json_decref(js);
    return str_json;
}

OVS_STATUS ovsdb_parse_msg(const char* json_str, size_t size)
{
    OVS_STATUS status = OVS_FAILED_STATUS;
    json_error_t error;
    json_t* msg = NULL;
    size_t bytes_read = 0;

    if (!json_str)
    {
        OvsDbApiError("%s JSON message is NULL.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    do
    {
        msg = json_loads(json_str, JSON_DISABLE_EOF_CHECK, &error);
        if (!msg)
        {
            OvsDbApiError("%s failed to parse JRPC: %s\n",
                __func__, error.text);
            return OVS_FAILED_STATUS;
        }

        bytes_read += error.position;
        json_str += error.position;
        OvsDbApiDebug("%s position=%d, bytes read=%zu, size=%zu\n",
            __func__, error.position, bytes_read, size);

        json_t* id = json_object_get(msg, "id");
        if (!id)
        {
            OvsDbApiError("%s cannot fetch ID from the JRPC, must be malformed message.\n",
                __func__);
            return OVS_FAILED_STATUS; // TODO: Use more meaningful OVS_STATUS code
        }

        if (json_is_null(id))
        {
            //TODO: Check 'method' to make sure it's monitor update
            json_t* method = json_object_get(msg, "method");
            if (!method || json_is_string(method) == 0)
            {
                OvsDbApiError("The value of 'method' within JSON string is invalid.\n");
                return OVS_FAILED_STATUS;
            }
            OvsDbApiDebug("%s JSON monitor update (id=null).\n", __func__);
            json_t* params = json_object_get(msg, "params");
            if (!params || json_is_array(params) == 0)
            {
                OvsDbApiError("The value of 'params' with monitor update is invalid.\n");
                return OVS_FAILED_STATUS;
            }

            status = ovsdb_parse_params(params);
        }
        else
        {
            status = receipt_list_process(json_string_value(id), json_object_get(msg, "result"));
        }
    } while (bytes_read != size);

    return status;
}

static OVS_STATUS ovsdb_parse_params(json_t* params)
{
    size_t index;
    json_t* value;
    const char * uuid = NULL;
    OVS_STATUS status = OVS_SUCCESS_STATUS;

    if (!params)
    {
        OvsDbApiError("%s params is NULL.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    //TODO: Add check to make sure params is an array

    json_array_foreach(params, index, value)
    {
        if (index == 0)
        {
            if (!value || json_is_string(value) == 0)
            {
                OvsDbApiError("Unable to get the UUID from the monitor update.\n");
                return OVS_FAILED_STATUS;
            }

            uuid = json_string_value(value);
        }
        else
        {
            if (!value || json_is_object(value) == 0)
            {
                OvsDbApiError("Unable to get the object from the monitor update.\n");
                return OVS_FAILED_STATUS;
            }

            status = ovsdb_parse_monitor_update(uuid, value);
            if (status != OVS_SUCCESS_STATUS)
            {
                OvsDbApiError("%s failed to parse monitor update for UUID: %s\n",
                    __func__, uuid);
            }
        }
    }

    return status;
}

static OVS_STATUS ovsdb_parse_monitor_update(const char * uuid, json_t* update)
{
    OVS_STATUS status = OVS_FAILED_STATUS;
    char* str_json = NULL;

    str_json = json_dumps(update, JSON_COMPACT);
    OvsDbApiDebug("%s UUID: %s, %s\n", __func__, uuid, str_json);
    free(str_json);

    if (json_object_size(update) != 1)
    {
        OvsDbApiError("%s as the size of the update object isn't 1\n",
            __func__);
        return OVS_FAILED_STATUS;
    }

    void* iter = json_object_iter(update);
    const char* table_name = json_object_iter_key(iter);
    json_t* table_value = json_object_iter_value(iter);

    void* update_iter = json_object_iter(table_value);
    while (update_iter)
    {
        const char* update_uuid = json_object_iter_key(update_iter);
        json_t* value = json_object_iter_value(update_iter);

        void* value_iter = json_object_iter(value);
        const char* update_type = json_object_iter_key(value_iter);
        OvsDbApiDebug("%s Table %s uuid=%s, type=%s\n", __func__,
            table_name, update_uuid, update_type);

        json_t* new_update = json_object_get(value, "new");
        if (!new_update)
        {   // handles and discards an update of type 'old' i.e. delete requests
            OvsDbApiWarning(
                "%s UUID: %s - Ignoring %s monitor update. Inner UUID: %s, Type %s!\n",
                __func__, uuid, table_name, update_uuid, update_type);
            status = OVS_SUCCESS_STATUS;
        }
        else
        {
            OvsAgent_Table_Config table_config = { 0 };

            strncpy(table_config.uuid, update_uuid, sizeof(table_config.uuid));
            table_config.uuid[ sizeof(table_config.uuid)-1 ] = '\0';

            status = parse_table(table_name, new_update, (Rdkb_Table_Config*) &table_config);
            if(status != OVS_SUCCESS_STATUS)
            {
                OvsDbApiError("%s failed to parse local structure for UUID: %s.\n",
                    __func__, uuid);
                return status;
            }

            status = mon_list_process(uuid, (Rdkb_Table_Config*)&table_config);
            if (status != OVS_SUCCESS_STATUS)
            {
                OvsDbApiError("%s failed to process monitor update for UUID: %s.\n",
                    __func__, uuid);
            }

            free(table_config.config);
       }

       update_iter = json_object_iter_next(table_value, update_iter);
    }

    return status;
}
