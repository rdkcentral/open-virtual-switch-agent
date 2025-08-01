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
#include <jansson.h>
#include <string.h>
#include "OvsDbApi/OvsDbDefs.h"
#include "common/OvsAgentLog.h"

char * fb_insert_to_json(Feedback * feedback, const char * unique_id)
{
  json_t *js_row = NULL;
  json_t *js_mainObj = NULL;
  json_t *js_params = NULL;
  json_t *js_main = NULL;
  char *str_out = NULL;

  if (!feedback || !unique_id)
  {
      OvsDbApiError("%s Unable to create JSON string due to incomplete parameters.\n",
          __func__);
      return NULL;
  }

  js_row = json_object ();
  js_mainObj = json_object ();
  js_params = json_array ();
  js_main = json_object ();

  json_array_append_new (js_params, json_string (OVSDB_DEF_DB));
  json_object_set_new (js_mainObj, "op", json_string ("insert"));
  json_object_set_new (js_mainObj, "table", json_string (FEEDBACK_TABLE_NAME));

  if (0 < json_object_set_new (js_row, "req_uuid", json_string (feedback->req_uuid)))
  {
      OvsDbApiError("%s Error adding req_uuid.\n", __func__);
  }

  if (0 < json_object_set_new (js_row, "status", json_integer (feedback->status)))
  {
      OvsDbApiError("%s Error adding status.\n", __func__);
  }

  json_object_set_new (js_mainObj, "row", js_row);
  json_array_append_new (js_params, js_mainObj);
  json_object_set_new (js_main, "method", json_string ("transact"));
  json_object_set_new (js_main, "id", json_string (unique_id));
  json_object_set_new (js_main, "params", js_params);

  str_out = json_dumps(js_main, JSON_COMPACT);
  json_decref(js_main);
  return str_out;
}
