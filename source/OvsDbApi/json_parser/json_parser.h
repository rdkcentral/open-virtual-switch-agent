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

#ifndef JSON_PARSER_H
#define JSON_PARSER_H

#include <jansson.h>
#include "gateway_config.h"
#include "feedback.h"

char* gc_insert_to_json(Gateway_Config * config, const char * unique_id);
char* fb_insert_to_json(Feedback * config, const char * unique_id);

#endif
