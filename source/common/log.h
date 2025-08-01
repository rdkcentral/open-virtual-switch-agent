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

#ifndef _LOG_H_
#define _LOG_H_

#include <stdbool.h>

typedef enum log_level
{
  LOG_ERROR_LEVEL = 1,
  LOG_WARNING_LEVEL,
  LOG_INFO_LEVEL,
  LOG_DEBUG_LEVEL,
  LOG_TRACE_LEVEL,
  LOG_MAX_LEVEL
} LOG_LEVEL;

bool open_log(const char *path, const char * name);

bool close_log();

bool set_log_level(LOG_LEVEL level);

bool get_log_level(LOG_LEVEL * level);

void LOG(LOG_LEVEL level, const char *module, const char *msg, ...)
    __attribute__((format (printf, 3, 4)));

#endif
