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

#ifndef  OVSAGENT_LOG_H
#define  OVSAGENT_LOG_H

#include <stdbool.h>
#include "rdk_debug.h"

/**
 * @brief Enables or disables logs of different severity levels.
 */
#define OvsAgentError(...)       OVSAGENT_LOG(RDK_LOG_ERROR, __VA_ARGS__)
#define OvsAgentInfo(...)        OVSAGENT_LOG(RDK_LOG_INFO, __VA_ARGS__)
#define OvsAgentWarning(...)     OVSAGENT_LOG(RDK_LOG_WARN, __VA_ARGS__)
#define OvsAgentDebug(...)       OVSAGENT_LOG(RDK_LOG_DEBUG, __VA_ARGS__)

void OVSAGENT_LOG(unsigned int level, const char *msg, ...)
    __attribute__((format (printf, 2, 3)));

bool OvsAgentLogInit();
bool OvsAgentLogDeinit();

#endif

