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

#ifndef _OVS_AGENT_LOG_H_
#define _OVS_AGENT_LOG_H_

#include <stdarg.h>
#include "common/log.h"

#ifndef OVS_AGENT_API_LOG_FILE
#define OVS_AGENT_API_LOG_FILE   "/rdklogs/logs/OvsAgentApi.log"
#endif

/**
 * @brief Configures logging for the various sub-systems with different
 *        severity levels.
 */
#define OvsActionError(...)      LOG(LOG_ERROR_LEVEL, "ACT", __VA_ARGS__)
#define OvsActionInfo(...)       LOG(LOG_INFO_LEVEL, "ACT", __VA_ARGS__)
#define OvsActionWarning(...)    LOG(LOG_WARNING_LEVEL, "ACT", __VA_ARGS__)
#define OvsActionDebug(...)      LOG(LOG_DEBUG_LEVEL, "ACT" , __VA_ARGS__)

#define OvsAgentApiError(...)    LOG(LOG_ERROR_LEVEL, "API", __VA_ARGS__)
#define OvsAgentApiInfo(...)     LOG(LOG_INFO_LEVEL, "API", __VA_ARGS__)
#define OvsAgentApiWarning(...)  LOG(LOG_WARNING_LEVEL, "API", __VA_ARGS__)
#define OvsAgentApiDebug(...)    LOG(LOG_DEBUG_LEVEL, "API" , __VA_ARGS__)

#define OvsDbApiError(...)       LOG(LOG_ERROR_LEVEL, "DB", __VA_ARGS__)
#define OvsDbApiInfo(...)        LOG(LOG_INFO_LEVEL, "DB", __VA_ARGS__)
#define OvsDbApiWarning(...)     LOG(LOG_WARNING_LEVEL, "DB", __VA_ARGS__)
#define OvsDbApiDebug(...)       LOG(LOG_DEBUG_LEVEL, "DB" , __VA_ARGS__)

#define OvsAgentSspError(...)    LOG(LOG_ERROR_LEVEL, "SSP", __VA_ARGS__)
#define OvsAgentSspInfo(...)     LOG(LOG_INFO_LEVEL, "SSP", __VA_ARGS__)
#define OvsAgentSspWarning(...)  LOG(LOG_WARNING_LEVEL, "SSP", __VA_ARGS__)
#define OvsAgentSspDebug(...)    LOG(LOG_DEBUG_LEVEL, "SSP" , __VA_ARGS__)

#endif
