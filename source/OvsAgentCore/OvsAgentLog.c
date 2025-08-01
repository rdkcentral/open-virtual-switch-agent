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
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>
#include "OvsAgentCore/OvsAgentLog.h"
#include "OvsAgentDefs.h"

#define DEBUG_INI_NAME  "/etc/debug.ini"

static volatile unsigned int g_rdkLogLevel = RDK_LOG_INFO;

/**
 * @brief OvsAgentLogInit Initialize RDK Logger
 */
bool OvsAgentLogInit()
{
#ifdef FEATURE_SUPPORT_RDKLOG
    if (rdk_logger_init(DEBUG_INI_NAME) != RDK_SUCCESS)
    {
        return false;
    }
#endif

    if (access(OVSAGENT_DEBUG_ENABLE, F_OK) != -1)
    {
        g_rdkLogLevel = RDK_LOG_DEBUG;
    }
    return true;
}

/**
 * @brief OVSAGENT_LOG OVSAGENT RDK Logger API
 *
 * @param[in] level LOG Level
 * @param[in] msg Message to be logged
 */
void OVSAGENT_LOG(unsigned int level, const char *msg, ...)
{
    va_list arg;
    char *pTempChar = NULL;
    int ret = 0;

    if (level <= g_rdkLogLevel)
    {
        pTempChar = (char *)malloc(4096);
        if (pTempChar)
        {
            va_start(arg, msg);
            ret = vsnprintf(pTempChar, 4096, msg, arg);
            if (ret < 0)
            {
                perror(pTempChar);
            }
            va_end(arg);

            RDK_LOG(level, "LOG.RDK.OVSAGENT", "%s", pTempChar);

            if (pTempChar !=NULL)
            {
                free(pTempChar);
                pTempChar = NULL;
            }
        }
    }
}

bool OvsAgentLogDeinit()
{
#ifdef FEATURE_SUPPORT_RDKLOG
    return (rdk_logger_deinit() == RDK_SUCCESS ? true : false);
#endif
}

