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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include "common/log.h"

#define MAX_LOG_NAME_SIZE   32
#define MAX_LOG_BUFFER_SIZE 4096 // Max

#define LogInfo(...)        LOG(LOG_INFO_LEVEL, "LOG", __VA_ARGS__)
#define LogDebug(...)       LOG(LOG_DEBUG_LEVEL, "LOG" , __VA_ARGS__)

typedef struct log_context
{
    char            name[MAX_LOG_NAME_SIZE];
    LOG_LEVEL       level;
    pid_t           pid;
    int             fd;
} log_context;

static log_context * g_logger = NULL;
static const char* const g_levels[] = {"UNKNOWN", "ERROR", "WARNING", "INFO", "DEBUG", "TRACE"};

bool open_log(const char * path, const char * name)
{
    if (g_logger)
    {
        LogDebug("%s already opened fd=%d.\n", __func__,
            g_logger->fd);
        return true;
    }

    if (!path)
    {
        fprintf(stderr, "%s log file path is NULL\n", __func__);
        return false;
    }

    if ((g_logger = (log_context *)malloc(sizeof(log_context))) == NULL)
    {
        fprintf(stderr, "%s failed to intialize log context\n", __func__);
        return false;
    }

    // RDKB-3832 0644 user permissions mode
    if ((g_logger->fd = open(path, O_CREAT | O_WRONLY | O_APPEND,
                             S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0)
    {
        perror("Error: Cannot open output log file.");
        free(g_logger);
        g_logger = NULL;
        return false;
    }

    g_logger->pid = getpid();
    g_logger->level = LOG_INFO_LEVEL;
    memset(g_logger->name, 0, MAX_LOG_NAME_SIZE);
    if (name && strlen(name) > 0)
    {
        strncpy(g_logger->name, name, MAX_LOG_NAME_SIZE-1);
    }
    LogInfo("%s successfully opened fd=%d.\n", __func__, g_logger->fd);
    return true;
}

bool close_log()
{
    if (!g_logger)
    {
        return true;
    }

    LogDebug("%s closing fd=%d...\n", __func__, g_logger->fd);
    if (close(g_logger->fd) < 0)
    {
        fprintf(stderr, "%s failed to close log file!\n", __func__);
    }

    free(g_logger);
    g_logger = NULL;
    return true;
}

bool set_log_level(LOG_LEVEL level)
{
    if (!g_logger)
    {
        return false;
    }

    g_logger->level = level;
    return true;
}

bool get_log_level(LOG_LEVEL * level)
{
    if (!g_logger || !level)
    {
        return false;
    }

    *level = g_logger->level;
    return true;
}

static const char * log_level_enum_to_string(LOG_LEVEL level)
{
    if (level > 0 && level <= LOG_MAX_LEVEL)
    {
        return g_levels[level];
    }
    return g_levels[0];
}

static int printTime(const struct tm *pTm, char *pBuff, int size)
{
    return snprintf(pBuff, size, "%02d%02d%02d-%02d:%02d:%02d",
        pTm->tm_year + 1900 - 2000, pTm->tm_mon + 1,
        pTm->tm_mday, pTm->tm_hour, pTm->tm_min, pTm->tm_sec);
}

void LOG(LOG_LEVEL level, const char * module, const char * msg, ...)
{
    va_list args;
    char * buffer = NULL;
    int size = 0;
    char timestamp[40] = {0};
    struct tm tm;
    struct timeval tv;

    //fprintf(stderr, "%s level=%d, logger level=%d, msg=%s, len=%d\n", __func__,
    //    level, g_logger->level, msg, strlen(msg));
    if (g_logger && level <= g_logger->level)
    {
        buffer = (char *)malloc(MAX_LOG_BUFFER_SIZE);
        if (!buffer)
        {
            return;
        }

        gettimeofday(&tv, NULL);
        gmtime_r(&tv.tv_sec, &tm);
        size = printTime(&tm, timestamp, 40);
        //fprintf(stderr, "gettimeofday size=%d, buffer=%s.%06ld, len=%d\n",
        //    size, timestamp, tv.tv_usec, strlen(timestamp));

        size = snprintf(buffer, MAX_LOG_BUFFER_SIZE, "%s.%06ld [%s] [pid=%d] [%s] [%s] ",
            timestamp, tv.tv_usec, g_logger->name, g_logger->pid,
            module, log_level_enum_to_string(level));
        //fprintf(stderr, "snprintf size=%d, buffer=%s, len=%d\n", size, buffer, strlen(buffer));

        va_start(args, msg);
        size = vsnprintf(buffer + size, MAX_LOG_BUFFER_SIZE - size, msg, args);
        //fprintf(stderr, "vsnprintf size=%d, buffer=%s, len=%d\n", size, buffer, strlen(buffer));
        if (size < 0)
        {
            perror(buffer);
        }
        va_end(args);

        size = write(g_logger->fd, buffer, strlen(buffer));
        //fprintf(stderr, "write size=%d, buffer=%s, len=%d\n", size, buffer, strlen(buffer));
        if (buffer)
        {
            free(buffer);
            buffer = NULL;
        }
    }
}
