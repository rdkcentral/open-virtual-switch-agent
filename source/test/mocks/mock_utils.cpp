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

#include "test/mocks/mock_utils.h"

extern UtilsMock * g_utilsMock;   /* This is just a declaration! The actual mock
                                     obj is defined globally in the test file. */

// Mock Method
extern "C" int system(const char * cmd)
{
    if (!g_utilsMock)
    {
        return 0;
    }
    return g_utilsMock->system(cmd);
}

extern "C" char * getenv(const char * name)
{
    if (!g_utilsMock)
    {
        return NULL;
    }
    return g_utilsMock->getenv(name);
}

extern "C" int access(const char * pathname, int mode)
{
    if (!g_utilsMock)
    {
        return -1;
    }
    return g_utilsMock->access(pathname, mode);
}
