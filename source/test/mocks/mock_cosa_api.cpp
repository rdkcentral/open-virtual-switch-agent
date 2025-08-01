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

#include "test/mocks/mock_cosa_api.h"

extern CosaMock * g_cosaMock;   /* This is just a declaration! The actual mock
                                   obj is defined globally in the test file. */

// Mock Method
extern "C" bool Cosa_Init(void)
{
    if (!g_cosaMock)
    {
        return false;
    }
    return g_cosaMock->Cosa_Init();
}

extern "C" void Cosa_Shutdown(void)
{
    if (!g_cosaMock)
    {
        return;
    }
    g_cosaMock->Cosa_Init();
}

extern "C" bool Cosa_FindDestComp(char* pObjName, char** ppDestComponentName,
    char** ppDestComponentPath)
{
    if (!g_cosaMock)
    {
        return false;
    }
    return g_cosaMock->Cosa_FindDestComp(pObjName, ppDestComponentName,
        ppDestComponentPath);
}

extern "C" bool Cosa_GetParamValues(char* pDestComponentName,
    char* pDestComponentPath, char** pParamArray, int uParamSize,
    int* puValueSize, parameterValStruct_t*** pppValueArray)
{
    if (!g_cosaMock)
    {
        return false;
    }
    return g_cosaMock->Cosa_GetParamValues(pDestComponentName,
        pDestComponentPath, pParamArray, uParamSize, puValueSize,
        pppValueArray);
}

extern "C" void Cosa_FreeParamValues(int uSize, parameterValStruct_t** ppValueArray)
{
    if (!g_cosaMock)
    {
        return;
    }
    g_cosaMock->Cosa_FreeParamValues(uSize, ppValueArray);
}
