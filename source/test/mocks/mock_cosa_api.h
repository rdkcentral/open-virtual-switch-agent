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

#ifndef MOCK_COSA_API_H
#define MOCK_COSA_API_H

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "ccsp_base_api.h"

class CosaInterface {
public:
   virtual ~CosaInterface() {}
   virtual bool Cosa_Init() = 0;
   virtual void Cosa_Shutdown() = 0;
   virtual bool Cosa_FindDestComp(char *, char **, char **) = 0;
   virtual bool Cosa_GetParamValues(char *, char *, char **, int, int *, parameterValStruct_t***) = 0;
   virtual void Cosa_FreeParamValues(int, parameterValStruct_t**) = 0;
};

class CosaMock : public CosaInterface {
public:
   virtual ~CosaMock() {}
   MOCK_METHOD0(Cosa_Init, bool());
   MOCK_METHOD0(Cosa_Shutdown, void());
   MOCK_METHOD3(Cosa_FindDestComp, bool(char *, char **, char **));
   MOCK_METHOD6(Cosa_GetParamValues, bool(char *, char *, char **, int, int *, parameterValStruct_t***));
   MOCK_METHOD2(Cosa_FreeParamValues, void(int, parameterValStruct_t**));
};

#endif
