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

#ifndef FEEDBACK_H
#define FEEDBACK_H

#include "OvsDataTypes.h"

/** \def MAX_UUID_LEN
    \brief Length of a UUID string.

    Defines the maximum length of a UUID string. Does not include
    space for the null character at the end of the string. An
    additional character should be added for the null character.
    e.g. 28be894a-e7d4-45b3-bc4b-fecc9c42afaa
*/
#define MAX_UUID_LEN        36

#define FEEDBACK_REQ_UUID   "req_uuid"

/**
 * @brief OVS DB Feedback table data.
 *
 * Structure that contains data related to the feedback table.
 */
typedef struct Feedback{
    OVS_STATUS status; /**< Status of the operation. */
    char req_uuid[MAX_UUID_LEN + 1]; /**< UUID of the request. */
} Feedback;

#endif
