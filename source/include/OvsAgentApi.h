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


#ifndef OVS_AGENT_API_H_
#define OVS_AGENT_API_H_

#include <stdbool.h>
#include "OvsConfig.h"

/**
 * @brief Initializes the OVS Agent API.
 *
 * Allocates and initializes internal data structures and OVS DB Socket.
 *
 * @param[in] cid Component ID enum.
 *
 * @return boolean true for success and false for failure.
 */
bool ovs_agent_api_init(OVS_COMPONENT_ID cid);

/**
 * @brief De-initializes the OVS Agent API.
 *
 * Deallocates internal data structures and releases the system resources.
 *
 * @return boolean true for success and false for failure.
 */
bool ovs_agent_api_deinit(void);

/**
 * @brief Allocates and initiaizes a table's configuration data to default values.
 *
 * @param[in] table Table identifier.
 * @param[in/out] ppConfig Pointer to a pointer to where the associated table's
 *                         configuration data is then allocated and initialized.
 *
 * @return boolean true for success and false for failure.
 */
bool ovs_agent_api_get_config(OVS_TABLE table, void ** ppConfig);

/**
 * @brief Submit request for interaction with the OVS DB Abstraction layer.
 *
 * @param[in] request Pointer to a request structure.
 * @param[in] callback Callback function that is called when the response is
 *                     ready to be provided back to the caller.
 *
 * @return boolean true indicating success, false indicating failure.
 */
bool ovs_agent_api_interact(ovs_interact_request * request, ovs_interact_cb callback);

#endif /* OVS_AGENT_API_H_ */
