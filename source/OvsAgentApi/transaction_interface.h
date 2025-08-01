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


#ifndef TRANSACTION_INTERFACE_H_
#define TRANSACTION_INTERFACE_H_

#include <stdbool.h>
#include "OvsConfig.h"

// TODO have rid be a char* instead of int in interface function definitions

/**
 * @brief Initializes the Transaction Manager.
 *
 * Allocates and initializes the transaction table.
 *
 * @return boolean true for success and false for failure.
 */
bool init_transaction_manager(void);

/**
 * @brief De-initializes the Transaction Manager.
 *
 * Deallocates and destroys the transaction table.
 *
 * @return boolean true for success and false for failure.
 */
void deinit_transaction_manager(void);

/**
 * @brief Create and adds a new transaction entry for processing.
 *
 * @param[in] rid Unique identifier associated with the request.
 * @param[in] callback Callback that is invoked when the transaction has completed.
 * @param[in] table_config Pointer to a suplied RDKB table configuration.
 *
 * @return boolean true indicating success, false indicating failure.
 */
bool insert_transaction(char * rid, ovs_interact_cb callback,
    Rdkb_Table_Config * table_config);

/**
 * @brief Deletes a transaction and frees its resources.
 *
 * @param[in] rid Unique identifier associated with the request.
 *
 * @return boolean true indicating success, false indicating failure.
*/
bool delete_transaction(char * rid);

/**
 * @brief Updates an existing transaction entry with provided UUID.
 *
 * @param[in] rid Unique identifier associated with the request.
 * @param[in] uuid The UUID associated with the DB transaction.
 *
 * @return boolean true indicating success, false indicating failure.
 */
bool update_transaction(const char * rid, const char * uuid);

/**
 * @brief Completes a transaction, calling its callback and free'ing resources.
 *
 * @param[in] uuid The UUID associated with the DB transaction.
 * @param[in] status The returned status code of the DB transaction.
 * @param[out] found Indicates whether the given uuid was found in the list.
 *
 * @return boolean true indicating success, false indicating failure.
*/
bool complete_transaction(char * uuid, OVS_STATUS status, bool * found);

#endif /* TRANSACTION_INTERFACE_H_ */
