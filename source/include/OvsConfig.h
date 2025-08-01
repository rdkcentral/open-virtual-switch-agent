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


#ifndef OVS_CONFIG_H_
#define OVS_CONFIG_H_

#include "gateway_config.h"
#include "feedback.h"

/**
 * @brief Table configuration ID.
 *
 * Base structure that contains the table configuration identifier that
 * uniquely identifies an associated table configuration data structure.
 */
typedef struct Table_Config
{
  OVS_TABLE id; /**< Table ID enum. */
} Table_Config;

/**
 * @brief Gateway Config table configuration.
 *
 * Structure that encapsulates Gateway Config table configuration data,
 * consisting of the table id followed by its associated table data.
 */
typedef struct Gateway_Table_Config
{
  Table_Config table; /**< Table configuration ID. */
  Gateway_Config * config; /**< Pointer to Gateway Config data. */
} Gateway_Table_Config;

/**
 * @brief Feedback table configuration.
 *
 * Structure that encapsulates Feedback table configuration data,
 * consisting of the table id followed by its associated table data.
 */
typedef struct Feedback_Table_Config
{
  Table_Config table; /**< Table configuration ID. */
  Feedback * config; /**< Pointer to Feedback data. */
} Feedback_Table_Config;

/**
 * @brief Generic RDKB Component's table configuration.
 *
 * Generic structure that encapsulates table configuration data destined
 * for the RDKB Component, consisting of the table id followed by its
 * associated table data.
 */
typedef struct Rdkb_Table_Config
{
  Table_Config table; /**< Table configuration ID. */
  void * config; /**< Generic pointer to a table ID's associated table data. */
} Rdkb_Table_Config;

/**
 * @brief Generic OvsAgent's table configuration.
 *
 * Generic structure that encapsulates table configuration data destined
 * for the OVS Agent, consisting of the table id followed by its associated
 * table data, followed by a UUID that OvsAgent requires.
 */
typedef struct OvsAgent_Table_Config
{
  Table_Config table; /**< Table configuration ID. */
  void * config; /**< Generic pointer to a table ID's associated table data. */

  char uuid[MAX_UUID_LEN + 1]; /**< UUID string, including space for null char. */
} OvsAgent_Table_Config;

/**
 * @brief Union of table configuration structures.
 *
 * Once the table id has been used to determine the type of table configuration,
 * this structure serves as a convenient accessor structure for acessing
 * the different types of table configuration's available.
 */
typedef struct Union_Table_Config
{
    union
    {
        Gateway_Table_Config gw_config; /**< Gateway Config table configuration. */
        Feedback_Table_Config fb_config; /**< Feedback table configuration. */
    } table_configs;

} Union_Table_Config;

/**
 * @brief Request structure for DB interaction.
 *
 * Structure used to send various request related data down to the DB Abstraction
 * layer for eventual processing by the OVS DB server.
 */
typedef struct ovs_interact_request
{
  OVS_BLOCK_MODE block_mode; /**< Block mode enum. */

  OVS_METHOD    method; /**< OVS DB Method enum. */
  OVS_OPERATION operation; /**< OVS DB Operation enum. */

  Rdkb_Table_Config table_config; /**< RDKB Component table configuration. */
} ovs_interact_request;

/**
 * @brief Callback for DB Interaction.
 *
 * @param[out] status Returns the status code of the DB interact operation.
 * @param[out] table_config Pointer to the RDKB Component's table configuration,
 *                          consisting of table id and config data.
 * NOTE: If needed, the RDKB Component must make a copy of the table's config
 *       data, as it will be deleted after the callback completes.
 *
 * NOTE: Maintains the same function parameter signature as the Monitor callback.
 */
typedef void (*ovs_interact_cb) (OVS_STATUS status, Rdkb_Table_Config * table_config);

#endif /* OVS_CONFIG_H_ */
