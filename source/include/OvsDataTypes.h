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

#ifndef OVS_DATA_TYPES_H_
#define OVS_DATA_TYPES_H_

/**
 * @brief OVS Callback status codes.
 *
 * Enumeration that defines the different types of status return codes
 * supported by the OVS Agent API methods, callback functions, and DB
 * Abstraction layer.
 */
typedef enum ovs_status
{
  OVS_SUCCESS_STATUS = 0, /**< Success status. */
  OVS_UNKNOWN_STATUS, /**< Unknown or pending status. */
  OVS_FAILED_STATUS, /**< Failed or error status. */
  OVS_TIMED_OUT_STATUS, /**< Operation timed out. */
  OVS_TIMED_WAIT_ERROR_STATUS /**< Error while waiting on a timed operation to complete. */
} OVS_STATUS;

/**
 * @brief OVS Table IDs/types.
 *
 * Enumeration that defines the different types of OVS DB tables
 * supported by the OVS Agent API and DB Abstraction layer.
 */
typedef enum ovs_table
{ // TODO: start at 1, avoid 0
  OVS_GW_CONFIG_TABLE = 0, /**< Gateway Config table id. */
  OVS_FEEDBACK_TABLE, /**< Feedback table id. */
  OVS_NOTIFY_TABLE, /**< Notifcation table id. */
  OVS_LOGBOOK_TABLE /**< Logbook table id. */
} OVS_TABLE;

/**
 * @brief OVS Request Method types.
 *
 * Enumeration that defines the different types of OVS DB methods
 * supported by the OVS Agent API and DB Abstraction layer.
 */
typedef enum ovs_method
{
  OVS_TRANSACT_METHOD = 0, /**< Transact method. */
  OVS_MONITOR_METHOD /**< Monitor method. */
} OVS_METHOD;

/**
 * @brief OVS Request Operation types.
 *
 * Enumeration that defines the different types of OVS DB operations
 * supported by the OVS Agent API and DB Abstraction layer.
 */
typedef enum ovs_operation
{
  OVS_INSERT_OPERATION = 0, /**< Insert operation. */
  OVS_UPDATE_OPERATION, /**< Update Operation. */
  OVS_DELETE_OPERATION  /**< Delete operation. */
} OVS_OPERATION;

/**
 * @brief OVS Request Component IDs.
 *
 * Enumeration that defines the different types of system components
 * that are identified for use by the OVS Agent API.
 */
typedef enum ovs_component_id
{
  OVS_TEST_APP_COMPONENT_ID = 1, /** OVS Test Application Component. */
  OVS_AGENT_COMPONENT_ID, /**< OVS Agent component. */
  OVS_BRIDGE_UTILS_COMPONENT_ID, /**< RDKB Bridge Utils component. */
  OVS_MESH_AGENT_COMPONENT_ID, /** RDKB Mesh Agent component. */
  OVS_MAX_COMPONENT_ID /** Maximum Component Identifier. */
} OVS_COMPONENT_ID;

/**
 * @brief OVS Request block modes.
 *
 * Enumeration that defines the two different types of block modes
 * supported by the OVS Agent API. If block mode is enabled, the
 * client thread is blocked till the callback(s) completes. If block
 * mode is disabled, the client thread is NOT blocked and the status
 * and data is returned asyncronously at a later time.
 */
typedef enum ovs_block_mode
{
  OVS_DISABLE_BLOCK_MODE = 0, /**< Block mode disabled. */
  OVS_ENABLE_BLOCK_MODE /**< Block mode enabled. */
} OVS_BLOCK_MODE;

/**
 * @brief OVS RDKB Device's Model Number.
 *
 * Device's Model Number identified by the MODEL_NUM field from the
 * /etc/device.properties file.
 *
 */
typedef enum ovs_device_model
{
  OVS_UNKNOWN_MODEL = 0,/**< Unknown or unrecognized model. */
  OVS_CGM4140COM_MODEL, /**< Technicolor XB6. */
  OVS_TG3482G_MODEL,    /**< Arris XB6. */
  OVS_CGM4981COM_MODEL, /** Technicolor XB8. */
  OVS_CGM601TCOM_MODEL, /** Vantiva XB10. */
  OVS_SG417DBCT_MODEL,  /** Sercomm XB10. */
  OVS_CGM4331COM_MODEL, /** Technicolor XB7. */
  OVS_VTER11QEL_MODEL,  /** XER5. */
  OVS_SR213_MODEL,      /** Sky Sharman SR213. */
  OVS_SR300_MODEL,      /** Sky Ada SR300. */
  OVS_SE501_MODEL,      /** Sky Ashelene SE501. */
  OVS_WNXL11BWL_MODEL,  /** Sky/Comcast XLE WNXL11BWL. */
  OVS_SR203_MODEL,      /** Sky HUB4 SR203. */
  OVS_TG4482A_MODEL,    /** Commscope XB7. */
  OVS_CGA4332COM_MODEL, /** Technicolor CBR2. vinoth */
  OVS_SCER11BEL_MODEL,  /** Sercomm XER10 */
  OVS_RPI_MODEL,        /** RPI Reference Platform */
  OVS_SCXF11BFL_MODEL,  /** Sercomm XF10 */
} OVS_DEVICE_MODEL;

#endif /* OVS_DATA_TYPES_H_ */
