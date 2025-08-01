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

#ifndef GATEWAY_CONFIG_H
#define GATEWAY_CONFIG_H

#include <stdbool.h>

/** \def MAX_IF_NAME_SIZE
    \brief Size of a network interface's name string.

    Defines the maximum size of a network interface's name.
    Includes space for the null character at the end of the string.
*/
#define MAX_IF_NAME_SIZE     16

/** \def MAX_IP_ADDR_SIZE
    \brief Size of a network IP Address string.

    Defines the maximum size of a network IP Address with the format
    "xxx.xxx.xxx.xxx" Includes space for the null character at the end
    of the string.
*/
#define MAX_IP_ADDR_SIZE     16

/** \def MAX_BRIDGE_NAME_SIZE
    \brief Size of a network bridge name string.

    Defines the maximum size of a network bridge's name.
    Includes space for the null character at the end of the string.
*/
#define MAX_BRIDGE_NAME_SIZE 16

/** \def DEFAULT_MTU
    \brief Default network interface's mtu.

    Integer that defines the maximum packet size for the network interface's
    maximum transmission unit (MTU) in bytes used by the Gateway Config table.
*/
#define DEFAULT_MTU       1500

/** \def DEFAULT_VLAN_ID
    \brief Default network interface's VLAN ID.

    Defines the default integer identifier for the network interface's Virtual
    LAN (VLAN) used by the Gateway Config table.
*/
#define DEFAULT_VLAN_ID   0

/**
 * @brief OVS Interface Type.
 *
 * Enumeration that defines the different types of network interfaces
 * supported by the Gateway Config table.
 */
typedef enum OVS_IF_TYPE
{
  OVS_OTHER_IF_TYPE =  0, /**< Some other network interface type. */
  OVS_BRIDGE_IF_TYPE, /**< Network bridge interface type. */
  OVS_ETH_IF_TYPE, /**< Network ethernet interface type. */
  OVS_GRE_IF_TYPE, /** Network GRE interface type. */
  OVS_VLAN_IF_TYPE /** Network VLAN interface type. */
} OVS_IF_TYPE;

/**
 * @brief OVS Network Interface/Bridge Commands.
 *
 * Enumeration that defines the different network interface or bridge
 * commands supported by the Gateway Config table.
 */
typedef enum OVS_CMD
{
  OVS_IF_UP_CMD =  0, /**< Network interface up command. */
  OVS_IF_DOWN_CMD, /**< Network interface down command. */
  OVS_IF_DELETE_CMD, /** Network interface delete command. */
  OVS_BR_REMOVE_CMD /** Network bridge removal command. */
} OVS_CMD;

/**
 * @brief OVS DB Gateway Config Table data.
 *
 * Structure that contains data related to the Gateway Config table.
 */
typedef struct Gateway_Config
{
  char if_name[MAX_IF_NAME_SIZE]; /**< Network interface name. */
  char inet_addr[MAX_IP_ADDR_SIZE]; /**< Network IP Address. */
  char netmask[MAX_IP_ADDR_SIZE]; /**< Network netmask. */
  char gre_remote_inet_addr[MAX_IP_ADDR_SIZE]; /**< GRE remote IP Address. */
  char gre_local_inet_addr[MAX_IP_ADDR_SIZE]; /**< GRE local IP Address. */
  char parent_ifname[MAX_IF_NAME_SIZE]; /**< Parent network interface name. */
  char parent_bridge[MAX_BRIDGE_NAME_SIZE]; /**< Parent network bridge name. */
  int mtu; /**< MTU packet size in bytes. */
  int vlan_id; /**< VLAN ID. */
  OVS_IF_TYPE if_type; /**< Network interface type. */
  OVS_CMD if_cmd; /**< Network interface/bridge command. */
} Gateway_Config;

#endif
