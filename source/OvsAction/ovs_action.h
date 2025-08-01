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

#ifndef OVS_ACTION_H
#define OVS_ACTION_H

#include "OvsDataTypes.h"
#include "gateway_config.h"
#include "feedback.h"

#define MODEL_NUM        "MODEL_NUM"      // from /etc/device.properties
#define ONE_WIFI_ENABLED "OneWiFiEnabled" // from /etc/device.properties

#define SYS_CLASS_NET_PATH "/sys/class/net"

#define ETHER_TYPE_BRCM       0x886c // Broadcom Corp.
#define ETHER_TYPE_BRCM_AIRIQ 0x88b7 // Broadcom Corp. AiriQ
#define ETHER_TYPE_802_1X     0x888e // 802.1x

#define BR106_ETH_NAME  "br106" // LnF Bridge
#define WL0_3_ETH_NAME  "wl0.3" // LnF port
#define BRLAN0_ETH_NAME "brlan0"
#define LLAN0_ETH_NAME  "llan0"
#define PUMA7_ETH1_NAME "nsgmii1.100"
#define PUMA7_ETH2_NAME "nsgmii1.101"
#define PUMA7_ETH1_PATH "/sys/class/net/nsgmii1.100"
#define PUMA7_ETH2_PATH "/sys/class/net/nsgmii1.101"
#define PUMA7_PORT1_NAME "eth_0"
#define PUMA7_PORT2_NAME "eth_1"

#define ETH_BHAUL_IF_NAME "ethsw123"
#define ETH_BHAUL_BR_NAME "brebhaul"
#define ETH_BHAUL_IF_PATH "/sys/class/net/ethsw123"
#define ETH_BHAUL_VLAN    "123"

#define LINUX_INTERFACE_PREFIX "INTERFACE="
#define LINUX_BRPORT_POSTFIX_PATH "/brport/bridge/uevent"

OVS_STATUS ovs_action_init();
OVS_STATUS ovs_action_gateway_config(Gateway_Config * req);
OVS_STATUS ovs_action_feedback(Feedback * req);

#endif
