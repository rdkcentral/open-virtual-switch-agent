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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "common/OvsAgentLog.h"
#include "OvsAction/ovs_action.h"
#include "OvsAction/syscfg.h"
#include "OvsAgentSsp/cosa_api.h"
#include "secure_wrapper.h"

#ifdef CORE_NET_LIB
#include <libnet.h>
#endif

#define MIN_IP_ADDR_STR_LEN 7  // 4+3
#define MAX_IP_ADDR_STR_LEN 15 // 12+3
#define MAC_ADDR_STR_LEN    17 // 12+5

#define OVS_PRIORITY_FILE "/tmp/of_priority_conf.txt"
#define BUFF_SIZE 4
#define TMP_STRING_SIZE 60
#define CMD_BUFF_SIZE 4096

typedef struct ovs_action_config
{
    OVS_DEVICE_MODEL modelNum; // RDKB Device Model Number
    bool             oneWifiEnabled;
} ovs_action_config;

static ovs_action_config g_ovsActionConfig = {0};

static OVS_STATUS getExistingOvsParentBridge(char * if_name,
    char * existing_bridge, size_t size, bool * found);

#ifdef CORE_NET_LIB
#define isValidSubnetByte(byte) (((byte == 255) || (byte == 254) || (byte == 252) || \
                                  (byte == 248) || (byte == 240) || (byte == 224) || \
                                  (byte == 192) || (byte == 128)) ? 1 : 0)
#define INET_ADDRSTRLEN 16 /* 4*3 + 3 dots + NULL */

void subnet(char *ipv4Addr, char *ipv4Subnet, char *subnet)
{
    int l_iFirstByte, l_iSecondByte, l_iThirdByte, l_iFourthByte;
    int l_iFirstByteSub, l_iSecondByteSub, l_iThirdByteSub, l_iFourthByteSub;

    sscanf(ipv4Addr, "%d.%d.%d.%d", &l_iFirstByte, &l_iSecondByte,
           &l_iThirdByte, &l_iFourthByte);

    sscanf(ipv4Subnet, "%d.%d.%d.%d", &l_iFirstByteSub, &l_iSecondByteSub,
           &l_iThirdByteSub, &l_iFourthByteSub);

    l_iFirstByte = l_iFirstByte & l_iFirstByteSub;
    l_iSecondByte = l_iSecondByte & l_iSecondByteSub;
    l_iThirdByte = l_iThirdByte & l_iThirdByteSub;
    l_iFourthByte = l_iFourthByte & l_iFourthByteSub;

    snprintf(subnet, 16, "%d.%d.%d.%d", l_iFirstByte,
             l_iSecondByte, l_iThirdByte, l_iFourthByte);
}

unsigned int countSetBits(int byte)
{
    unsigned int l_iCount = 0;
    if (isValidSubnetByte(byte) || 0 == byte)
    {
        while (byte)
        {
            byte &= (byte-1);
            l_iCount++;
        }
        return l_iCount;
    }
    else
    {
        OvsActionError("Invalid subnet byte:%d\n", byte);
        return 0;
    }
}

unsigned int mask2cidr(char *subnetMask)
{
    int l_iFirstByte, l_iSecondByte, l_iThirdByte, l_iFourthByte;
    int l_iCIDR = 0;

    sscanf(subnetMask, "%d.%d.%d.%d", &l_iFirstByte, &l_iSecondByte,
            &l_iThirdByte, &l_iFourthByte);

    l_iCIDR += countSetBits(l_iFirstByte);
    l_iCIDR += countSetBits(l_iSecondByte);
    l_iCIDR += countSetBits(l_iThirdByte);
    l_iCIDR += countSetBits(l_iFourthByte);
    return l_iCIDR;
}

void Set_Broadcast_address(char IfName[],char subnetmask[],char IpAddr[])
{
    int l_iCIDR;
    char l_cSubnet[16] = {0};
    char bcast[INET_ADDRSTRLEN];
    char cmd[255] = {0};

    l_iCIDR = mask2cidr(subnetmask);
    subnet(IpAddr, subnetmask, l_cSubnet);
    OvsActionDebug("%s Adding IP routes\n",__func__);
    addr_derive_broadcast(IpAddr, l_iCIDR, bcast, INET_ADDRSTRLEN);
    snprintf(cmd, sizeof(cmd),"%s/%d broadcast %s dev %s", IpAddr, l_iCIDR, bcast, IfName);
    addr_add(cmd);
    OvsActionDebug("%s cmd: %s\n", __func__, cmd);
}
#endif

static bool SetModelNum(const char * model_num, ovs_action_config * config)
{
    bool rtn = false;
    if (!model_num || !config)
    {
        return false;
    }
    if (strcmp(model_num, "CGM4140COM") == 0)
    {
        config->modelNum = OVS_CGM4140COM_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "TG3482G") == 0)
    {
        config->modelNum = OVS_TG3482G_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "CGM4981COM") == 0)
    {
        config->modelNum = OVS_CGM4981COM_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "CGM601TCOM") == 0)
    {
        config->modelNum = OVS_CGM601TCOM_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "SG417DBCT") == 0)
    {
        config->modelNum = OVS_SG417DBCT_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "CGM4331COM") == 0)
    {
        config->modelNum = OVS_CGM4331COM_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "VTER11QEL") == 0)
    {
        config->modelNum = OVS_VTER11QEL_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "CGA4332COM") == 0)
    {
        config->modelNum = OVS_CGA4332COM_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "SR300") == 0)
    {
        config->modelNum = OVS_SR300_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "SE501") == 0)
    {
        config->modelNum = OVS_SE501_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "WNXL11BWL") == 0)
    {
        config->modelNum = OVS_WNXL11BWL_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "SR203") == 0)
    {
        config->modelNum = OVS_SR203_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "SR213") == 0)
    {
        config->modelNum = OVS_SR213_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "TG4482A") == 0)
    {
        config->modelNum = OVS_TG4482A_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "SCER11BEL") == 0)
    {
        config->modelNum = OVS_SCER11BEL_MODEL;
        rtn = true;
    }
    else if (strcmp(model_num, "RPI_MOD") == 0)
    {
        config->modelNum = OVS_RPI_MODEL;
        rtn = true;
    }
    else
    {
        config->modelNum = OVS_UNKNOWN_MODEL;
        OvsActionError("Failed to lookup Model Number!\n");
    }
    return rtn;
}

static bool SetOneWifiEnabled(const char * enabled, ovs_action_config * config)
{
    if (!config)
    {
        return false;
    }
    config->oneWifiEnabled = (enabled && (strcmp(enabled, "true") == 0)) ? true : false;
    return true;
}

static char * getVlanFromInterfaceName(const char *ifName)
{
    const char delimiter = '.';
    char *vlan = NULL;
    vlan = strchr(ifName, delimiter);
    if (!vlan || *(vlan+1)=='\0')
    {
        return NULL;
    }
    vlan += 1;
    return vlan;
}

static OVS_STATUS setupAndRestoreEthSwitchCmds(char *ifName, char *ifPath,
    char *ifVlan, char *restoreIfName, char *restoreBridge, char *restorePath,
    char *restoreVlan)
{
    char parentBridge[32] = {0};
    bool found = false;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif

    OvsActionDebug("%s: Ethernet Port %s exists at %s, under %s, with vlan %s\n",
        __func__, restoreIfName, restorePath, restoreBridge, restoreVlan);

    if (restoreBridge)
    {
        OvsActionDebug("%s Cmd: ovs-vsctl del-port %s %s\n", __func__, restoreBridge, restoreIfName);
        v_secure_system("ovs-vsctl del-port %s %s", restoreBridge, restoreIfName);
    }

    // find the parent bridge of the interface and remove it
    if ((status = getExistingOvsParentBridge(ifName, parentBridge,
        sizeof(parentBridge), &found)) != OVS_SUCCESS_STATUS)
    {
        return status;
    }
    if (found)
    {
        OvsActionDebug("%s Cmd: ovs-vsctl del-port %s %s\n", __func__,  parentBridge, ifName);
        v_secure_system("ovs-vsctl del-port %s %s", parentBridge, ifName);
    }

    OvsActionDebug("%s Cmd: /bin/vlan_util add_group dummy100 100\n", __func__);
    v_secure_system("/bin/vlan_util add_group dummy100 100");

    OvsActionDebug("%s Cmd: /bin/vlan_util add_group dummy101 101\n", __func__);
    v_secure_system("/bin/vlan_util add_group dummy101 101");

    OvsActionDebug("%s Cmd: /bin/vlan_util add_interface dummy100 eth_0\n", __func__);
    v_secure_system("/bin/vlan_util add_interface dummy100 eth_0");

    OvsActionDebug("%s Cmd: /bin/vlan_util add_interface dummy101 eth_1\n", __func__);
    v_secure_system("/bin/vlan_util add_interface dummy101 eth_1");

#ifdef CORE_NET_LIB
    sts = interface_remove_from_bridge(ifName);
    if (sts == CNL_STATUS_SUCCESS) {
       OvsActionDebug("%s: Removed %s from bridge dummy%s\n", __func__, ifName, ifVlan);
    }
    else {
       OvsActionError("%s: Failed to remove %s from bridge dummy%s\n", __func__, ifName, ifVlan);
    }
#else
    OvsActionDebug("%s Cmd: brctl delif dummy%s %s\n", __func__,  ifVlan, ifName);
    v_secure_system("brctl delif dummy%s %s", ifVlan, ifName);
#endif

#ifdef CORE_NET_LIB
    sts = interface_remove_from_bridge(restoreIfName);
    if (sts == CNL_STATUS_SUCCESS) {
       OvsActionDebug("%s: Removed %s from bridge dummy%s\n", __func__, restoreIfName, restoreVlan);
    }
    else {
       OvsActionError("%s: Failed to remove %s from bridge dummy%s\n", __func__, restoreIfName, restoreVlan);
    }
#else
    OvsActionDebug("%s Cmd: brctl delif dummy%s %s\n", __func__,  restoreVlan, restoreIfName);
    v_secure_system("brctl delif dummy%s %s", restoreVlan, restoreIfName);
#endif

#ifdef CORE_NET_LIB
    sts = interface_down("dummy100");
    if (sts == CNL_STATUS_SUCCESS) {
        OvsActionDebug("%s: Successfully brought down interface dummy100\n", __func__);
        sts = bridge_delete("dummy100");
        if (sts == CNL_STATUS_SUCCESS) {
           OvsActionDebug("%s: Successfully deleted bridge dummy100\n", __func__);
        }
        else {
            OvsActionError("%s: Failed to delete bridge dummy100\n", __func__);
        }
    }
    else {
       OvsActionError("%s: Failed to bring down interface dummy100\n", __func__);
    }
#else
    OvsActionDebug("%s Cmd: ifconfig dummy100 down; brctl delbr dummy100\n", __func__);
    v_secure_system("ifconfig dummy100 down; brctl delbr dummy100");
#endif

#ifdef CORE_NET_LIB
    sts = interface_down("dummy101");
    if (sts == CNL_STATUS_SUCCESS) {
        OvsActionDebug("%s: Successfully brought down interface dummy101\n", __func__);
        sts = bridge_delete("dummy101");
        if (sts == CNL_STATUS_SUCCESS) {
           OvsActionDebug("%s: Successfully deleted bridge dummy101\n", __func__);
        }
        else {
           OvsActionError("%s: Failed to delete bridge dummy101\n", __func__);
        }
    }
    else {
       OvsActionError("%s: Failed to bring down interface dummy101\n", __func__);
    }
#else
    OvsActionDebug("%s Cmd: ifconfig dummy101 down; brctl delbr dummy101\n", __func__);
    v_secure_system("ifconfig dummy101 down; brctl delbr dummy101");
#endif

    if (restoreBridge)
    {
        OvsActionDebug("%s Cmd: ovs-vsctl add-port %s %s\n", __func__,restoreBridge, restoreIfName);
        v_secure_system("ovs-vsctl add-port %s %s", restoreBridge, restoreIfName);
    }

    if (access(ifPath, F_OK) == 0)
    {
        OvsActionDebug("%s: Ethernet Port %s exists\n", __func__, ifName);
    }
    else
    {
        OvsActionDebug("%s: Ethernet Port %s doesn't exist\n", __func__, ifName);
    }
    if (access(restorePath, F_OK) == 0)
    {
        OvsActionDebug("%s: Restored Ethernet Port %s exists\n", __func__, restoreIfName);
    }
    else
    {
        OvsActionDebug("%s: Restored Ethernet Port %s doesn't exist\n", __func__, restoreIfName);
    }
    return status;
}

static OVS_STATUS setupEthSwitchCmds(char *ifName, char *ifPath, char *ifVlan)
{
    OVS_STATUS status = OVS_SUCCESS_STATUS;

#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
    char cmd[256] = {0};
#endif
    OvsActionDebug("%s Cmd: /bin/vlan_util add_group dummy%s %s\n", __func__, ifVlan, ifVlan);
    v_secure_system("/bin/vlan_util add_group dummy%s %s", ifVlan, ifVlan);

    if (strcmp(ifName, PUMA7_ETH1_NAME) == 0)
    {
        OvsActionDebug("%s Cmd: /bin/vlan_util add_interface dummy%s %s\n", __func__,  ifVlan, PUMA7_PORT1_NAME);
        v_secure_system("/bin/vlan_util add_interface dummy%s "PUMA7_PORT1_NAME, ifVlan);
    }

    OvsActionDebug("%s Cmd: /bin/vlan_util add_interface dummy%s %s\n", __func__, ifVlan, PUMA7_PORT2_NAME);
    v_secure_system( "/bin/vlan_util add_interface dummy%s "PUMA7_PORT2_NAME, ifVlan);

#ifdef CORE_NET_LIB
    sts = interface_remove_from_bridge(ifName);
    if (sts == CNL_STATUS_SUCCESS) {
       OvsActionDebug("%s: Removed %s from bridge dummy%s\n", __func__, ifName, ifVlan);
    }
    else {
       OvsActionError("%s: Failed to remove %s from bridge dummy%s\n", __func__, ifName, ifVlan);
    }
#else
    OvsActionDebug("%s Cmd: brctl delif dummy%s %s\n", __func__,  ifVlan, ifName);
    v_secure_system("brctl delif dummy%s %s", ifVlan, ifName);
#endif

#ifdef CORE_NET_LIB
    memset(cmd, 0, sizeof(cmd));
    snprintf(cmd, sizeof(cmd), "dummy%s", ifVlan);
    sts = interface_down(cmd);
    if (sts == CNL_STATUS_SUCCESS) {
        OvsActionDebug("%s: Successfully brought down interface %s\n", __func__, cmd);
        sts = bridge_delete(cmd);
        if (sts == CNL_STATUS_SUCCESS) {
           OvsActionDebug("%s: Successfully deleted bridge %s\n", __func__, cmd);
        }
        else {
            OvsActionError("%s: Failed to delete bridge %s\n", __func__, cmd);
        }
    }
    else {
       OvsActionError("%s: Failed to bring down interface %s\n", __func__, cmd);
    }
#else
    OvsActionDebug("%s Cmd: ifconfig dummy%s down; brctl delbr dummy%s\n", __func__, ifVlan, ifVlan);
    v_secure_system("ifconfig dummy%s down; brctl delbr dummy%s", ifVlan, ifVlan);
#endif

    if (access(ifPath, F_OK) == 0)
    {
        OvsActionDebug("%s: Ethernet Port %s exists\n", __func__, ifName);
    }
    else
    {
        OvsActionDebug("%s: Ethernet Port %s doesn't exist\n", __func__, ifName);
    }
    return status;
}

//WAR: Intel Puma7 Switch hal has a dependency in using the brctl to bring up
//the interfaces. As a temporary solution intermediate create dummy Linux bridge
//create ethernet ports using the dummy bridge and move it to required OVS bridge later
//TODO: Temporary solution, long term plan is to accomodate the brcompact ARRISXB6-12186
//TODO: Add unit tests
// Also provides a fix for ARRISXB6-12678 and ARRISXB6-12964
static OVS_STATUS ovs_setupEthSwitch(char *ifName)
{
    char restoreBridge[32] = {0};
    char *restoreIfName = NULL;
    char *restorePath = NULL;
    char *restoreVlan = NULL;
    char *ifPath = NULL;
    char *ifVlan = NULL;
    bool found = false;
    bool ethBhaulFound = false;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif

    if (!ifName)
    {
        return OVS_FAILED_STATUS;
    }

    ifVlan = getVlanFromInterfaceName(ifName);
    OvsActionDebug("%s Special handling of eth switch port %s, vlan=%s\n",
        __func__, ifName, ifVlan);

    // Check for presence of ethbhaul vlan
    ethBhaulFound = (access(ETH_BHAUL_IF_PATH, F_OK) == 0) ? true : false;

    if (strcmp(ifName, PUMA7_ETH1_NAME) == 0)
    {
        ifPath = PUMA7_ETH1_PATH;
        restoreIfName = PUMA7_ETH2_NAME;
        restorePath = PUMA7_ETH2_PATH;
        restoreVlan = getVlanFromInterfaceName(restoreIfName);

        // find the parent bridge of nsgmii1.101 and store it for later
        if ((status = getExistingOvsParentBridge(restoreIfName, restoreBridge,
            sizeof(restoreBridge), &found)) != OVS_SUCCESS_STATUS)
        {
            return status;
        }

        // check if the interface path /sys/class/net/nsgmii1.101 exists
        // and if it belongs to a parent bridge, restore it back
        if ((access(restorePath, F_OK) == 0) && found)
        {
            status = setupAndRestoreEthSwitchCmds(ifName, ifPath, ifVlan,
                restoreIfName, restoreBridge, restorePath, restoreVlan);
        }
        else
        {
            OvsActionDebug("%s: Didn't find Ethernet Port path %s and parent bridge.\n",
                __func__, restorePath);
            status = setupEthSwitchCmds(ifName, ifPath, ifVlan);
        }
    }
    else if (strcmp(ifName, PUMA7_ETH2_NAME) == 0)
    {
        ifPath = PUMA7_ETH2_PATH;
        restoreIfName = PUMA7_ETH1_NAME;
        restorePath = PUMA7_ETH1_PATH;
        restoreVlan = getVlanFromInterfaceName(restoreIfName);

        // find the parent bridge of nsgmii1.100 and store it for later
        if ((status = getExistingOvsParentBridge(restoreIfName, restoreBridge,
            sizeof(restoreBridge), &found)) != OVS_SUCCESS_STATUS)
        {
            return status;
        }

        // check if the interface path /sys/class/net/nsgmii1.100 exists
        // and if it belongs to a parent bridge, restore it back
        if ((access(restorePath, F_OK) == 0) && found)
        {
            status = setupAndRestoreEthSwitchCmds(ifName, ifPath, ifVlan,
                restoreIfName, restoreBridge, restorePath, restoreVlan);
        }
        else
        {
            OvsActionDebug("%s: Didn't find Ethernet Port path %s and parent bridge.\n",
                __func__, restorePath);
            status = setupEthSwitchCmds(ifName, ifPath, ifVlan);
        }
    }

    // restore ethernet bhaul, if present before
    if (ethBhaulFound)
    {
        OvsActionDebug("%s Cmd: ip link add link %s %s type vlan proto 802.1Q id %s\n", __func__,  PUMA7_ETH1_NAME, ETH_BHAUL_IF_NAME, ETH_BHAUL_VLAN);
        v_secure_system("ip link add link "PUMA7_ETH1_NAME" "ETH_BHAUL_IF_NAME" type vlan proto 802.1Q id "ETH_BHAUL_VLAN);

#ifdef CORE_NET_LIB
        sts = interface_up(ETH_BHAUL_IF_NAME);
        if (sts == CNL_STATUS_SUCCESS) {
            OvsActionDebug("%s: Successfully brought up interface %s\n", __func__, ETH_BHAUL_IF_NAME);
        }
        else {
            OvsActionError("%s: Failed to bring up interface %s\n", __func__, ETH_BHAUL_IF_NAME);
        }
#else
        OvsActionDebug("%s Cmd: ifconfig %s up\n", __func__,  ETH_BHAUL_IF_NAME);
        v_secure_system("ifconfig "ETH_BHAUL_IF_NAME" up");
#endif

        OvsActionDebug("%s Cmd: ovs-vsctl add-port %s %s\n", __func__,  ETH_BHAUL_BR_NAME,ETH_BHAUL_IF_NAME);
        v_secure_system("ovs-vsctl add-port "ETH_BHAUL_BR_NAME" "ETH_BHAUL_IF_NAME);
    }

    return status;
}

// TODO: Uses syscfg to get the IP Address for lan0 interface.
// In the future, remove utopia and syscfg dependency and have
// this info sent by the caller. i.e. bridgeUtils
static bool GetLan0IPAddess(char *ip_address, size_t size)
{
    size_t len = 0;
    if (!ip_address)
    {
        return false;
    }
    if (SyscfgGet(LAN0_IP_ADDR_SYSCFG_PARAM_NAME, ip_address, size) == 0)
    {
        len = strlen(ip_address);
        return ((len >= MIN_IP_ADDR_STR_LEN && len <= MAX_IP_ADDR_STR_LEN) ?
            true : false);
    }
    OvsActionError("%s failed to get Lan0 IP Address!\n", __func__);
    return false;
}

// Fix for TCXB6-9125, ARRISXB6-12373, TCXB7-4051 and TCXB8-473
static OVS_STATUS ovs_setup_admin_gui_access(Gateway_Config * req)
{
    size_t len = 0;
    char ip_address[16] = {0};
    char mac_address[18] = {0};
    FILE *fp = NULL;
    int ret = 0;
    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    /* Fix for TCXB6-9125. In Bridge Mode only, setup two static Open Flow flows for
       ARP & IP packets, so ethernet clients can access the http://10.0.0.1 webpage.*/
    if (!GetLan0IPAddess(ip_address, sizeof(ip_address)))
    {
        OvsActionDebug("%s lan0 IP Address=%s, len=%zu\n",
            __func__, ip_address, strlen(ip_address));
        return OVS_FAILED_STATUS;
    }

    OvsActionDebug("%s Cmd: ovs-ofctl --strict del-flows %s arp,nw_dst=%s/32\n", __func__,req->parent_bridge, ip_address);
    ret = v_secure_system("ovs-ofctl --strict del-flows %s arp,nw_dst=%s/32",req->parent_bridge, ip_address);
    OvsActionDebug("%s : ret val of  v_secure_system %d \n",__func__,ret);

    OvsActionDebug("%s Cmd: ovs-ofctl --strict del-flows %s ip,nw_dst=%s/32\n", __func__, req->parent_bridge, ip_address);
    ret = v_secure_system( "ovs-ofctl --strict del-flows %s ip,nw_dst=%s/32",req->parent_bridge, ip_address);
    OvsActionDebug("%s : ret val of  v_secure_system %d \n",__func__,ret);

    if (req->if_cmd != OVS_BR_REMOVE_CMD)
    {
        OvsActionDebug("%s Cmd: cat /sys/class/net/lan0/address\n", __func__);
        fp = fopen("/sys/class/net/lan0/address", "r");
        if (!fp)
        {
            return OVS_FAILED_STATUS;
        }
        while (fgets(mac_address, sizeof(mac_address), fp) != NULL)
        {
            break;
        }
        fclose(fp);
        fp = NULL;

        len = strlen(mac_address);
        OvsActionDebug("%s lan0 Mac Address %s len: %zu\n", __func__,
            mac_address, len);
        if (len != MAC_ADDR_STR_LEN)
        {
            OvsActionError("%s Invalid Mac Address len %zu\n", __func__, len);
            return OVS_FAILED_STATUS;
        }
        OvsActionDebug("%s Cmd: ovs-ofctl add-flow %s arp,nw_dst=%s/32,actions=mod_dl_dst:%s,output:%s\n", __func__,req->parent_bridge, ip_address, mac_address, req->if_name);
        ret = v_secure_system("ovs-ofctl add-flow %s arp,nw_dst=%s/32,actions=mod_dl_dst:%s,output:%s",req->parent_bridge, ip_address, mac_address, req->if_name);
        OvsActionDebug("%s : OVS DEBUG3: ret val of  v_secure_system %d \n",__func__,ret);
        OvsActionDebug("%s Cmd: ovs-ofctl add-flow %s ip,nw_dst=%s/32,actions=mod_dl_dst:%s,output:%s\n", __func__, req->parent_bridge, ip_address, mac_address, req->if_name);
        ret = v_secure_system("ovs-ofctl add-flow %s ip,nw_dst=%s/32,actions=mod_dl_dst:%s,output:%s",req->parent_bridge, ip_address, mac_address, req->if_name);
	OvsActionDebug("%s : ret val of  v_secure_system %d \n",__func__,ret);
    }
    return OVS_SUCCESS_STATUS;
}

static bool GetCosaParamValues(char **paramNames, const int numParams,
    int * paramSize, parameterValStruct_t ***paramValues)
{
    char *componentName = NULL;
    char *componentPath = NULL;

    if (!paramNames || !paramSize | (numParams < 1))
    {
        return false;
    }

    OvsActionDebug("%s: Ovs Action Cosa Api Get Param '%s', numParams=%d\n",
        __func__, paramNames[0], numParams);

    if (!Cosa_FindDestComp(paramNames[0], &componentName, &componentPath) ||
        !componentName || !componentPath)
    {
        OvsActionError("Failed to find Dest CCSP component supporting '%s'!\n",
            paramNames[0]);
        return false;
    }
    OvsActionDebug(
        "%s: Ovs Action Cosa Api Found Dest CCSP component %s, Path: %s\n",
        __func__, componentName, componentPath);

    if (!Cosa_GetParamValues(componentName, componentPath, paramNames,
            numParams, paramSize, paramValues) ||
        (*paramSize != numParams) || !(*paramValues)[0])
    {
        OvsActionError(
            "Ovs Action Cosa Api Get Param Values failed for '%s' (size=%d)!\n",
            paramNames[0], *paramSize);
        Cosa_FreeParamValues(*paramSize, *paramValues);
        return false;
    }
    OvsActionDebug("%s: Ovs Action Cosa Api Get Param size=%d, %s=%s, len=%zu\n",
        __func__, *paramSize, ((*paramValues)[0])->parameterName,
        ((*paramValues)[0])->parameterValue,
        strlen(((*paramValues)[0])->parameterValue));
    return true;
}

// TCHXB6-9721 Fix to block MSO UI access from LAN clients in bridge mode.
// Fix for TCXB7-4051 and TCXB8-473
static OVS_STATUS ovs_block_mso_ui_access(Gateway_Config * req)
{
    char *paramNames[] = {"Device.DeviceInfo.X_COMCAST-COM_CM_IP"};
    const int numParams = (int)(sizeof(paramNames)/sizeof(*paramNames));
    parameterValStruct_t **paramValues = NULL;
    int paramSize = 0;
    size_t paramValueLen = 0;
    int ret = 0;

    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    if (!GetCosaParamValues(paramNames, numParams, &paramSize, &paramValues) ||
        !paramValues[0]->parameterValue)
    {
        OvsActionError("%s Ovs Action CCSP Get Param Values failed.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    paramValueLen = strlen(paramValues[0]->parameterValue);
    if (paramValueLen == 0)
    {
        OvsActionError("%s failed due to empty Get Param Value length.\n",
        __func__);
        return OVS_FAILED_STATUS;
    }
    OvsActionDebug("%s: Ovs Action Cosa Api Get Param size=%d, %s=%s, len=%zu\n",
        __func__, paramSize, paramValues[0]->parameterName,
        paramValues[0]->parameterValue, paramValueLen);

    OvsActionDebug("%s Cmd: ovs-ofctl --strict del-flows %s ipv6,ipv6_dst=%s/128\n", __func__, req->parent_bridge, paramValues[0]->parameterValue);
    ret = v_secure_system("ovs-ofctl --strict del-flows %s ipv6,ipv6_dst=%s/128",req->parent_bridge, paramValues[0]->parameterValue);
    OvsActionDebug("%s : ret val of  v_secure_system %d \n",__func__,ret);
    if (req->if_cmd != OVS_BR_REMOVE_CMD)
    {
        OvsActionDebug("%s Cmd: ovs-ofctl add-flow %s ipv6,ipv6_dst=%s/128,actions=drop\n", __func__,req->parent_bridge, paramValues[0]->parameterValue);
        ret = v_secure_system("ovs-ofctl add-flow %s ipv6,ipv6_dst=%s/128,actions=drop",req->parent_bridge, paramValues[0]->parameterValue);
	OvsActionDebug("%s :  ret val of  v_secure_system %d \n",__func__,ret);
    }

    // Free the parameter values
    Cosa_FreeParamValues(paramSize, paramValues);
    return OVS_SUCCESS_STATUS;
}

// Fix for RDKB-40884 on TCHXB7 and TCHXB8
static OVS_STATUS ovs_setup_brcm_wifi_flows(Gateway_Config * req)
{
    int idx = 0;
    int ret = 0;
    const unsigned int eth_types[] =
        {ETHER_TYPE_BRCM, ETHER_TYPE_BRCM_AIRIQ, ETHER_TYPE_802_1X};

    if (!req || strlen(req->parent_bridge) == 0)
    {
        return OVS_FAILED_STATUS;
    }

    for (idx = 0; idx < sizeof(eth_types)/sizeof(eth_types[0]); idx++)
    {
        if (((g_ovsActionConfig.modelNum == OVS_SR203_MODEL)) &&
	    (eth_types[idx] == ETHER_TYPE_802_1X))
        {   // If OneWifi is enabled (at compile time) or device is HUB4, do not setup 802.1X ovs flow.
            OvsActionDebug("%s Skipping OVS flow for Ether Type 0x%04x\n",
                __func__, eth_types[idx]);
            continue;
        }

        OvsActionDebug("%s Cmd: ovs-ofctl --strict del-flows %s \"dl_type=0x%04x, actions=%s\"\n", __func__, req->parent_bridge, eth_types[idx], req->parent_bridge);
        ret = v_secure_system("ovs-ofctl --strict del-flows %s \"dl_type=0x%04x, actions=%s\"",req->parent_bridge, eth_types[idx], req->parent_bridge);
        OvsActionDebug("%s :  ret val of  v_secure_system %d \n",__func__,ret);
        if (req->if_cmd != OVS_BR_REMOVE_CMD)
        {
            OvsActionDebug("%s Cmd: ovs-ofctl add-flow %s \"dl_type=0x%04x, actions=%s\"\n", __func__, req->parent_bridge, eth_types[idx], req->parent_bridge);
            ret = v_secure_system("ovs-ofctl add-flow %s \"dl_type=0x%04x, actions=%s\"",req->parent_bridge, eth_types[idx], req->parent_bridge);
	    OvsActionDebug("%s : ret val of  v_secure_system %d \n",__func__,ret);
        }
    }
    return OVS_SUCCESS_STATUS;
}

static OVS_STATUS getExistingOvsParentBridge(char * if_name,
    char * existing_bridge, size_t size, bool * found)
{
    size_t len = 0;
    char ports[128] = {0};
    FILE *fp = NULL;
    const char * ovsBridgeNotFoundPrefix = "ovs-vsctl:";

    if (!if_name || !existing_bridge || !found || (size == 0))
    {
        return OVS_FAILED_STATUS;
    }
    *found = false;

    OvsActionDebug("%s Cmd: ovs-vsctl iface-to-br %s\n", __func__, if_name);
    fp = v_secure_popen("r","ovs-vsctl iface-to-br %s",if_name);
    if (!fp)
    {
        return OVS_FAILED_STATUS;
    }
    while (fgets(existing_bridge, size, fp) != NULL)
    {
        OvsActionDebug("%s existing parent bridge %s", __func__, existing_bridge);
    }
    v_secure_pclose(fp);
    fp = NULL;

    /* Remove trailing newline character */
    len = strlen(existing_bridge);
    if (len > 0 && existing_bridge[len-1] == '\n')
    {
        existing_bridge[len-1] = '\0';
    }

    if ((strlen(existing_bridge) > 0) &&
        (strncmp(ovsBridgeNotFoundPrefix, existing_bridge,
            strlen(ovsBridgeNotFoundPrefix)) != 0))
    {
        OvsActionDebug("%s found existing bridge %s, len=%zu for %s\n",
            __func__, existing_bridge, strlen(existing_bridge), if_name);
        *found = true;
    }
    return OVS_SUCCESS_STATUS;
}

static OVS_STATUS getExistingLinuxParentBridge(char * if_name,
    char * existing_bridge, size_t size, bool * found)
{
    size_t len = 0;
    char line[64] = {0};
    FILE *fp = NULL;
    char ifpath[128] = {0};
    const char * linuxBridgeFoundPrefix = LINUX_INTERFACE_PREFIX;
    char * bridge = NULL;

    if (!if_name || !existing_bridge || !found || (size == 0))
    {
        return OVS_FAILED_STATUS;
    }
    *found = false;

    snprintf(ifpath, 128, "%s/%s%s", SYS_CLASS_NET_PATH, if_name, LINUX_BRPORT_POSTFIX_PATH);

    OvsActionDebug("%s path: %s\n", __func__, ifpath);
    fp = fopen(ifpath, "r");
    if (!fp)
    {
        OvsActionDebug("%s: Interface Port path %s doesn't exist\n", __func__, ifpath);
        return OVS_SUCCESS_STATUS;
    }
    while (fgets(line, sizeof(line), fp) != NULL)
    {
        if ((bridge = strstr(line, linuxBridgeFoundPrefix)) != NULL)
        {
            OvsActionDebug("%s found existing parent bridge %s for %s",
                __func__, bridge, if_name);
            break;
        }
    }
    fclose(fp);
    fp = NULL;

    if (!bridge)
    {
        OvsActionDebug("%s didn't find existing parent bridge for %s\n",
            __func__, if_name);
        return OVS_SUCCESS_STATUS;
    }
    bridge += strlen(linuxBridgeFoundPrefix);

    /* Remove trailing newline character */
    len = strlen(bridge);
    if (len > 0 && bridge[len-1] == '\n')
    {
        bridge[len-1] = '\0';
    }

    strncpy(existing_bridge, bridge, size);
    len = strlen(existing_bridge);
    if (len > 0)
    {
        OvsActionDebug("%s found existing bridge %s, len=%zu for %s\n",
            __func__, existing_bridge, len, if_name);
        *found = true;
    }
    return OVS_SUCCESS_STATUS;
}

static OVS_STATUS removeExistingInterfacePort(Gateway_Config * req, bool ovs_enabled)
{
    size_t len = 0;
    char existingBridge[32] = {0};
    bool removePort = false;
    bool found = false;
    OVS_STATUS status = OVS_SUCCESS_STATUS;
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif

    if (ovs_enabled)
    {
        status = getExistingOvsParentBridge(req->if_name, existingBridge,
            sizeof(existingBridge), &found);
    }
    else
    {
        status = getExistingLinuxParentBridge(req->if_name, existingBridge,
            sizeof(existingBridge), &found);
    }
    if (status != OVS_SUCCESS_STATUS)
    {
        return status;
    }
    if (!found)
    {
        OvsActionDebug("%s Port %s is not part of an existing bridge.\n",
            __func__, req->if_name);
        return status;
    }

    OvsActionDebug("%s Port %s already exists as part of bridge %s\n",
        __func__, req->if_name, existingBridge);
    if ((strcmp(req->parent_bridge, existingBridge) == 0) &&
        (req->if_cmd == OVS_BR_REMOVE_CMD))
    {   // parent bridge and existing bridge are the SAME and
        // command is to remove the bridge
        removePort = true;
    }
    else if ((strcmp(req->parent_bridge, existingBridge) != 0) &&
        (req->if_cmd == OVS_IF_UP_CMD))
    {   // parent bridge and existing bridge are different and
        // command is to bring the interface up but from a different
        // bridge, without having to first delete the port from the
        // other bridge, and then add it to this bridge
        removePort = true;
    }

    if (!removePort)
    {
        return status;
    }

    /* remove the port from its existing bridge */
    if (ovs_enabled)
    {
	v_secure_system("ovs-vsctl del-port %s %s", existingBridge,req->if_name);
   	OvsActionDebug("%s Cmd: ovs-vsctl del-port %s %s\n", __func__, existingBridge,req->if_name);
    }
    else
    {
#ifdef CORE_NET_LIB
        sts = interface_remove_from_bridge(req->if_name);
        if (sts == CNL_STATUS_SUCCESS) {
            OvsActionDebug("%s: Removed %s from bridge dummy%s\n", __func__, req->if_name, existingBridge);
        }
        else {
            OvsActionError("%s: Failed to remove %s from bridge dummy%s\n", __func__, req->if_name, existingBridge);
        }
#else
    	v_secure_system("brctl delif %s %s", existingBridge ,req->if_name);
    	OvsActionDebug("%s Cmd: brctl delif %s %s\n", __func__, existingBridge ,req->if_name);
#endif
    }

    return status;
}

static OVS_STATUS configureParentBridge(Gateway_Config * req, bool ovs_enabled,
    bool * exists)
{
    char ports[128] = {0};
    FILE *fp = NULL;
    char brpath[64] = {0};
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif

    if (!req || !exists)
    {
        return OVS_FAILED_STATUS;
    }

    snprintf(brpath, 64, "%s/%s", SYS_CLASS_NET_PATH, req->parent_bridge);
    *exists = (access(brpath, F_OK) == 0) ? true : false;
    if (!*exists)
    {
        OvsActionDebug("%s Adding a port for a non-existant bridge. Creating bridge...\n",
            __func__);
        if (ovs_enabled)
        {
        	v_secure_system("ovs-vsctl add-br %s", req->parent_bridge);
        	OvsActionDebug("%s Cmd: ovs-vsctl add-br %s\n", __func__, req->parent_bridge);
	}
        else
        {
#ifdef CORE_NET_LIB
        sts = bridge_create(req->parent_bridge);
        if (sts == CNL_STATUS_SUCCESS) {
           OvsActionDebug("%s: Added bridge %s\n", __func__, req->parent_bridge);
        }
        else {
            OvsActionError("%s: Failed to add bridge %s\n", __func__, req->parent_bridge);
        }
#else
	    v_secure_system("brctl addbr %s", req->parent_bridge);
        	OvsActionDebug("%s Cmd: brctl addbr %s\n", __func__,  req->parent_bridge);
#endif
        }
    }

    if (req->if_cmd==OVS_IF_UP_CMD || req->if_cmd==OVS_IF_DOWN_CMD)
    {
#ifdef CORE_NET_LIB
        if (req->if_cmd==OVS_IF_UP_CMD)
        {
            sts = interface_up(req->parent_bridge);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought up bridge %s\n", __func__, req->parent_bridge);
            }
            else {
                OvsActionError("%s: Failed to bring up bridge %s\n", __func__, req->parent_bridge);
            }
        }
        else
        {
            sts = interface_down(req->parent_bridge);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought down bridge %s\n", __func__, req->parent_bridge);
            }
            else {
                OvsActionError("%s: Failed to bring down bridge %s\n", __func__, req->parent_bridge);
            }
        }
#else
        OvsActionDebug("%s Cmd: ifconfig %s %s\n", __func__,req->parent_bridge,(req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
        v_secure_system("ifconfig %s %s", req->parent_bridge,(req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
#endif
    }

    if (ovs_enabled)
    {
    	v_secure_system( "ovs-vsctl add-port %s %s", req->parent_bridge,req->if_name);
    	OvsActionDebug("%s Cmd: ovs-vsctl add-port %s %s\n", __func__, req->parent_bridge,req->if_name);
    }
    else
    {
#ifdef CORE_NET_LIB
        sts = interface_add_to_bridge(req->parent_bridge, req->if_name);
        if (sts == CNL_STATUS_SUCCESS) {
           OvsActionDebug("%s: Added interface %s to bridge %s\n", __func__, req->if_name, req->parent_bridge);
        }
        else {
            OvsActionError("%s: Failed to add interface %s to bridge %s\n", __func__, req->if_name, req->parent_bridge);
        }
#else
	v_secure_system("brctl addif %s %s", req->parent_bridge, req->if_name);
    	 OvsActionDebug("%s Cmd: brctl addif %s %s\n", __func__,  req->parent_bridge, req->if_name);
#endif
    }

    if (ovs_enabled)
    {
    	OvsActionDebug("%s Cmd: ovs-vsctl list-ports %s\n", __func__, req->parent_bridge);
	fp = v_secure_popen("r","ovs-vsctl list-ports %s",req->parent_bridge);
    }
    else
    {
	OvsActionDebug("%s Cmd: ovs-vsctl list-ports %s\n", __func__, req->parent_bridge);
	fp = v_secure_popen("r","ovs-vsctl list-ports %s",req->parent_bridge);

    }
    if (!fp)
    {
        return OVS_FAILED_STATUS;
    }
    while (fgets(ports, sizeof(ports), fp) != NULL)
    {
        OvsActionDebug("existing port: %s", ports);
    }
    v_secure_pclose(fp);
    fp = NULL;

    return OVS_SUCCESS_STATUS;
}

static OVS_STATUS ovs_setup_bridge_flows(Gateway_Config * req)
{
    OVS_STATUS status = OVS_SUCCESS_STATUS;

    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    // sets up OpenFlow flows for bridge related flows
    if (!g_ovsActionConfig.oneWifiEnabled && ((g_ovsActionConfig.modelNum == OVS_CGM4331COM_MODEL) ||
        (g_ovsActionConfig.modelNum == OVS_CGA4332COM_MODEL) ||
        (g_ovsActionConfig.modelNum == OVS_CGM4981COM_MODEL) ||
        (g_ovsActionConfig.modelNum == OVS_CGM601TCOM_MODEL) ||
        (g_ovsActionConfig.modelNum == OVS_SG417DBCT_MODEL) ||
        (g_ovsActionConfig.modelNum == OVS_VTER11QEL_MODEL) ||
	(g_ovsActionConfig.modelNum == OVS_SR203_MODEL)))
    {
        if ((status = ovs_setup_brcm_wifi_flows(req)) != OVS_SUCCESS_STATUS)
        {
            OvsActionError(
                "%s failed to setup Broadcom wifi flows for Bridge %s, Port %s.\n",
                __func__, req->parent_bridge, req->if_name);
        }
    }

    return status;
}

// TODO: replace error return value 1 with right enum value
// TODO: validate the action and then do a return

static OVS_STATUS ovs_modifyParentBridge(Gateway_Config * req)
{
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    bool ovsEnabled = true;
    bool bridgeExists = false;

    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    if ((strcmp(req->parent_bridge, "brlan2") == 0) ||
        (strcmp(req->parent_bridge, "brlan3") == 0) ||
        (strcmp(req->parent_bridge, "brlan4") == 0) ||
        (strcmp(req->parent_bridge, "brlan5") == 0) ||
        (strcmp(req->parent_bridge, "brpublic") == 0) ||
        (strcmp(req->parent_bridge, "bropen6g") == 0) ||
        (strcmp(req->parent_bridge, "brsecure6g") == 0))
    {   // RDKB-36101 Setup Xfinity Wifi bridges using Linux bridge utils and not OVS
        ovsEnabled = false;
    }

    if ((status = removeExistingInterfacePort(req, ovsEnabled)) !=
        OVS_SUCCESS_STATUS)
    {
        return status;
    }

    if (req->if_cmd != OVS_BR_REMOVE_CMD) // TODO: refactor this condition check
    {
        status = configureParentBridge(req, ovsEnabled, &bridgeExists);

        if (!bridgeExists)
        {
            status = ovs_setup_bridge_flows(req);
        }
    }
    return status;
}

static OVS_STATUS ovs_setup_port_flows(Gateway_Config * req)
{
    OVS_STATUS status = OVS_SUCCESS_STATUS;

    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    if ((strcmp(req->parent_bridge, BRLAN0_ETH_NAME) == 0) &&
        (strcmp(req->if_name, LLAN0_ETH_NAME) == 0))
    {
        // sets up OpenFlow flows for brlan0's llan0 interface port
        if ((g_ovsActionConfig.modelNum == OVS_CGM4140COM_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_TG3482G_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_CGM4331COM_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_CGA4332COM_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_CGM601TCOM_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_CGM4981COM_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_SG417DBCT_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_VTER11QEL_MODEL) ||
            (g_ovsActionConfig.modelNum == OVS_TG4482A_MODEL))
        {
            if ((status = ovs_setup_admin_gui_access(req)) != OVS_SUCCESS_STATUS)
            {
                OvsActionError(
                    "%s failed to setup Admin GUI access flows for Bridge %s, Port %s.\n",
                    __func__, req->parent_bridge, req->if_name);
            }
            if ((status = ovs_block_mso_ui_access(req)) != OVS_SUCCESS_STATUS)
            {
                OvsActionError(
                    "%s failed to block MSO UI access flows for Bridge %s, Port %s.\n",
                    __func__, req->parent_bridge, req->if_name);
            }
        }
    }
    else if ((strcmp(req->parent_bridge, BR106_ETH_NAME) == 0) &&
        (strcmp(req->if_name, WL0_3_ETH_NAME) == 0))
    {
        // Workaround for br106 to add flows, due to a previous hostapd hack which
        // bypasses our OvsAgentApi on calls to add-br for br106, br112, br113
        // so OvsAgentApi is NOT being used to create and add (add-br) these
        // bridges to ovs. Therefore we have now resorted to this hack to add
        // the bridge level flows butt by basing it on one of its ports, at the
        // port level. TODO: Refactor when new api is designed which adds an array
        // of bridge ports in one api call.
        status = ovs_setup_bridge_flows(req);
    }

    return status;
}

static OVS_STATUS ovs_createBridge(Gateway_Config * req)
{
    OVS_STATUS status = OVS_SUCCESS_STATUS;
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif

    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    if (req->if_cmd == OVS_IF_DELETE_CMD)
    {
        OvsActionDebug("%s Cmd: ovs-vsctl del-br %s\n", __func__, req->if_name);
        v_secure_system("ovs-vsctl del-br %s", req->if_name);
        return OVS_SUCCESS_STATUS;
    }

    OvsActionDebug("%s Cmd: ovs-vsctl add-br %s\n", __func__,req->if_name);
    v_secure_system("ovs-vsctl add-br %s", req->if_name);

    if (strlen(req->inet_addr))
    {
#ifdef CORE_NET_LIB
        interface_set_ip(req->if_name, req->inet_addr);
        Set_Broadcast_address(req->if_name, req->netmask, req->inet_addr);
        sts = interface_set_netmask(req->if_name, req->netmask);
        if (sts == CNL_STATUS_SUCCESS) {
           OvsActionDebug("%s: Successfully set netmask %s for interface %s\n", __func__, req->netmask, req->if_name);
        }
        else {
           OvsActionError("%s: Failed to set netmask %s for interface %s\n", __func__, req->netmask, req->if_name);
        }
#else
         OvsActionDebug("%s Cmd: ifconfig %s %s netmask %s\n", __func__, req->if_name,req->inet_addr, req->netmask);
         v_secure_system("ifconfig %s %s netmask %s", req->if_name,req->inet_addr, req->netmask);
#endif
    }

    if (req->if_cmd==OVS_IF_UP_CMD || req->if_cmd==OVS_IF_DOWN_CMD)
    {
#ifdef CORE_NET_LIB
        if (req->if_cmd==OVS_IF_UP_CMD)
        {
            sts = interface_up(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought up bridge %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring up bridge %s\n", __func__, req->if_name);
            }
        }
        else
        {
            sts = interface_down(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought down bridge %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring down bridge %s\n", __func__, req->if_name);
            }
        }

#else
        OvsActionDebug("%s Cmd: ifconfig %s %s\n", __func__,  req->if_name,(req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
        v_secure_system("ifconfig %s %s", req->if_name,(req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
#endif
    }

    if (req->mtu)
    {
#ifdef CORE_NET_LIB
        char mtu[8] = {0};
        snprintf(mtu, sizeof(mtu), "%d", req->mtu);
        sts = interface_set_mtu(req->if_name, mtu);
        if (sts == CNL_STATUS_SUCCESS) {
           OvsActionDebug("%s: Successfully set MTU %d for interface %s\n", __func__, req->mtu, req->if_name);
        }
        else {
           OvsActionError("%s: Failed to set MTU %d for interface %s\n", __func__, req->mtu, req->if_name);
        }
#else
        OvsActionDebug("%s Cmd: ifconfig %s mtu %d\n", __func__, req->if_name, req->mtu);
        v_secure_system("ifconfig %s mtu %d", req->if_name, req->mtu);
#endif
    }

    // setup bridge related flows at bridge creation
    status = ovs_setup_bridge_flows(req);

    return status;
}

static OVS_STATUS ovs_createVlan(Gateway_Config * req)
{
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif

    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    if (req->if_cmd == OVS_IF_DELETE_CMD)
    {
#ifdef CORE_NET_LIB
        sts = interface_delete(req->if_name);
        if (sts == CNL_STATUS_SUCCESS) {
            OvsActionDebug("%s: Successfully deleted %s\n", __func__, req->if_name);
        }
        else {
            OvsActionError("%s: Failed to delete %s\n", __func__, req->if_name);
        }
#else
        OvsActionDebug("%s Cmd: ip link del %s \n", __func__, req->if_name);
        v_secure_system("ip link del %s", req->if_name);
#endif
        return OVS_SUCCESS_STATUS;
    }

    if (strlen(req->parent_ifname))
    {
        if (g_ovsActionConfig.modelNum == OVS_TG3482G_MODEL)
        {
            OvsActionInfo("%s Cmd: ip link add link %s %s type vlan proto 802.1Q id %d\n", __func__, req->parent_ifname, req->if_name, req->vlan_id);
            v_secure_system( "  ip link add link %s %s type vlan proto 802.1Q id %d",req->parent_ifname, req->if_name, req->vlan_id);
        }
        else
        {
#ifdef CORE_NET_LIB
            sts = vlan_create(req->parent_ifname, req->vlan_id);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Created vlan %d on interface %s\n", __func__, req->vlan_id, req->parent_ifname);
            }
            else {
                OvsActionError("%s: Failed to create vlan %d on interface %s\n", __func__, req->vlan_id, req->parent_ifname);
            }
#else
            OvsActionDebug("%s Cmd: vconfig add %s %d\n", __func__,  req->parent_ifname, req->vlan_id);
            v_secure_system("vconfig add %s %d", req->parent_ifname, req->vlan_id);
#endif
        }
    }

    if (req->if_cmd==OVS_IF_UP_CMD || req->if_cmd==OVS_IF_DOWN_CMD)
    {
#ifdef CORE_NET_LIB
        if (req->if_cmd==OVS_IF_UP_CMD)
        {
            sts = interface_up(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought up vlan %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring up vlan %s\n", __func__, req->if_name);
            }
        }
        else
        {
            sts = interface_down(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought down vlan %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring down vlan %s\n", __func__, req->if_name);
            }
        }

#else
        OvsActionDebug("%s Cmd: ifconfig %s %s\n", __func__, req->if_name,(req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
        v_secure_system("ifconfig %s %s", req->if_name,(req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
#endif
    }

    if (strlen(req->parent_bridge))
    {
        return ovs_modifyParentBridge(req);
    }
    return OVS_SUCCESS_STATUS;
}

static OVS_STATUS ovs_createGRE(Gateway_Config * req)
{
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif
    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    if (req->if_cmd == OVS_IF_DELETE_CMD)
    {
#ifdef CORE_NET_LIB
        sts = interface_delete(req->if_name);
        if (sts == CNL_STATUS_SUCCESS) {
            OvsActionDebug("%s: Successfully deleted %s\n", __func__, req->if_name);
        }
        else {
            OvsActionError("%s: Failed to delete %s\n", __func__, req->if_name);
        }
#else
        OvsActionDebug("%s Cmd: ip link del %s\n", __func__,  req->if_name);
        v_secure_system("ip link del %s", req->if_name);
#endif
        return OVS_SUCCESS_STATUS;
    }

    if (strlen(req->parent_ifname) && strlen(req->gre_local_inet_addr) &&
        strlen(req->gre_remote_inet_addr))
    {
        OvsActionDebug("%s Cmd: ip link add %s type gretap local %s remote %s dev %s tos 1\n", __func__, req->if_name, req->gre_local_inet_addr,req->gre_remote_inet_addr, req->parent_ifname);
        v_secure_system( "ip link add %s type gretap local %s remote %s dev %s tos 1",
            req->if_name, req->gre_local_inet_addr,
            req->gre_remote_inet_addr, req->parent_ifname);
    }

    if (req->if_cmd==OVS_IF_UP_CMD || req->if_cmd==OVS_IF_DOWN_CMD)
    {
#ifdef CORE_NET_LIB
        if (req->if_cmd==OVS_IF_UP_CMD)
        {
            sts = interface_up(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought up GRE %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring up GRE %s\n", __func__, req->if_name);
            }
        }
        else
        {
            sts = interface_down(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought down GRE %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring down GRE %s\n", __func__, req->if_name);
            }
        }
#else
        OvsActionDebug("%s Cmd: ifconfig %s %s\n", __func__, req->if_name, (req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
        v_secure_system("ifconfig %s %s", req->if_name,
            (req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
#endif
    }

    if (strlen(req->parent_bridge))
    {
        return ovs_modifyParentBridge(req);
    }
    return OVS_SUCCESS_STATUS;
}

static OVS_STATUS ovs_addPort(Gateway_Config * req)
{
    OVS_STATUS status = OVS_SUCCESS_STATUS;
#ifdef CORE_NET_LIB
    libnet_status sts = CNL_STATUS_SUCCESS;
#endif

    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    if (req->if_cmd == OVS_IF_DELETE_CMD)
    {
#ifdef CORE_NET_LIB
        sts = interface_delete(req->if_name);
        if (sts == CNL_STATUS_SUCCESS) {
            OvsActionDebug("%s: Successfully deleted %s\n", __func__, req->if_name);
        }
        else {
            OvsActionError("%s: Failed to delete %s\n", __func__, req->if_name);
        }
#else
        OvsActionDebug("%s Cmd: ip link del %s\n", __func__,  req->if_name);
        v_secure_system( "ip link del %s", req->if_name);
#endif
        return OVS_SUCCESS_STATUS;
    }
    else if (req->if_cmd==OVS_IF_UP_CMD || req->if_cmd==OVS_IF_DOWN_CMD)
    {
        //WAR: Special handling in case of Intel Puma7 on Arris XB6
        if ((g_ovsActionConfig.modelNum == OVS_TG3482G_MODEL) &&
            ((strcmp(req->if_name, PUMA7_ETH1_NAME) == 0) ||
                (strcmp(req->if_name, PUMA7_ETH2_NAME) == 0)) &&
            (req->if_cmd == OVS_IF_UP_CMD))
        {
            if ((status = ovs_setupEthSwitch(req->if_name)) != OVS_SUCCESS_STATUS)
            {
                return status;
            }
        }

#ifdef CORE_NET_LIB
        if (req->if_cmd==OVS_IF_UP_CMD)
        {
            sts = interface_up(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought up GRE %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring up GRE %s\n", __func__, req->if_name);
            }
        }
        else
        {
            sts = interface_down(req->if_name);
            if (sts == CNL_STATUS_SUCCESS) {
                OvsActionDebug("%s: Brought down interface %s\n", __func__, req->if_name);
            }
            else {
                OvsActionError("%s: Failed to bring down interface %s\n", __func__, req->if_name);
            }
        }
#else
        OvsActionDebug("%s Cmd: ifconfig %s %s\n", __func__,  req->if_name,(req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
        v_secure_system("ifconfig %s %s", req->if_name,
            (req->if_cmd==OVS_IF_UP_CMD ? "up" : "down"));
#endif
    }

    if (strlen(req->parent_bridge))
    {
        if ((status = ovs_modifyParentBridge(req)) != OVS_SUCCESS_STATUS)
        {
            OvsActionError("%s Error modifying Bridge %s, Port %s, Cmd %d\n",
                __func__, req->parent_bridge, req->if_name, req->if_cmd);
            return status;
        }

        status = ovs_setup_port_flows(req);
    }
    return status;
}

OVS_STATUS ovs_action_init()
{
#ifdef BCI_RESIDENTIAL_SUPPORT
    const char * model_num = "CGA4332COM";
#else
    const char * model_num = getenv(MODEL_NUM);
#endif
    if (!SetModelNum(model_num, &g_ovsActionConfig))
    {
        OvsActionError("%s failed to set Model Number property.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    const char * one_wifi_enabled = getenv(ONE_WIFI_ENABLED);
    if (!SetOneWifiEnabled(one_wifi_enabled, &g_ovsActionConfig))
    {
        OvsActionError("%s failed to set One Wifi Enabled property.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    /* Initialize Sysconfig*/
    if (SyscfgInit() != 0)
    {
        OvsActionError("%s failed to initialize syscfg.\n", __func__);
        return OVS_FAILED_STATUS;
    }

    OvsActionInfo(
        "%s successfully initialized for Model Number %d (%s), OneWifiEnabled=%d\n",
        __func__, g_ovsActionConfig.modelNum, model_num, g_ovsActionConfig.oneWifiEnabled);
    return OVS_SUCCESS_STATUS;
}

void update_openflow_priority_conf()
{
    /*RDKB-50782, update the ovs open flow priority list to add the pod tunnel interfaces at the start to avoid DHCP offers getting lost*/
    FILE *fp = NULL;
    char buff[BUFF_SIZE] ={0};
    int num_of_interfaces = 0;
    char tmp_String[TMP_STRING_SIZE]={0};
    int index=0;
    char options[200]={0};
    int ret = 0;
    unlink("/tmp/of_priority_conf.txt");
    v_secure_system("ovs-vsctl list-ifaces brlan0 |grep pgd >> /tmp/of_priority_conf.txt");
    v_secure_system("ovs-vsctl list-ifaces brlan0 |grep wl >> /tmp/of_priority_conf.txt");
    v_secure_system("ovs-vsctl list-ifaces brlan0 |grep eth >> /tmp/of_priority_conf.txt");

    fp = v_secure_popen("r","cat "OVS_PRIORITY_FILE " |wc -l");
    if( fp != NULL) {
        fgets (buff, BUFF_SIZE, fp);
        v_secure_pclose(fp);
    }
    num_of_interfaces = atoi(buff);
    if(num_of_interfaces < 1)
	    return;

    memset(options, '\0', sizeof(options));
    snprintf(options,sizeof(options),"in_port=LOCAL,dl_dst=ff:ff:ff:ff:ff:ff,dl_type=0x0800,udp,tp_src=67,tp_dst=68,actions=");
    fp = fopen(OVS_PRIORITY_FILE, "r");
    if(fp == NULL)
	    return;
    while(index < num_of_interfaces) {
        if(fp != NULL) {
            memset(tmp_String, '\0', TMP_STRING_SIZE);
            fgets(tmp_String, TMP_STRING_SIZE, fp);
            if( index != (num_of_interfaces-1))
                tmp_String[strlen(tmp_String)-1]= ',';
            else
                tmp_String[strlen(tmp_String)-1]= '\0';
            strcat(options,tmp_String);
        }
        index++;
    }
    if(fp != NULL)
        fclose(fp);

    if(num_of_interfaces)
    {
        ret = v_secure_system("/usr/bin/ovs-ofctl add-flow brlan0 %s",options);
	if(ret!=0)
	{
            OvsActionDebug("Failed in executing the command via v_secure_system ret val %d \n",ret);
	}
    }
    return;
}

OVS_STATUS ovs_action_gateway_config(Gateway_Config * req)
{
    OVS_STATUS status = OVS_SUCCESS_STATUS;
    if (!req)
    {
        return OVS_FAILED_STATUS;
    }

    switch (req->if_type)
    {
        case OVS_BRIDGE_IF_TYPE:
          OvsActionDebug("OvsAction: Bridge %s, Cmd: %d\n",
              req->if_name, req->if_cmd);
          status = ovs_createBridge(req);
          break;
        case OVS_VLAN_IF_TYPE:
          OvsActionDebug("OvsAction: VLAN %s, Cmd: %d\n",
              req->if_name, req->if_cmd);
          status = ovs_createVlan(req);
          break;
        case OVS_GRE_IF_TYPE:
          OvsActionDebug("OvsAction: GRE %s, Cmd: %d\n",
              req->if_name, req->if_cmd);
          status = ovs_createGRE(req);
          break;
        default:
          OvsActionDebug("OvsAction: If Type: %d for Port %s, Cmd: %d\n",
              req->if_type, req->if_name, req->if_cmd);
          status = ovs_addPort(req);
          break;
    }

    if ((g_ovsActionConfig.modelNum == OVS_SR203_MODEL || g_ovsActionConfig.modelNum == OVS_SR213_MODEL) && status == OVS_SUCCESS_STATUS && !strcmp(req->parent_bridge, BRLAN0_ETH_NAME))
    {
        update_openflow_priority_conf();
    }
    return status;
}

OVS_STATUS ovs_action_feedback(Feedback * req)
{
    if (!req)
    {
        return OVS_FAILED_STATUS;
    }
    return OVS_SUCCESS_STATUS;
}
