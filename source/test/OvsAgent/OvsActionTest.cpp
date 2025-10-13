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
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "test/mocks/mock_utils.h"
#include "test/mocks/mock_file_io.h"
#include "test/mocks/mock_syscfg.h"
#include "test/mocks/mock_cosa_api.h"

extern "C" {
#include "OvsAction/ovs_action.h"
#include "common/OvsAgentLog.h"
#include "OvsAction/syscfg.h"
}

using ::testing::_;
using ::testing::Return;
using ::testing::StrEq;

UtilsMock * g_utilsMock = NULL;  /* This is the actual definition of the mock obj */
FileIOMock * g_fileIOMock = NULL;
SyscfgMock * g_syscfgMock = NULL;
CosaMock * g_cosaMock = NULL;

class OvsActionTestFixture : public ::testing::Test {
    protected:
        UtilsMock mockedUtils;
        FileIOMock mockedFileIO;
        SyscfgMock mockedSyscfg;
        CosaMock mockedCosa;
        char expOneWifiEnabledProperty[8] = "false";

        OvsActionTestFixture()
        {
            g_utilsMock = &mockedUtils;
            g_fileIOMock = &mockedFileIO;
            g_syscfgMock = &mockedSyscfg;
            g_cosaMock = &mockedCosa;

            EXPECT_CALL(*g_utilsMock, getenv(StrEq(ONE_WIFI_ENABLED)))
                .Times(1)
                .WillOnce(Return(expOneWifiEnabledProperty));
        }
        virtual ~OvsActionTestFixture()
        {
            g_utilsMock = NULL;
            g_fileIOMock = NULL;
            g_syscfgMock = NULL;
            g_cosaMock = NULL;
        }

        virtual void SetUp()
        {
            OvsActionInfo("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        virtual void TearDown()
        {
            OvsActionInfo("%s %s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_info()->test_case_name(),
                ::testing::UnitTest::GetInstance()->current_test_info()->name());
        }

        static void SetUpTestCase()
        {
            OvsActionInfo("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
        }

        static void TearDownTestCase()
        {
            OvsActionInfo("%s %s\n", __func__,
                ::testing::UnitTest::GetInstance()->current_test_case()->name());
        }
};

ACTION_TEMPLATE(SetArgNPointeeTo, HAS_1_TEMPLATE_PARAMS(unsigned, uIndex), AND_2_VALUE_PARAMS(pData, uiDataSize))
{
    memcpy(std::get<uIndex>(args), pData, uiDataSize);
}

class GatewayConfigTest :
    public OvsActionTestFixture,
    public ::testing::WithParamInterface<Gateway_Config>
{
    public:
        GatewayConfigTest()
        {
            OvsActionInfo("%s if_name: %s, inet_addr: %s, netmask: %s, parent_ifname: %s, parent_bridge: %s, mtu: %d, vlan_id: %d, if_type: %d, if_cmd: %d\n",
                __func__, GetParam().if_name, GetParam().inet_addr,
                GetParam().netmask, GetParam().parent_ifname,
                GetParam().parent_bridge, GetParam().mtu, GetParam().vlan_id,
                GetParam().if_type, GetParam().if_cmd);
        }
};

TEST(OvsAction, ovs_action_gateway_config_null)
{
    ASSERT_EQ(OVS_FAILED_STATUS, ovs_action_gateway_config(NULL));
}

TEST_F(OvsActionTestFixture, ovs_action_add_bridge_up_valid)
{
    const OVS_IF_TYPE ifType = OVS_BRIDGE_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string bridge = "brlan0";
    const std::string ip = "10.0.0.1";
    const std::string netmask = "255.255.255.0";
    const std::string mtu = "1500";
    char expectedModel[] = "CGM4140COM";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ovs-vsctl add-br " + bridge);
    expectedCmds.push_back("ifconfig " + bridge + " " + ip + " netmask " + netmask);
    expectedCmds.push_back("ifconfig " + bridge + " up");
    expectedCmds.push_back("ifconfig " + bridge + " mtu " + mtu);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(bridge.c_str()));
    strcpy(cfg.inet_addr,  const_cast<char *>(ip.c_str()));
    strcpy(cfg.netmask, const_cast<char *>(netmask.c_str()));
    cfg.mtu = atoi(mtu.c_str());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

// RDKB-41589
// test case: add port to a parent bridge that does not exist
TEST_F(OvsActionTestFixture, ovs_action_add_vlan_up_valid)
{
    const OVS_IF_TYPE ifType = OVS_VLAN_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string parentIfName = "pgd0-91";
    const std::string ifName = "pgd0-91.200";
    const std::string vlanId = "200";
    const std::string parentBridge = "dummy";
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " + ifName;
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;
    //char expectedParentBridge[] = "dummy\n";
    char expectedBridgePorts[] = "pgd0-91.200\n";
    FILE * expectedFd1 = (FILE *)0xffffffff;
    FILE * expectedFd2 = (FILE *)0xfffffffe;
    char expectedModel[] = "CGM4140COM";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("vconfig add " + parentIfName + " " + vlanId);
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ovs-vsctl add-br " + parentBridge);
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.parent_ifname, const_cast<char *>(parentIfName.c_str()));
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    cfg.vlan_id = atoi(vlanId.c_str());
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(1)
        /*.WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        )) // Set .Times(2) and uncomment to add port to an existing bridge */
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

// RDKB-36101
TEST_P(GatewayConfigTest, ovs_action_setup_linux_bridge_valid)
{
    Gateway_Config cfg = GetParam();

    const OVS_IF_TYPE ifType = cfg.if_type;
    const OVS_CMD     ifCmd = cfg.if_cmd;
    const std::string parentIfName = cfg.parent_ifname;
    const std::string ifName = cfg.if_name;
    const int vlanId = cfg.vlan_id;
    const std::string parentBridge = GetParam().parent_bridge;

    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const std::string expectedIfPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        ifName + LINUX_BRPORT_POSTFIX_PATH;
    const std::string expectedParentBridgeCmd = "cat " + expectedIfPath;
    const std::string expectedBridgePortsCmd = "brctl show " + std::string(parentBridge);
    char expectedParentBridge[32] = {0};
    char expectedBridgePorts[64] = {0};
    FILE * expectedFd1 = (FILE *)0xffffffff;
    FILE * expectedFd2 = (FILE *)0xfffffffe;
    char expectedModel[] = "CGM4140COM";

    snprintf(expectedParentBridge, sizeof(expectedParentBridge), "%s%s\n",
        LINUX_INTERFACE_PREFIX, parentBridge.c_str());
    snprintf(expectedBridgePorts, sizeof(expectedBridgePorts), "%s %s %s %s\n",
        parentBridge.c_str(), "8000.002686027664", "no", ifName.c_str());

    std::vector<std::string> expectedCmds;
    if (parentIfName.length())
    {
        expectedCmds.push_back("vconfig add " + parentIfName + " " +
            std::to_string(vlanId));
    }
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("brctl addbr " + parentBridge);
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("brctl addif " + parentBridge + " " + ifName);

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ));
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedIfPath), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

INSTANTIATE_TEST_SUITE_P(GatewayConfigTestSuite, GatewayConfigTest,
    ::testing::Values(
        Gateway_Config{"gretap0.102", "", "", "", "", "gretap0", "brlan2", 1500, 102, OVS_VLAN_IF_TYPE, OVS_IF_UP_CMD},
        Gateway_Config{"ath4", "", "", "", "", "", "brlan2", 1500, 0, OVS_OTHER_IF_TYPE, OVS_IF_UP_CMD}));

TEST_F(OvsActionTestFixture, ovs_action_add_gre_up_valid)
{
    const OVS_IF_TYPE ifType = OVS_GRE_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string parentIfName = "brlan0";
    const std::string ifName = "wifi0";
    const std::string greLocalIP = "10.0.0.1";
    const std::string greRemoteIP = "175.5.5.5";
    //const std::string parentBridge = "brlan0"; // TODO: Add Parent Bridge tests
    char expectedModel[] = "CGM4140COM";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ip link add " + ifName + " type gretap local " + greLocalIP +
        " remote " + greRemoteIP + " dev " + parentIfName + " tos 1");
    expectedCmds.push_back("ifconfig " + ifName + " up");
    //expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.parent_ifname, const_cast<char *>(parentIfName.c_str()));
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.gre_local_inet_addr, const_cast<char *>(greLocalIP.c_str()));
    strcpy(cfg.gre_remote_inet_addr, const_cast<char *>(greRemoteIP.c_str()));
    //strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

TEST_F(OvsActionTestFixture, ovs_action_ethernet_up_valid)
{
    const OVS_IF_TYPE ifType = OVS_ETH_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    //const std::string parentIfName = "brport";
    const std::string ifName = "wifi0";
    //const std::string parentBridge = "brlan0"; // TODO: Add Parent Bridge tests
    char expectedModel[] = "CGM4140COM";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ifconfig " + ifName + " up");
    //expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    //strcpy(cfg.parent_ifname, const_cast<char *>(parentIfName.c_str()));
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    //strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

TEST_F(OvsActionTestFixture, ovs_action_add_port_to_bridge_valid)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string ifName = "ath0";
    const std::string parentBridge = "brlan0";
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " + ifName;
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;
    char expectedParentBridge[] = "brlan0\n";
    char expectedBridgePorts[] = "ath0\n";
    FILE * expectedFd1 = (FILE *)0xffffffff;
    FILE * expectedFd2 = (FILE *)0xfffffffe;
    char expectedModel[] = "TG3482G";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ovs-vsctl add-br " + parentBridge);
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

class ModelNumBasedTestFixture :
    public OvsActionTestFixture,
    public ::testing::WithParamInterface<char *>
{
};

ACTION_P(SetCosaGetParamValuesArg4, value)
{
    *static_cast<int*>(arg4) = value;
}

ACTION_P(SetCosaGetParamValuesArg5, value)
{
    *static_cast<parameterValStruct_t***>(arg5) = *value;
}

// Fix for TCXB6-9125, ARRISXB6-12373, TCXB6-9721, TCXB7-4051, TCXB8-473
TEST_P(ModelNumBasedTestFixture, ovs_action_add_http_llan0_port_in_bridge_mode)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string ifName = "llan0";
    const std::string parentBridge = "brlan0";
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const char expectedIP[] = "10.0.0.1";
    char expectedCMIP[] = "2001:558:4000:a0:82d0:4aff:fed1:faad";
    char expectedParamName[] = "Device.DeviceInfo.X_COMCAST-COM_CM_IP";
    char expectedDestComponentName[] = "eRT.com.cisco.spvtg.ccsp.pam";
    char expectedDestComponentPath[] = "/com/cisco/spvtg/ccsp/pam";
    FILE * expectedFd1 = (FILE *)0xffffffff;
    FILE * expectedFd2 = (FILE *)0xfffffffe;
    FILE * expectedFd3 = (FILE *)0xfffffffd;
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " + ifName;
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;
    const std::string expectedMacAddressCmd = "cat /sys/class/net/lan0/address";
    char expectedParentBridge[] = "brlan0\n";
    char expectedBridgePorts[] = "llan0\n";
    char expectedMacAddress[] = "12:34:56:78:90:AB";
    char * expectedModel = GetParam();
    const int expectedParamSize = 1;

    parameterValStruct_t **pExpectedParamValues = new parameterValStruct_t*[expectedParamSize];
    pExpectedParamValues[0] = new parameterValStruct_t;
    pExpectedParamValues[0]->parameterName = expectedParamName;
    pExpectedParamValues[0]->parameterValue = &expectedCMIP[0];

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);
    expectedCmds.push_back("ovs-ofctl --strict del-flows " + parentBridge + " arp,nw_dst=" + expectedIP + "/32");
    expectedCmds.push_back("ovs-ofctl --strict del-flows " + parentBridge + " ip,nw_dst=" + expectedIP + "/32");
    expectedCmds.push_back("ovs-ofctl add-flow " + parentBridge + " arp,nw_dst=" +
        expectedIP  + "/32,actions=mod_dl_dst:" + expectedMacAddress + ",output:" + ifName);
    expectedCmds.push_back("ovs-ofctl add-flow " + parentBridge + " ip,nw_dst=" +
        expectedIP  + "/32,actions=mod_dl_dst:" + expectedMacAddress + ",output:" + ifName);
    expectedCmds.push_back("ovs-ofctl --strict del-flows " + parentBridge +
        " ipv6,ipv6_dst=" + expectedCMIP + "/128");
    expectedCmds.push_back("ovs-ofctl add-flow " + parentBridge + " ipv6,ipv6_dst=" +
        expectedCMIP  + "/128,actions=drop");

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedMacAddressCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd3));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd3))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd3))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedMacAddress), sizeof(expectedMacAddress)),
            ::testing::Return(expectedMacAddress)
        ));

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    // Parent bridge already exists
    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));
    EXPECT_CALL(*g_syscfgMock, SyscfgGet(StrEq(LAN0_IP_ADDR_SYSCFG_PARAM_NAME), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<1>(std::begin(expectedIP), sizeof(expectedIP)),
            ::testing::Return(0)
        ));

    EXPECT_CALL(*g_cosaMock, Cosa_FindDestComp(StrEq(expectedParamName), _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            ::testing::SetArgPointee<1>(expectedDestComponentName),
            ::testing::SetArgPointee<2>(expectedDestComponentPath),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_cosaMock, Cosa_GetParamValues(_, _, _, _, _, _))
        .Times(1)
        .WillOnce(::testing::DoAll(
            SetCosaGetParamValuesArg4(expectedParamSize),
            SetCosaGetParamValuesArg5(&pExpectedParamValues),
            ::testing::Return(true)
        ));
    EXPECT_CALL(*g_cosaMock, Cosa_FreeParamValues(_, _))
        .Times(1)
        .WillOnce(Return());

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));

    delete pExpectedParamValues[0];
    delete[] pExpectedParamValues;
}

INSTANTIATE_TEST_SUITE_P(PlatformSpecificOvsActionTests, ModelNumBasedTestFixture,
    ::testing::Values((char*)"CGM4140COM", (char*)"TG3482G",
                      (char*)"CGM4331COM", (char*)"CGM4981COM", (char*)"CGM601TCOM", (char*)"CWA438TCOM", (char*)"SG417DBCT"));

// RDKB-35124 and RDKB-42700
// parent - br1
// existing - br2
// cmd - if up
// Action: Run del-port and add-port cmd
TEST_F(OvsActionTestFixture, ovs_action_remove_and_port_different_bridge_valid)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string ifName = "sw_2";
    const std::string parentBridge = "br1";
    char expectedParentBridge[] = "br0\n";
    char expectedBridgePorts[] = "sw_2\n";
    FILE * expectedFd1 = (FILE *)0xffffffff;
    FILE * expectedFd2 = (FILE *)0xfffffffe;
    char expectedModel[] = "TG4482A";
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " + ifName;
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ovs-vsctl del-port br0 " + ifName);
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ovs-vsctl add-br " + parentBridge);
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

// RDKB-35124
// parent - br1
// existing - br1
// cmd - br remove
// Action: Run del-port cmd
TEST_F(OvsActionTestFixture, ovs_action_remove_port_from_bridge_valid)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_BR_REMOVE_CMD;
    const std::string ifName = "ath0";
    const std::string parentBridge = "brlan0";
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " + ifName;
    char expectedParentBridge[] = "brlan0\n";
    FILE * expectedFd = (FILE *)0xffffffff;
    char expectedModel[] = "TG3482G";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ovs-vsctl del-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

// ARRISXB6-12247
// This interface nsgmi1.100, other interface nsgmii1.101, associated
// interface ethsw123 and parent bridge brlan0 don't exist prior.
// Adds nsgmii100 to brlan0.
TEST_F(OvsActionTestFixture, ovs_action_setup_eth_switch_port1_axb6)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string ifName = PUMA7_ETH1_NAME;
    const std::string parentBridge = "brlan0";
    const std::string vlan = "100";
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const char expectedIP[] = "10.0.0.1";
    FILE * expectedFd1 = (FILE *)0xffffffff;
    FILE * expectedFd2 = (FILE *)0xfffffffe;
    FILE * expectedFd3 = (FILE *)0xfffffffd;
    const std::string expectedIfPath = PUMA7_ETH1_PATH;
    const std::string expectedOtherIfPath = PUMA7_ETH2_PATH;
    const std::string expectedParentBridgeCmd =
        std::string("ovs-vsctl iface-to-br ") + std::string(PUMA7_ETH1_NAME);
    const std::string expectedOtherParentBridgeCmd =
        std::string("ovs-vsctl iface-to-br ") + std::string(PUMA7_ETH2_NAME);
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;
    char expectedParentBridge[] = "brlan0\n";
    char expectedBridgePorts[] = "nsgmii1.100\n";
    char expectedModel[] = "TG3482G";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("/bin/vlan_util add_group dummy" + vlan + " " + vlan);
    expectedCmds.push_back("/bin/vlan_util add_interface dummy" + vlan +
        " " + PUMA7_PORT1_NAME);
    expectedCmds.push_back("/bin/vlan_util add_interface dummy" + vlan +
        " " + PUMA7_PORT2_NAME);
    expectedCmds.push_back("brctl delif dummy" + vlan + " " + ifName);
    expectedCmds.push_back("ifconfig dummy" + vlan + " down; brctl delbr dummy" + vlan);
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ovs-vsctl add-br " + parentBridge);
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedOtherParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd3));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd3))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(1)
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd3))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, access(StrEq(ETH_BHAUL_IF_PATH), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedIfPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedOtherIfPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

// ARRISXB6-12678
// This interface nsgmi1.101, other interface nsgmii1.100, associated
// interface ethsw123 and parent bridge brlan1 don't exist prior.
TEST_F(OvsActionTestFixture, ovs_action_setup_eth_switch_port2_axb6)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string ifName = PUMA7_ETH2_NAME;
    const std::string parentBridge = "brlan1";
    const std::string vlan = "101";
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const char expectedIP[] = "172.16.12.1";
    FILE * expectedFd0 = (FILE *)0xffffffff;
    FILE * expectedFd1 = (FILE *)0xfffffffe;
    FILE * expectedFd2 = (FILE *)0xfffffffd;
    const std::string expectedIfPath = PUMA7_ETH2_PATH;
    const std::string expectedOtherIfPath = PUMA7_ETH1_PATH;
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " +
        std::string(PUMA7_ETH2_NAME);
    const std::string expectedOtherBridgeCmd = "ovs-vsctl iface-to-br " +
        std::string(PUMA7_ETH1_NAME);
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;
    char expectedParentBridge[] = "brlan1\n";
    char expectedBridgePorts[] = "nsgmii1.101\n";
    char expectedModel[] = "TG3482G";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("/bin/vlan_util add_group dummy" + vlan + " " + vlan);
    expectedCmds.push_back("/bin/vlan_util add_interface dummy" + vlan +
        " " + PUMA7_PORT2_NAME);
    expectedCmds.push_back("brctl delif dummy" + vlan + " " + ifName);
    expectedCmds.push_back("ifconfig dummy" + vlan + " down; brctl delbr dummy" + vlan);
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ovs-vsctl add-br " + parentBridge);
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd0));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedOtherBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd0))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd0))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(1)
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, access(StrEq(ETH_BHAUL_IF_PATH), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedIfPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedOtherIfPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

// ARRISXB6-12678
// This interface nsgmi1.101 and interface ethsw123 don't exist prior.
// Other interface nsgmii1.100 DOES exist prior and it belongs to brlan0.
// Covers case where nsgmii1.100 is already part of brlan0 and then a
// request is made to add nsgmmii1.101 to brlan1.
TEST_F(OvsActionTestFixture, ovs_action_setup_eth_switch_xhs_port2_axb6)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string ifName = PUMA7_ETH2_NAME;
    const std::string parentBridge = "brlan1";
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    const char expectedIP[] = "172.16.12.1";
    FILE * expectedFd0 = (FILE *)0xffffffff;
    FILE * expectedFd1 = (FILE *)0xfffffffe;
    FILE * expectedFd2 = (FILE *)0xfffffffd;
    const std::string expectedOtherIfPath = PUMA7_ETH1_PATH;
    const std::string expectedIfPath = PUMA7_ETH2_PATH;
    const std::string expectedBrlan0BridgeCmd = "ovs-vsctl iface-to-br " + std::string(PUMA7_ETH1_NAME);
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " + ifName;
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;
    char expectedBrlan0Bridge[] = "brlan0\n";
    char expectedParentBridge[] = "brlan1\n";
    char expectedBridgePorts[] = "nsgmii1.101\n";
    char expectedModel[] = "TG3482G";

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ovs-vsctl del-port brlan0 " + std::string(PUMA7_ETH1_NAME));
    expectedCmds.push_back("/bin/vlan_util add_group dummy100 100");
    expectedCmds.push_back("/bin/vlan_util add_group dummy101 101");
    expectedCmds.push_back("/bin/vlan_util add_interface dummy100 " + std::string(PUMA7_PORT1_NAME));
    expectedCmds.push_back("/bin/vlan_util add_interface dummy101 " + std::string(PUMA7_PORT2_NAME));
    expectedCmds.push_back("brctl delif dummy100 " + std::string(PUMA7_ETH1_NAME));
    expectedCmds.push_back("brctl delif dummy101 " + ifName);
    expectedCmds.push_back("ifconfig dummy100 down; brctl delbr dummy100");
    expectedCmds.push_back("ifconfig dummy101 down; brctl delbr dummy101");
    expectedCmds.push_back("ovs-vsctl add-port brlan0 " + std::string(PUMA7_ETH1_NAME));
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ovs-vsctl add-br " + parentBridge);
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBrlan0BridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd0));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(2)
       .WillRepeatedly(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd0))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(2)
       .WillRepeatedly(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd0))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBrlan0Bridge), sizeof(expectedBrlan0Bridge)),
            ::testing::Return((char*)expectedBrlan0Bridge)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(2)
        .WillRepeatedly(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    EXPECT_CALL(*g_utilsMock, access(StrEq(ETH_BHAUL_IF_PATH), _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(-1));
    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedOtherIfPath), _))
        .Times(2)
        .WillRepeatedly(Return(0));
    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedIfPath), _))
        .Times(1)
        .WillOnce(Return(-1));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}

TEST_P(ModelNumBasedTestFixture, ovs_action_add_brcm_wifi_flows_test)
{
    const OVS_IF_TYPE ifType = OVS_OTHER_IF_TYPE;
    const OVS_CMD     ifCmd = OVS_IF_UP_CMD;
    const std::string ifName = WL0_3_ETH_NAME;
    const std::string parentBridge = BR106_ETH_NAME;
    const std::string expectedBrPath = std::string(SYS_CLASS_NET_PATH) + "/" +
        parentBridge;
    FILE * expectedFd1 = (FILE *)0xffffffff;
    FILE * expectedFd2 = (FILE *)0xfffffffe;
    const std::string expectedParentBridgeCmd = "ovs-vsctl iface-to-br " + ifName;
    const std::string expectedBridgePortsCmd = "ovs-vsctl list-ports " + parentBridge;
    char expectedParentBridge[] = "br106\n";
    char expectedBridgePorts[] = "wl0.3\n";
    char * expectedModel = GetParam();
    const unsigned int eth_types[] =
        {ETHER_TYPE_BRCM, ETHER_TYPE_BRCM_AIRIQ, ETHER_TYPE_802_1X};

    std::vector<std::string> expectedCmds;
    expectedCmds.push_back("ifconfig " + ifName + " up");
    expectedCmds.push_back("ifconfig " + parentBridge + " up");
    expectedCmds.push_back("ovs-vsctl add-port " + parentBridge + " " + ifName);

    if ((strcmp(expectedModel, "CGM4331COM") == 0) ||
        (strcmp(expectedModel, "CGM601TCOM") == 0) ||
        (strcmp(expectedModel, "CWA438TCOM") == 0) ||
        (strcmp(expectedModel, "SG417DBCT") == 0) ||
        (strcmp(expectedModel, "CGM4981COM") == 0))
    {
        for (int idx = 0; idx < sizeof(eth_types)/sizeof(eth_types[0]); idx++)
        {
            std::stringstream ethType;
            ethType << std::hex << eth_types[idx];
            expectedCmds.push_back("ovs-ofctl --strict del-flows " + parentBridge +
                " \"dl_type=0x" + ethType.str() + ", actions=" + parentBridge + "\"");
            expectedCmds.push_back("ovs-ofctl add-flow " + parentBridge +
                " \"dl_type=0x" + ethType.str() + ", actions=" + parentBridge + "\"");
        }
    }

    Gateway_Config cfg = {0};
    cfg.if_type = ifType;
    cfg.if_cmd = ifCmd;
    strcpy(cfg.if_name, const_cast<char *>(ifName.c_str()));
    strcpy(cfg.parent_bridge, const_cast<char *>(parentBridge.c_str()));

    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedParentBridgeCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd1));
    EXPECT_CALL(*g_fileIOMock, popen(StrEq(expectedBridgePortsCmd), StrEq("r")))
       .Times(1)
       .WillOnce(::testing::Return(expectedFd2));

    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd1))
       .Times(1)
       .WillOnce(::testing::Return(0));
    EXPECT_CALL(*g_fileIOMock, pclose(expectedFd2))
       .Times(1)
       .WillOnce(::testing::Return(0));

    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd1))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedParentBridge), sizeof(expectedParentBridge)),
            ::testing::Return((char*)expectedParentBridge)
        ))
        .WillOnce(::testing::ReturnNull());
    EXPECT_CALL(*g_fileIOMock, fgets(_, _, expectedFd2))
        .Times(2)
        .WillOnce(::testing::DoAll(
            SetArgNPointeeTo<0>(std::begin(expectedBridgePorts), sizeof(expectedBridgePorts)),
            ::testing::Return((char*)expectedBridgePorts)
        ))
        .WillOnce(::testing::ReturnNull());

    EXPECT_CALL(*g_utilsMock, system(_))
        .Times(0);
    for (size_t idx=0; idx<expectedCmds.size(); idx++)
    {
        //std::cout << "Expected " << expectedCmds.at(idx) << std::endl;
        EXPECT_CALL(*g_utilsMock, system(StrEq(expectedCmds.at(idx))))
            .Times(1)
            .WillOnce(Return(1));
    }

    // On TCHXB7/8 only, if bridge doesn't exist, also create the wifi related
    // ether_type ovs flow rules to send those packets to the bridge only. But
    // lnf is a special case, since br106, brlan112, brlan113 are created else-
    // where and not via the OvsAgentApi.
    EXPECT_CALL(*g_utilsMock, access(StrEq(expectedBrPath), _))
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_CALL(*g_utilsMock, getenv(StrEq(MODEL_NUM)))
        .Times(1)
        .WillOnce(Return(expectedModel));

    EXPECT_CALL(*g_syscfgMock, SyscfgInit())
        .Times(1)
        .WillOnce(Return(0));

    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_init());
    EXPECT_EQ(OVS_SUCCESS_STATUS, ovs_action_gateway_config(&cfg));
}
