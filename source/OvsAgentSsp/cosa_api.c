#include <stdlib.h>
#include "ansc_platform.h"
#include "OvsAgentSsp/cosa_api.h"
#include "common/OvsAgentLog.h"
#include "safec_lib_common.h"

/* Cosa specific stuff */
#define CCSP_OVS_AGENT_SUBSYSTEM "eRT."
#define COMPONENT_NAME           "ccsp.cisco.spvtg.ccsp.ovsagent"
#define CONF_FILENAME            "/tmp/ccsp_msg.cfg"

static void * bus_handle = NULL;

/* Init COSA */
bool Cosa_Init(void)
{
    errno_t rc =-1;
    char dst_pathname_cr[64] = {0};

    /*
     *  Hardcoding "eRT." is just a workaround. We need to feed the subsystem
     *  info into this initialization routine.
     */
    rc = sprintf_s(dst_pathname_cr, sizeof(dst_pathname_cr), "%s%s",
            CCSP_OVS_AGENT_SUBSYSTEM, CCSP_DBUS_INTERFACE_CR);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        return false;
    }
    if(!bus_handle)
    {
        if (CCSP_Message_Bus_Init(COMPONENT_NAME, CONF_FILENAME, &bus_handle,
            malloc, free) != 0)
        {
            OvsAgentSspError("%s: CCSP_Message_Bus_Init error\n", __func__);
            return false;
        }
    }
    return true;
}

/* Exit COSA */
void Cosa_Shutdown(void)
{
    if (bus_handle)
    {
        CCSP_Message_Bus_Exit(bus_handle);
        bus_handle = NULL;
    }
}

/* Retrieve the CCSP Component name and path who supports specified name space */
bool Cosa_FindDestComp(char* pObjName, char** ppDestComponentName,
    char** ppDestComponentPath)
{
    int ret;
    int size = 0;
    componentStruct_t** ppComponents = NULL;
    errno_t rc =-1;
    char dst_pathname_cr[64] = {0};

    if (!bus_handle || !pObjName)
    {
        return false;
    }

    rc = sprintf_s(dst_pathname_cr, sizeof(dst_pathname_cr), "%s%s",
            CCSP_OVS_AGENT_SUBSYSTEM, CCSP_DBUS_INTERFACE_CR);
    if (rc < EOK)
    {
        ERR_CHK(rc);
        return false;
    }

    ret = CcspBaseIf_discComponentSupportingNamespace(bus_handle,
        dst_pathname_cr,
        pObjName,
        "", /* prefix */
        &ppComponents,
        &size);
    if (ret == CCSP_SUCCESS && size >= 1)
    {
        *ppDestComponentName = AnscCloneString(ppComponents[0]->componentName);
        *ppDestComponentPath = AnscCloneString(ppComponents[0]->dbusPath);
        free_componentStruct_t(bus_handle, size, ppComponents);
        return true;
    }

    OvsAgentSspError("%s: Failed to find Dest CCSP Component for '%s', status %d!\n",
        __func__, pObjName, ret);
    return false;
}

/* GetParameterValues */
bool Cosa_GetParamValues(char* pDestComponentName, char* pDestComponentPath,
    char** pParamArray, int uParamSize, int* puValueSize,
    parameterValStruct_t*** pppValueArray)
{
    int status = ANSC_STATUS_FAILURE;

    if (!bus_handle || !pDestComponentName || !pDestComponentPath || !puValueSize)
    {
        OvsAgentSspError("%s: Failed to get param value due to NULL param!\n",
            __func__);
        return false;
    }

    status = CcspBaseIf_getParameterValues(bus_handle,
        pDestComponentName,
        pDestComponentPath,
        pParamArray,
        uParamSize,
        puValueSize,
        pppValueArray);
    if (status != CCSP_SUCCESS && *pParamArray)
    {
        OvsAgentSspError("%s: Failed to get param '%s' with status %d!\n",
            __func__, *pParamArray, status);
        return false;
    }

    OvsAgentSspDebug("%s: GET Param '%s' success\n", __func__, *pParamArray);
    return true;
}

/* Free Parameter Values */
void Cosa_FreeParamValues(int uSize, parameterValStruct_t** ppValueArray)
{
    if (bus_handle)
    {
        free_parameterValStruct_t(bus_handle, uSize, ppValueArray);
    }
}

