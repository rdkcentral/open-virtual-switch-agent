/**********************************************************************
    module: cosa_api.h

    description: Defines all the api related to dbus message.

**********************************************************************/
#ifndef _COSA_API_H
#define _COSA_API_H

#include <stdbool.h>
#include "ccsp_base_api.h"

/* Init and Exit functions */
bool Cosa_Init();
void Cosa_Shutdown();

/* Retrieve the CCSP Component name and path who supports specified name space */
bool Cosa_FindDestComp(char* pNamespace, char** ppDestComponentName,
    char** ppDestComponentPath);

/* GetParameterValues */
bool Cosa_GetParamValues(char* pDestComponentName, char* pDestComponentPath,
    char* paramArray[], int uParamSize, int* puValueSize,
    parameterValStruct_t*** pppValueArray);

/* Free Parameter Values */
void Cosa_FreeParamValues(int uSize, parameterValStruct_t** ppValueArray);

#endif /* COSA_API_H */

