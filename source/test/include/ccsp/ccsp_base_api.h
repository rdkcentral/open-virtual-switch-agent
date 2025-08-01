#ifndef CCSP_BASE_API_H
#define CCSP_BASE_API_H

/* Copied over from CcspCommonLibrary's cosa_base_api.h for build on
   Mac OS X platforms which don't have the dependant CcspCommonLibrary
   installed.*/

enum dataType_e
{
    ccsp_string = 0,
    ccsp_int,
    ccsp_unsignedInt,
    ccsp_boolean,
    ccsp_dateTime,
    ccsp_base64,
    ccsp_long,
    ccsp_unsignedLong,
    ccsp_float,
    ccsp_double,
    ccsp_byte,
    ccsp_none,
};

typedef struct
{
    char *parameterName;
    char *parameterValue;
    enum dataType_e type;
} parameterValStruct_t;

#endif /* CCSP_BASE_API_H */
