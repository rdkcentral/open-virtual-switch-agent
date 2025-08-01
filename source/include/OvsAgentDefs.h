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

#ifndef _OVSAGENT_DEFS_H_
#define _OVSAGENT_DEFS_H_

#define OVSAGENT_COMPONENT_NAME  "OvsAgent"
#define OVSAGENT_SYSCFG_NAME     "mesh_ovs_enable"

#ifndef OVSAGENT_DEBUG_ENABLE
#define OVSAGENT_DEBUG_ENABLE    "/nvram/enable_ovs_debug"
#endif

#ifndef OVSAGENT_INIT_FILE
#define OVSAGENT_INIT_FILE       "/tmp/ovsagent_initialized"
#endif

#endif
