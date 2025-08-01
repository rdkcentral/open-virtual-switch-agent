#!/bin/sh
#
# Copyright 2020 Comcast Cable Communications Management, LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
#


OPENSYNC_ENABLE="`syscfg get opensync`"
OPENSYNC_ENABLE_LEGACY="`syscfg get opensync_enable`"
OPENSYNC_44_ENABLE="`syscfg get opensync_44`"
OPENSYNC_SCRIPTS_PATH=/usr/opensync/scripts
if [ "$OPENSYNC_44_ENABLE" == "true" ]
 then
    echo "OPENSYNC_44_ENABLE is true"
    OPENSYNC_SCRIPTS_PATH=/usr/opensync_44/scripts
fi
if [ "$OPENSYNC_ENABLE" != "true" ] && [ "$OPENSYNC_ENABLE_LEGACY" == "true" ]; then
    OPENSYNC_ENABLE="true"
    syscfg set "opensync" "true"
    syscfg commit
fi
if [ $# -eq 0 ]; then
 echo "No arguments passed"
 exit 0
else
 if [ "$OPENSYNC_ENABLE" == "true" ] || [ "$OneWiFiEnabled" == "true" ] ||
                                        [ -f /etc/WFO_enabled ];then
  $OPENSYNC_SCRIPTS_PATH/managers.init $@
 else
  /usr/plume/scripts/managers.init $@
 fi
fi
