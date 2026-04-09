# Open Virtual Switch Agent

Open Virtual Switch Agent (OvsAgent) is the RDK-B component responsible for translating network bridge configuration requests stored in the Open vSwitch Database (OVSDB) into actual Linux networking operations on the gateway. The component connects to the OVSDB server over a Unix domain socket, monitors the `Gateway_Config` table for incoming configuration commands, and executes the corresponding bridge and port management operations using either Open vSwitch (`ovs-vsctl`) commands or Linux bridge utilities (`brctl`/`ifconfig`) depending on bridge type. After executing each operation, OvsAgent writes the result status back to the OVSDB `Feedback` table so that requesting components can confirm success or failure.

OvsAgent serves as the southbound executor for virtual networking configuration on RDK-B platforms. Components such as BridgeUtils and MeshAgent submit configuration requests to OVSDB; OvsAgent picks them up, applies them to the Linux kernel networking layer, and reports back. This decoupling allows other middleware components to interact with the virtual switch through a well-defined database interface without needing direct knowledge of the underlying networking commands or platform-specific details.

```mermaid
graph LR
    subgraph ExternalSystems ["External Systems"]
        MeshCtrl["Mesh Controller\n(Remote)"]
    end

    subgraph RDKBMiddleware ["RDK-B Middleware (Linux Process)"]
        BridgeUtils["BridgeUtils\nComponent"]
        MeshAgent["MeshAgent\nComponent"]
        OvsAgent["OvsAgent\n(This Component)"]
        OvsDbServer["OVSDB Server\n(ovsdb-server)"]
        CcspPsm["CcspPsm\n(PSM)"]
        CcspCR["Component Registry"]
    end

    subgraph SystemLayer ["System & Platform Layer"]
        OvsTools["ovs-vsctl\novs-ofctl"]
        LinuxNet["Linux Bridge\nbrctl / ifconfig"]
        Syscfg["syscfg\n(NVRAM Store)"]
        DeviceProps["/etc/device.properties"]
    end

    MeshCtrl -->|"Remote Mgmt"| MeshAgent
    BridgeUtils -->|"Unix Socket\nJSON-RPC"| OvsDbServer
    MeshAgent -->|"Unix Socket\nJSON-RPC"| OvsDbServer
    OvsAgent -->|"Unix Socket /var/run/openvswitch/db.sock\nJSON-RPC OVSDB Protocol"| OvsDbServer
    OvsAgent -->|"R-BUS"| CcspCR
    OvsAgent -->|"Reads /tmp/psm_initialized"| CcspPsm
    OvsAgent -->|"syscfg_get\nmesh_ovs_enable, lan_ipaddr"| Syscfg
    OvsAgent -->|"getenv MODEL_NUM\nOneWiFiEnabled"| DeviceProps
    OvsAgent -->|"v_secure_system"| OvsTools
    OvsAgent -->|"v_secure_system\n(non-OVS bridges)"| LinuxNet

    classDef external fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px;
    classDef component fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
    classDef system fill:#fff3e0,stroke:#ef6c00,stroke-width:2px;
    classDef thisComp fill:#fce4ec,stroke:#c62828,stroke-width:2px;

    class MeshCtrl external;
    class BridgeUtils,MeshAgent,OvsDbServer,CcspPsm,CcspCR component;
    class OvsTools,LinuxNet,Syscfg,DeviceProps system;
    class OvsAgent thisComp;
```

**Key Features & Responsibilities**:

- **OVSDB Gateway Config Monitoring**: Connects to the OVSDB server via Unix domain socket at `/var/run/openvswitch/db.sock` and monitors the `Gateway_Config` table for incoming network interface and bridge configuration requests from other RDK-B components.
- **Bridge and Port Management**: Translates `Gateway_Config` records into actual Linux networking commands — creating or removing OVS bridges with `ovs-vsctl`, adding or removing ports, bringing interfaces up or down, and configuring VLAN and GRE interfaces.
- **Dual-mode Networking Backend**: Selects between OVS-managed (`ovs-vsctl`) and Linux-native (`brctl`/`ifconfig`) bridge operations at runtime based on the bridge name. To meet Xfinity WiFi requirements, specific bridges (`brlan2`–`brlan5`, `brpublic`, `bropen6g`, `brsecure6g`) are managed using Linux bridge utilities.
- **Feedback Reporting**: After applying each configuration, inserts a `Feedback` record into the OVSDB `Feedback` table containing the request UUID and the operation status, allowing the originating component to confirm the outcome.
- **OpenFlow Flow Configuration**: Sets up OpenFlow flows on OVS bridges for specific Wi-Fi hardware models and Mesh fast-roaming scenarios using `ovs-ofctl` commands after bridge configuration.
- **Conditional Startup via syscfg**: Reads the `mesh_ovs_enable` syscfg key at startup. If the key is not set to `true` and neither `OneWiFiEnabled` nor `/etc/WFO_enabled` is present, the agent skips execution and touches `/tmp/ovsagent_initialized` to signal readiness without launching the main process.

## Design

OvsAgent is designed around a single-responsibility principle: it is the sole executor of OVSDB-originated network configuration commands on the Linux platform. The design separates concerns into five distinct libraries linked into the final binary — the core orchestration layer, the public API, the database abstraction layer, the action execution layer, and the CCSP SSP integration layer. Each layer communicates through well-defined C interfaces, making the component straightforward to unit-test and extend.

The northbound interface to OvsAgent is the OVSDB `Gateway_Config` table. Any RDK-B component that needs to configure a bridge or port inserts a row into this table using the OVS Agent API (`ovs_agent_api_interact`). The southbound interface consists of `ovs-vsctl`/`ovs-ofctl` commands for OVS bridge management and `brctl`/`ifconfig` utilities for Linux-native bridge operations, all invoked via `v_secure_system`. The R-BUS connection via `libOvsAgentSsp` allows the agent to resolve CCSP component paths if needed, though the primary communication path is through the Unix socket to OVSDB.

The OVSDB socket layer runs a dedicated listener thread (`ovsdb_listen`) that continuously reads from the socket, parses incoming JSON-RPC messages using the jansson library, and dispatches them to the appropriate receipt or monitor update handlers. The main thread initializes all subsystems in sequence and then enters a sleep loop. Synchronization between the listener thread and the calling thread uses a `pthread_cond_t`/`pthread_mutex_t` pair with a configurable timeout (`OVS_BLOCK_MODE_TIMEOUT_SECS = 3` seconds).

The agent's startup is controlled by the `mesh_ovs_enable` syscfg key, which determines whether the service should launch at boot.

A Component diagram showing the component's internal structure and dependencies is given below:

```mermaid
graph LR
    subgraph ExtSys ["External Systems"]
        OvsDbSrv[("OVSDB Server\n/var/run/openvswitch/db.sock")]
        CcspBus[("R-BUS")]
    end

    subgraph OvsAgentProc ["OvsAgent Process (C, Linux)"]
        subgraph Core ["OvsAgentCore"]
            Main["OvsAgentMain.c\nEntry point, sleep loop"]
            Agent["OvsAgent.c\nInit/Deinit orchestration\ngwconf_mon_cb callback"]
            Log["OvsAgentLog.c\nRDK Logger init\nlog4c / rdk_debug"]
        end

        subgraph ApiLib ["libOvsAgentApi"]
            Api["OvsAgentApi.c\novs_agent_api_init/deinit\novs_agent_api_interact"]
            TxMgr["transaction_manager.c\nHash table, max 5 entries\nUUID-based lifecycle"]
        end

        subgraph DbLib ["libOvsDbApi"]
            DbApi["OvsDbApi.c\novsdb_init, ovsdb_write\novsdb_monitor, ovsdb_delete"]
            Sock["ovsdb_socket.c\nUnix socket\n/var/run/openvswitch/db.sock"]
            Parser["ovsdb_parser.c\nJSON-RPC parsing (jansson)"]
            GwJson["json_parser/gateway_config.c\nGateway_Config serialization"]
            FbJson["json_parser/feedback.c\nFeedback serialization"]
            RecvList["receipt_list.c\nPending receipt tracking"]
            MonList["mon_update_list.c\nMonitor callback dispatch"]
        end

        subgraph ActionLib ["libOvsAction"]
            Action["ovs_action.c\novs_action_gateway_config\novs_action_init"]
            Syscfg["syscfg.c\nSyscfgInit, SyscfgGet\n(lan_ipaddr)"]
        end

        subgraph SspLib ["libOvsAgentSsp"]
            Cosa["cosa_api.c\nCCSP_Message_Bus_Init\nCcspBaseIf_getParameterValues"]
        end
    end

    subgraph OsLayer ["System Layer"]
        OsNet["OS Networking\novs-vsctl / brctl / ifconfig"]
    end

    OvsDbSrv -->|"Gateway_Config monitor"| Sock
    Main --> Agent
    Agent --> Log
    Agent --> Api
    Agent --> Action
    Agent --> Cosa
    Api --> TxMgr
    Api --> DbApi
    DbApi --> Sock
    DbApi --> Parser
    Parser --> GwJson
    Parser --> FbJson
    Parser --> RecvList
    Parser --> MonList
    Action --> Syscfg
    Sock -->|"JSON-RPC"| OvsDbSrv
    Cosa -->|"R-BUS"| CcspBus
    Action -->|"v_secure_system"| OsNet

    classDef coreStyle fill:#fce4ec,stroke:#c62828,stroke-width:1px;
    classDef apiStyle fill:#e1f5fe,stroke:#0277bd,stroke-width:1px;
    classDef dbStyle fill:#f3e5f5,stroke:#7b1fa2,stroke-width:1px;
    classDef actionStyle fill:#e8f5e8,stroke:#2e7d32,stroke-width:1px;
    classDef sspStyle fill:#fff3e0,stroke:#ef6c00,stroke-width:1px;
    classDef extStyle fill:#eceff1,stroke:#546e7a,stroke-width:1px;

    class Main,Agent,Log coreStyle;
    class Api,TxMgr apiStyle;
    class DbApi,Sock,Parser,GwJson,FbJson,RecvList,MonList dbStyle;
    class Action,Syscfg actionStyle;
    class Cosa sspStyle;
    class OvsDbSrv,CcspBus,OsNet extStyle;
```

### Prerequisites and Dependencies

**Build-Time Flags and Configuration:**

The following configure options are available during the `./configure` step:

| Configure Option                        | Purpose                                                                                                                                                                                    | Default  |
| --------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------- |
| `--enable-gtestapp`                     | Enables building the GTest unit test applications under `source/test/`. When disabled, the test subdirectory is excluded from the build.                                                   | Disabled |
| `--enable-core_net_lib_feature_support` | Enables the core network library (`libnet`) backend in `OvsAction`. When active, bridge creation, port add/remove, and interface up/down use `libnet` API calls instead of shell commands. | Disabled |

<br>

**RDK-B Platform and Integration Requirements:**

- **Build Dependencies**: `libjansson` (JSON parsing for OVSDB protocol), `libdbus-1 >= 1.6.18` (R-BUS), `libsyscfg` (syscfg get/init), `libccsp_common` (CCSP base interfaces), `liblog4c` (RDK logging), `libsystemd` (systemd notify integration)
- **RDK-B Components**: Component Registry (must be reachable on R-BUS at startup), `CcspPsm` (PSM must have written `/tmp/psm_initialized` before OvsAgent starts)
- **Systemd Services**: `OvsAgent.service` requires `OvsAgent_ovsdb-server.service`. `OvsAgent.path` triggers service start when `/tmp/psm_initialized` is created.
- **Configuration Files**: `/etc/device.properties` must export `MODEL_NUM` and `OneWiFiEnabled` into the process environment. `/etc/debug.ini` is read by the RDK logger.
- **syscfg Keys**: `mesh_ovs_enable` (controls service startup), `lan_ipaddr` (used for OpenFlow rule generation).
- **Runtime Indicators**: `/tmp/ovsagent_initialized` — created after successful initialization. `/nvram/enable_ovs_debug` — enables debug-level logging.

<br>

**Threading Model:**

OvsAgent runs two threads throughout its process lifetime.

- **Threading Architecture**: Two-threaded. The main thread handles initialization and remains in a `sleep(30)` loop for the lifetime of the process. The listener thread handles all OVSDB socket I/O.
- **Main Thread**: Executes the full initialization sequence (`OvsAgentInit`), enters an infinite sleep loop, and runs `OvsAgentDeinit` on shutdown.
- **Worker Threads**:
  - **`ovsdb_listen` thread**: Created during `ovsdb_init()`. Calls `ovsdb_socket_listen()` in a poll loop with a 100ms timeout. On receiving data, passes the raw buffer to `ovsdb_parse_msg()` for JSON-RPC message dispatch. Thread exits when `g_terminate` is set during deinit.
- **Synchronization**: Blocking API calls in `OvsAgentApi` use a `pthread_cond_t`/`pthread_mutex_t` pair per context handle with a 3-second timed wait (`OVS_BLOCK_MODE_TIMEOUT_SECS`). The transaction table is protected by `ovs_agent_api_mutex` (a static `PTHREAD_MUTEX_INITIALIZER`).

### Component State Flow

**Initialization to Active State**

OvsAgent starts conditionally. The systemd service executes `syscfg_check.sh` to read the `mesh_ovs_enable` syscfg key. If OVS is disabled and neither `OneWiFiEnabled` nor `/etc/WFO_enabled` is present, the script exits after touching `/tmp/ovsagent_initialized` without launching the binary. When OVS is enabled, the binary initializes each subsystem in order — RDK Logger, R-BUS, OVSDB API with listener thread, OvsAction with syscfg — then sets a monitor on the `Gateway_Config` table and creates `/tmp/ovsagent_initialized` to signal readiness.

```mermaid
sequenceDiagram
    autonumber
    participant Systemd as systemd
    participant Script as syscfg_check.sh
    participant OvsAgent as OvsAgent Process
    participant OvsDbSrv as OVSDB Server
    participant Cosa as R-BUS
    participant Syscfg as syscfg

    Systemd->>Script: ExecStart (OvsAgent.service)
    Script->>Syscfg: syscfg get mesh_ovs_enable
    Syscfg-->>Script: value

    alt OVS disabled and OneWiFiEnabled != true and /etc/WFO_enabled absent
        Script->>Script: touch /tmp/ovsagent_initialized
        Script->>Systemd: exit 0 (no OvsAgent binary launched)
    else OVS enabled
        Script->>OvsAgent: launch /usr/bin/OvsAgent
        Note over OvsAgent: main() → OvsAgentInit()

        OvsAgent->>OvsAgent: OvsAgentLogInit()
        Note over OvsAgent: rdk_logger_init("/etc/debug.ini")

        OvsAgent->>Cosa: Cosa_Init()
        Cosa-->>OvsAgent: CCSP_Message_Bus_Init success

        OvsAgent->>OvsDbSrv: ovs_agent_api_init(OVS_AGENT_COMPONENT_ID)
        Note over OvsDbSrv: ovsdb_init → connect to /var/run/openvswitch/db.sock
        Note over OvsDbSrv: spawn ovsdb_listen thread
        OvsDbSrv-->>OvsAgent: init success

        OvsAgent->>Syscfg: ovs_action_init() → SyscfgInit()
        Note over OvsAgent: reads MODEL_NUM, OneWiFiEnabled from env

        OvsAgent->>OvsDbSrv: ovs_agent_api_interact(MONITOR, Gateway_Config)
        Note over OvsDbSrv: ovsdb_monitor sends JSON-RPC monitor request
        OvsDbSrv-->>OvsAgent: monitor established

        OvsAgent->>OvsAgent: creat("/tmp/ovsagent_initialized")
        Note over OvsAgent: State: Active — sleep(30) loop

        loop Runtime
            OvsDbSrv->>OvsAgent: Gateway_Config update → gwconf_mon_cb()
            OvsAgent->>OvsAgent: ovs_action_gateway_config()
            OvsAgent->>OvsDbSrv: ovs_agent_api_interact(INSERT, Feedback)
        end

        Systemd->>OvsAgent: stop signal
        OvsAgent->>OvsAgent: OvsAgentDeinit()
        OvsAgent->>OvsDbSrv: ovs_agent_api_deinit() → ovsdb_deinit()
        OvsAgent->>Cosa: Cosa_Shutdown()
    end
```

**Runtime State Changes and Context Switching**

OvsAgent does not implement a formal state machine beyond init/active/deinit. During active operation, the agent reacts to each `Gateway_Config` monitor update independently.

**State Change Triggers:**

- A new row inserted into the OVSDB `Gateway_Config` table by BridgeUtils or MeshAgent triggers `gwconf_mon_cb()` on the listener thread.
- The `if_cmd` field in `Gateway_Config` determines the specific operation: `OVS_IF_UP_CMD`, `OVS_IF_DOWN_CMD`, `OVS_IF_DELETE_CMD`, or `OVS_BR_REMOVE_CMD`.
- The `parent_bridge` name determines whether OVS or Linux bridge tools are used; for Xfinity WiFi support, `brlan2`–`brlan5`, `brpublic`, `bropen6g`, `brsecure6g` are handled by Linux bridges.
- Presence of `/nvram/enable_ovs_debug` at startup switches the log level from `RDK_LOG_INFO` to `RDK_LOG_DEBUG`.

**Context Switching Scenarios:**

- If `mesh_ovs_enable` is `false` at service start, the shell script exits without launching the binary, touching `/tmp/ovsagent_initialized` to prevent dependent services from stalling.
- On specific Wi-Fi hardware models (`OVS_CGM4331COM_MODEL`, `OVS_CGA4332COM_MODEL`, `OVS_CGM4981COM_MODEL`, `OVS_CGM601TCOM_MODEL`, `OVS_SG417DBCT_MODEL`, `OVS_VTER11QEL_MODEL`, `OVS_SR203_MODEL`), additional OpenFlow flows are configured via `ovs_setup_brcm_wifi_flows()` after bridge setup.
- In warehouse mode (`/tmp/warehouse_mode` present), the agent skips adding `eth0` to `brlan0`.

### Call Flow

**Initialization Call Flow:**

```mermaid
sequenceDiagram
    participant Main as OvsAgentMain.c
    participant Agent as OvsAgent.c
    participant Log as OvsAgentLog.c
    participant Cosa as cosa_api.c
    participant Api as OvsAgentApi.c
    participant DbApi as OvsDbApi.c
    participant Action as ovs_action.c

    Main->>Agent: OvsAgentInit()
    Agent->>Log: OvsAgentLogInit()
    Log-->>Agent: success
    Agent->>Cosa: Cosa_Init()
    Cosa-->>Agent: bus_handle acquired
    Agent->>Api: ovs_agent_api_init(OVS_AGENT_COMPONENT_ID)
    Api->>DbApi: ovsdb_init(startingId)
    DbApi->>DbApi: ovsdb_socket_connect("/var/run/openvswitch/db.sock")
    DbApi->>DbApi: pthread_create(ovsdb_listen)
    DbApi-->>Api: OVS_SUCCESS_STATUS
    Api->>DbApi: ovsdb_monitor(OVS_FEEDBACK_TABLE, feedback_cb)
    DbApi-->>Api: monitor request sent
    Api-->>Agent: init success
    Agent->>Action: ovs_action_init()
    Action->>Action: getenv(MODEL_NUM), getenv(OneWiFiEnabled)
    Action->>Action: SyscfgInit()
    Action-->>Agent: OVS_SUCCESS_STATUS
    Agent->>Api: ovs_agent_api_interact(MONITOR, Gateway_Config, gwconf_mon_cb)
    Api->>DbApi: ovsdb_monitor(OVS_GW_CONFIG_TABLE, ...)
    DbApi-->>Api: success
    Api-->>Agent: success
    Agent->>Agent: creat("/tmp/ovsagent_initialized")
    Agent-->>Main: true
    Main->>Main: while(1) sleep(30)
```

**Request Processing Call Flow:**

```mermaid
sequenceDiagram
    participant Caller as BridgeUtils / MeshAgent
    participant OvsDb as OVSDB Server
    participant Listener as ovsdb_listen thread
    participant Parser as ovsdb_parser.c
    participant MonList as mon_update_list.c
    participant Agent as OvsAgent.c (gwconf_mon_cb)
    participant Action as ovs_action.c
    participant Feedback as OvsAgentApi.c

    Caller->>OvsDb: INSERT into Gateway_Config (JSON-RPC)
    OvsDb->>Listener: monitor update notification
    Listener->>Parser: ovsdb_parse_msg(buffer, len)
    Parser->>Parser: parse JSON-RPC update method
    Parser->>MonList: mon_list_process(uuid, table_config)
    MonList->>Agent: gwconf_mon_cb(status, table_config)
    Agent->>Action: ovs_action_gateway_config(config)
    Note over Action: determine bridge type (OVS vs Linux)
    Note over Action: removeExistingInterfacePort()
    Note over Action: configureParentBridge()
    Note over Action: ovs_setup_bridge_flows() if OVS bridge
    Action-->>Agent: OVS_SUCCESS_STATUS / OVS_FAILED_STATUS
    Agent->>Feedback: ovs_agent_api_interact(INSERT, Feedback{uuid, status})
    Feedback->>OvsDb: INSERT into Feedback table (JSON-RPC)
    OvsDb-->>Feedback: insert receipt with UUID
    OvsDb->>Listener: Feedback monitor update
    Listener->>Parser: ovsdb_parse_msg
    Parser->>Feedback: ovs_agent_api_monitor_feedback_callback
    Feedback->>Feedback: complete_transaction(uuid, status)
    Feedback->>OvsDb: DELETE from Gateway_Config (uuid)
    Feedback->>OvsDb: DELETE from Feedback (req_uuid)
```

## Internal Modules

OvsAgent is organized into five library modules with a single executable entry point. Each library has a clearly scoped responsibility.

| Module/Class                       | Description                                                                                                                                                                                                                                                                                                                                                                                 | Key Files                                                                                                                                         |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OvsAgentCore**                   | Entry point and top-level orchestration. Calls each subsystem in initialization order, registers the Gateway_Config monitor callback (`gwconf_mon_cb`), creates the `/tmp/ovsagent_initialized` marker on success, and drives the deinit sequence on shutdown.                                                                                                                              | `OvsAgentMain.c`, `OvsAgent.c`, `OvsAgentLog.c`, `OvsAgentLog.h`                                                                                  |
| **OvsAgentApi** (`libOvsAgentApi`) | Public interaction API consumed by other RDK-B components. Manages the component lifecycle (`ovs_agent_api_init/deinit`), serializes requests to the OvsDbApi, tracks each request through a hash-table-based transaction manager (max 5 concurrent entries), and handles timed blocking waits for feedback.                                                                                | `OvsAgentApi.c`, `transaction_manager.c`, `transaction_interface.h`                                                                               |
| **OvsDbApi** (`libOvsDbApi`)       | OVSDB protocol abstraction. Manages the Unix domain socket connection to the OVSDB server, runs the `ovsdb_listen` listener thread, serializes `Gateway_Config` and `Feedback` records to JSON-RPC using jansson, and dispatches received messages to receipt and monitor update lists.                                                                                                     | `OvsDbApi.c`, `ovsdb_socket.c`, `ovsdb_parser.c`, `receipt_list.c`, `mon_update_list.c`, `json_parser/gateway_config.c`, `json_parser/feedback.c` |
| **OvsAction** (`libOvsAction`)     | Network operation execution. Reads device model and `OneWiFiEnabled` flag from environment variables and initializes syscfg at startup. Translates each `Gateway_Config` record into the appropriate `ovs-vsctl`, `brctl`, or `ifconfig` command (or `libnet` API calls when `CORE_NET_LIB` is defined). Handles OpenFlow flow setup for specific Wi-Fi hardware models and Mesh scenarios. | `ovs_action.c`, `ovs_action.h`, `syscfg.c`, `syscfg.h`                                                                                            |
| **OvsAgentSsp** (`libOvsAgentSsp`) | CCSP Service Support Platform integration. Initializes the R-BUS connection, exposes helpers to discover CCSP component paths (`Cosa_FindDestComp`) and retrieve parameter values (`Cosa_GetParamValues`), and cleanly shuts down the bus handle.                                                                                                                                | `cosa_api.c`, `cosa_api.h`                                                                                                                        |

## Component Interactions

OvsAgent communicates with the OVSDB server over a Unix domain socket using JSON-RPC, with the `ovsdb_listen` thread handling all incoming messages. Network operations are executed through `v_secure_system` shell commands targeting `ovs-vsctl`, `brctl`, or `ifconfig`. The R-BUS connection initialized via `libOvsAgentSsp` enables CCSP component path resolution at startup.

### Interaction Matrix

| Target Component/Layer          | Interaction Purpose                                                                                                                          | Key APIs/Endpoints                                                                                                     |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| **RDK-B Middleware Components** |                                                                                                                                              |                                                                                                                        |
| OVSDB Server (`ovsdb-server`)   | Primary communication channel. Receives `Gateway_Config` monitor updates; sends `Feedback` inserts and cleanup deletes.                      | Unix socket `/var/run/openvswitch/db.sock`, JSON-RPC `transact`, `monitor`, `monitor_cancel` methods                   |
| BridgeUtils                     | Indirect; inserts `Gateway_Config` rows that OvsAgent monitors. OvsAgent does not call BridgeUtils directly.                                 | OVSDB `Gateway_Config` table (consumer side)                                                                           |
| MeshAgent                       | Indirect; inserts `Gateway_Config` rows for Mesh networking bridge setup. OvsAgent sends Feedback on completion.                             | OVSDB `Gateway_Config` table (consumer side), OVSDB `Feedback` table                                                   |
| Component Registry              | CCSP Component Registry — used during `Cosa_Init()` to establish R-BUS bus handle.                                                           | `CCSP_Message_Bus_Init()`, `CcspBaseIf_discComponentSupportingNamespace()`                                             |
| CcspPsm                         | Startup gate — OvsAgent service requires `/tmp/psm_initialized` to exist before it starts. No direct API calls to PSM at runtime.            | `ConditionPathExists=/tmp/psm_initialized` (systemd)                                                                   |
| **System & Platform Layer**     |                                                                                                                                              |                                                                                                                        |
| syscfg (NVRAM)                  | Reads `lan_ipaddr` for OpenFlow rule construction; `SyscfgInit()` called once in `ovs_action_init()`.                                        | `SyscfgInit()`, `SyscfgGet("lan_ipaddr", ...)` in `ovs_action.c`                                                       |
| `/etc/device.properties`        | Source of `MODEL_NUM` and `OneWiFiEnabled` flags used to select OVS flow configuration paths. Read via `getenv()`.                           | `getenv("MODEL_NUM")`, `getenv("OneWiFiEnabled")`                                                                      |
| `ovs-vsctl` / `ovs-ofctl`       | Executes OVS bridge/port management and OpenFlow rule setup via shell command.                                                               | `v_secure_system("ovs-vsctl add-br ...")`, `v_secure_system("ovs-ofctl ...")`                                          |
| `brctl` / `ifconfig`            | Executes Linux-native bridge and interface commands for non-OVS bridges.                                                                     | `v_secure_system("brctl addbr ...")`, `v_secure_system("ifconfig ...")`                                                |
| `libnet` (optional)             | When built with `CORE_NET_LIB` defined, replaces `brctl`/`ifconfig` shell calls with `libnet` API calls for bridge and interface operations. | `bridge_create()`, `interface_add_to_bridge()`, `interface_up()`, `interface_down()`, `interface_remove_from_bridge()` |

**Note:** No configuration changes are persisted across reboots by OvsAgent itself. `SyscfgGet` is used read-only for `lan_ipaddr`. The `mesh_ovs_enable` syscfg key that gates service startup is written and managed by other components.

**Major Events Published by OvsAgent:**

OvsAgent does not publish R-BUS or CCSP events. Its output channel is inserting rows into the OVSDB `Feedback` table over the Unix socket.

| Output                             | Target                                           | Trigger Condition                                                   | Description                                                                                                                  |
| ---------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| OVSDB `Feedback` INSERT            | OVSDB Server → BridgeUtils / MeshAgent (monitor) | After each `Gateway_Config` operation completes                     | Contains `req_uuid` (matching the processed `Gateway_Config` row) and `status` (`OVS_SUCCESS_STATUS` or `OVS_FAILED_STATUS`) |
| OVSDB `Gateway_Config` DELETE      | OVSDB Server                                     | After Feedback monitor callback confirms completion                 | Cleans the processed request row from the table                                                                              |
| OVSDB `Feedback` DELETE            | OVSDB Server                                     | After Feedback monitor callback confirms completion                 | Cleans the feedback row from the table                                                                                       |
| `/tmp/ovsagent_initialized` (file) | Dependent systemd units / shell scripts          | After `OvsAgentInit()` succeeds, or when OVS is disabled at startup | Marker file indicating OvsAgent is ready or has determined it should not run                                                 |

### IPC Flow Patterns

**Primary IPC Flow — Gateway Config Request and Feedback:**

```mermaid
sequenceDiagram
    participant Caller as BridgeUtils / MeshAgent
    participant OvsDb as OVSDB Server
    participant OvsAgent as OvsAgent
    participant OS as OS Networking (ovs-vsctl / brctl)

    Caller->>OvsDb: JSON-RPC transact (INSERT Gateway_Config)
    Note over OvsDb: Row inserted with UUID
    OvsDb->>OvsAgent: JSON-RPC monitor update (Gateway_Config row)
    Note over OvsAgent: gwconf_mon_cb() invoked on listener thread
    OvsAgent->>OS: v_secure_system (ovs-vsctl / brctl command)
    OS-->>OvsAgent: command result
    OvsAgent->>OvsDb: JSON-RPC transact (INSERT Feedback {req_uuid, status})
    OvsDb->>OvsAgent: JSON-RPC monitor update (Feedback row)
    Note over OvsAgent: ovs_agent_api_monitor_feedback_callback()
    OvsAgent->>OvsDb: JSON-RPC transact (DELETE Gateway_Config by uuid)
    OvsAgent->>OvsDb: JSON-RPC transact (DELETE Feedback by req_uuid)
```

## Implementation Details

### Key Implementation Logic

- **Bridge Backend Selection**: In `ovs_modifyParentBridge()` ([ovs_action.c](open-virtual-switch-agent/source/OvsAction/ovs_action.c#L1178-L1186)), the bridge name is checked against a hard-coded list (`brlan2`–`brlan5`, `brpublic`, `bropen6g`, `brsecure6g`) to meet Xfinity WiFi requirements. These bridges use Linux bridge utilities. All other bridges use `ovs-vsctl`.

- **OpenFlow Flow Setup**: After creating or modifying a bridge, `ovs_setup_bridge_flows()` is called. For specific Wi-Fi hardware models (identified as `OVS_CGM4331COM_MODEL`, `OVS_CGA4332COM_MODEL`, `OVS_CGM4981COM_MODEL`, `OVS_CGM601TCOM_MODEL`, `OVS_SG417DBCT_MODEL`, `OVS_VTER11QEL_MODEL`, `OVS_SR203_MODEL`), `ovs_setup_brcm_wifi_flows()` sets up OpenFlow flows. Additional flows handle Mesh fast-roaming scenarios.

- **Transaction Manager**: Uses a fixed-size hash table in `transaction_manager.c` with a maximum of 5 concurrent entries (`MAX_TABLE_SIZE = 5`), keyed by a string request ID (`rid`). States: `TRANSACTION_INIT_ST` → `TRANSACTION_UUID_RECV_ST` → `TRANSACTION_COMPLETE_ST`.

- **Blocking Mode Timeout**: `wait_for_callback_completion()` in `OvsAgentApi.c` uses `pthread_cond_timedwait` with a 3-second timeout (`OVS_BLOCK_MODE_TIMEOUT_SECS`). On timeout, `OVS_TIMED_OUT_STATUS` is returned.

- **Warehouse Mode Guard**: In `configureParentBridge()`, if `if_name` is `eth0` and the target bridge is `brlan0` and `/tmp/warehouse_mode` exists, port addition is skipped to avoid modifying the network in warehouse mode.

- **Logging and Debug**: `OvsAgentLog.c` initializes RDK Logger from `/etc/debug.ini`. Log channel is `LOG.RDK.OVSAGENT`. Debug logging is enabled at runtime by creating `/nvram/enable_ovs_debug`.

- **Error Handling**: Each initialization step in `OvsAgentInit()` performs a teardown of previously initialized subsystems before returning `false`. The `OvsAgent.service` systemd unit has `Restart=on-failure`, so the process will be restarted by systemd if it exits with a non-zero return code.

### Key Configuration Files

| Configuration File       | Purpose                                                                                                                                               | Override Mechanisms                                               |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| `/etc/device.properties` | Supplies `MODEL_NUM` (device model identifier) and `OneWiFiEnabled` flag via environment variables injected by the systemd unit (`EnvironmentFile=`). | Replaced per platform at image build time.                        |
| `/etc/debug.ini`         | RDK Logger configuration, read during `OvsAgentLogInit()`.                                                                                            | N/A                                                               |
| `/tmp/ccsp_msg.cfg`      | R-BUS configuration file, read by `CCSP_Message_Bus_Init()` in `cosa_api.c`.                                                               | Written at runtime by CCSP infrastructure before OvsAgent starts. |

**Configuration Persistence:**

`OvsAgent` reads `lan_ipaddr` from syscfg via `SyscfgGet()` in `ovs_action.c`. This is a read-only operation. No syscfg keys are written or committed by OvsAgent. The `mesh_ovs_enable` key that gates service startup is read exclusively by the `syscfg_check.sh` shell script, not by the C binary. Network interface and bridge configurations applied by OvsAgent are not persisted to any store — they are re-applied from OVSDB state on each service start.
