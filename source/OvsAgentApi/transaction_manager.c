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
#include <stdlib.h>
#include <string.h>
#include "common/OvsAgentLog.h"
#include "OvsAgentApi/transaction_interface.h"

#define MAX_TABLE_SIZE 5

typedef enum transaction_state
{
    TRANSACTION_INIT_ST = 0,
    TRANSACTION_UUID_RECV_ST,
    TRANSACTION_COMPLETE_ST,
    TRANSACTION_TIMEOUT_ST // TODO: use somewhere
} TRANSACTION_STATE;

// TODO: add timestamp
typedef struct Transaction_Entry
{
    unsigned int id;
    char uuid[MAX_UUID_LEN + 1];
    TRANSACTION_STATE state;
    ovs_interact_cb callback;
    Rdkb_Table_Config table_config;
    OVS_STATUS status;
} Transaction_Entry;

typedef struct Transaction_Table
{
    unsigned int size;
    Transaction_Entry **elements; // An array of pointers to Transaction_Entry structures
} Transaction_Table;

static Transaction_Table * g_transaction_table = NULL;

// TODO: DOM Cleanup entire transaction table
// TODO: DOM Unit test cases
// TODO: DOM Keep id as char* instead of unsigned int. Do atoi in hash_code(char* id, size)

static unsigned int hash_code(unsigned int key, unsigned int tableSize)
{
    return (key % tableSize); // the hash function returns a number bounded by the number of table slots.
}

static void init_transaction_table(Transaction_Table * transactionTable)
{
    unsigned int i;
    OvsAgentApiDebug("%s table: %p(%p), Size: %u\n", __func__,
        transactionTable, transactionTable->elements, transactionTable->size);
    for (i=0; i<transactionTable->size; i++)
    {
        transactionTable->elements[i] = NULL;
    }
}

/* Create a new transaction table. */
static Transaction_Table * create_transaction_table(unsigned int size)
{
    Transaction_Table * transactionTable = NULL;

    if (size < 1 || size > MAX_TABLE_SIZE)
    {
        return NULL;
    }

    /* Allocate the table itself. */
    if ((transactionTable =
        (Transaction_Table *)malloc(sizeof(Transaction_Table))) == NULL)
    {
        return NULL;
    }

    // Allocate pointers to the entries.*/
    if ((transactionTable->elements =
        (Transaction_Entry **)malloc(sizeof(Transaction_Entry *) * size)) == NULL)
    {
        free(transactionTable);
        transactionTable = NULL;
        return NULL;
    }

    transactionTable->size = size;
    OvsAgentApiDebug("%s table: %p, Elements: %p, Size: %u\n", __func__,
        transactionTable, transactionTable->elements, transactionTable->size);
    return transactionTable;
}

static bool destroy_transaction(Transaction_Entry * transaction)
{
    if (!transaction)
    {
        OvsAgentApiWarning("%s transaction is NULL\n", __func__);
        return false;
    }
    OvsAgentApiDebug("%s %p with Id: %u\n", __func__, transaction, transaction->id);
    if (transaction->table_config.config)
    {
        OvsAgentApiDebug("%s free'ing Id: %u, Table: %d, Config: %p\n", __func__,
            transaction->id, transaction->table_config.table.id,
            transaction->table_config.config);
        free(transaction->table_config.config);
        transaction->table_config.config = NULL;
    }
    free(transaction);
    transaction = NULL;
    return true;
}

bool init_transaction_manager(void)
{
    unsigned int size = MAX_TABLE_SIZE;
    Transaction_Table * table = NULL;

    if (g_transaction_table)
    {
        OvsAgentApiDebug("%s transaction table already initialized\n", __func__);
        return true;
    }

    table = create_transaction_table(size);
    if (!table)
    {
        OvsAgentApiError("%s failed to create the transaction table of size %u!\n", __func__, size);
        return false;
    }

    init_transaction_table(table);

    g_transaction_table = table;
    OvsAgentApiDebug("%s table: %p, Elements: %p, Size: %u\n", __func__,
        g_transaction_table, g_transaction_table->elements, g_transaction_table->size);
    return true;
}

void deinit_transaction_manager(void)
{
    unsigned int i;
    Transaction_Entry * transaction = NULL;

    if (!g_transaction_table)
    {
        OvsAgentApiDebug("%s transaction table already de-initialized\n", __func__);
        return;
    }

    // Delete Transaction Entries
    for (i=0; i<g_transaction_table->size; i++)
    {
        transaction = g_transaction_table->elements[i];
        if (transaction)
        {
            (void)destroy_transaction(transaction);
        }
    }

    // Delete Transaction Table's array of pointers to structures
    if (g_transaction_table->elements)
    {
        OvsAgentApiDebug("%s table elements %p\n", __func__, g_transaction_table->elements);
        free(g_transaction_table->elements);
        g_transaction_table->elements = NULL;
    }

    // Delete the table structure
    if (g_transaction_table)
    {
        g_transaction_table->size = 0;
        OvsAgentApiDebug("%s table %p\n", __func__, g_transaction_table);
        free(g_transaction_table);
        g_transaction_table = NULL;
    }
}

static void print_transaction(unsigned int index)
{
    Transaction_Entry * transaction = NULL;
    unsigned int key = hash_code(index, g_transaction_table->size);
    transaction = g_transaction_table->elements[key];
    if (!transaction)
    {
        OvsAgentApiDebug("%s: Key: %u EMPTY\n", __func__, key);
        return;
    }
    OvsAgentApiDebug("%s: Key: %u, Id: %u, Uuid: %s\n", __func__,
        key, transaction->id, transaction->uuid);
}

static void print_transaction_table(void)
{
    unsigned int idx;
    for (idx=0; idx<g_transaction_table->size; idx++)
    {
        print_transaction(idx);
    }
}

static bool find_transaction_key(char * uuid, unsigned int * key)
{
    unsigned int i;
    Transaction_Entry * transaction = NULL;
    if (!uuid || !key)
    {
        return false;
    }
    for (i=0; i<g_transaction_table->size; i++)
    {
        transaction = g_transaction_table->elements[i];
        if (transaction && (strncmp(transaction->uuid, uuid, MAX_UUID_LEN) == 0))
        {
            OvsAgentApiDebug("%s Found Uuid %s at key %u.\n", __func__, uuid, i);
            *key = i;
            return true;
        }
    }
    OvsAgentApiDebug("%s unable to find Uuid %s!\n", __func__, uuid);
    return false;
}

// Returns a ptr to the transaction
static Transaction_Entry * get_transaction(unsigned int id)
{
    unsigned int key = hash_code(id, g_transaction_table->size);
    if (!g_transaction_table->elements[key])
    {
        return NULL;
    }
    return g_transaction_table->elements[key];
}

// Removes the transaction ptr from the table, and set its key to NULL.$
// Returns a ptr to the removed transaction.
static Transaction_Entry * remove_transaction_table(unsigned int key)
{
    Transaction_Entry * transaction = NULL;
    if (!g_transaction_table->elements[key])
    {
        OvsAgentApiWarning("%s: transaction NULL at key: %u\n", __func__, key);
        return NULL;
    }
    transaction = g_transaction_table->elements[key];
    g_transaction_table->elements[key] = NULL;
    return transaction;
}

static bool remove_transaction(unsigned int id)
{
    OvsAgentApiDebug("%s: Id: %u\n", __func__, id);
    unsigned int key = hash_code(id, g_transaction_table->size);
    Transaction_Entry * transaction = remove_transaction_table(key);
    if (!transaction)
    {
        OvsAgentApiError("%s: failed for Id: %u at key %u\n", __func__, id, key);
        return false;
    }
    return destroy_transaction(transaction);
}

bool delete_transaction(char * rid)
{
    unsigned int id = 0;
    OvsAgentApiDebug("%s: rId: %s\n", __func__, (rid ? rid : "NULL"));

    if (!rid)
    {
        OvsAgentApiError("%s: rId is NULL\n", __func__);
        return false;
    }

    id = atoi(rid);
    return remove_transaction(id);
}

// TODO: Handle collisions in non-block mode for non-timed out transactions or in
// the case when the table is full.
static bool insert_transaction_table(Transaction_Entry * transaction)
{
    unsigned int id = 0;
    unsigned int key = 0;

    if (!transaction)
    {
        return false;
    }
    id = transaction->id;
    key = hash_code(id, g_transaction_table->size);
    if (g_transaction_table->elements[key])
    {
        // Entry already exists, as callback was not received, and it was never removed.
        // Remove transaction, delete it, and reuse key.
        // TODO: Destroy transaction only if the transaction has timed out.
        OvsAgentApiWarning("%s removing existing Transaction at key %u\n",
            __func__, key);
        if (!destroy_transaction(remove_transaction_table(key)))
        {
            OvsAgentApiError("%s failed to destroy existing Transaction at key %u\n",
                __func__, key);
            return false;
        }
    }
    g_transaction_table->elements[key] = transaction;
    OvsAgentApiDebug("%s for Id: %u at key %u\n", __func__, id, key);
    return true;
}

static Transaction_Entry * create_transaction(unsigned int id, ovs_interact_cb callback,
    Rdkb_Table_Config * table_config)
{
    Transaction_Entry * transaction = NULL;
    OvsAgentApiDebug("%s: Id: %u\n", __func__, id);

    if (!table_config)
    {
        return NULL;
    }
    if ((transaction = (Transaction_Entry *)malloc(sizeof(Transaction_Entry))) == NULL)
    {
        return NULL;
    }
    transaction->id = id;
    memset(transaction->uuid, 0, sizeof(transaction->uuid));
    transaction->state = TRANSACTION_INIT_ST;
    transaction->callback = callback; // Can be NULL
    transaction->table_config = *table_config; // shallow copy, transfers ownership of config ptr member
    transaction->status = OVS_UNKNOWN_STATUS;

    OvsAgentApiDebug("%s: created Transaction %p Id: %u, Table: %d, Config: %p\n",
        __func__, transaction, id, table_config->table.id, table_config->config);
    return transaction;
}

bool insert_transaction(char * rid, ovs_interact_cb callback,
    Rdkb_Table_Config * table_config)
{
    unsigned int id = 0;
    Transaction_Entry * transaction = NULL;
    OvsAgentApiDebug("%s: rId: %s\n", __func__, (rid ? rid : "NULL"));

    if (!rid || !table_config)
    {
        OvsAgentApiError("%s: rId or table config is NULL\n", __func__);
        return false;
    }

    id = atoi(rid);
    transaction = create_transaction(id, callback, table_config);
    if (!transaction)
    {
        OvsAgentApiError("%s: NULL transaction for Id: %u\n", __func__, id);
        return false;
    }
    if (!insert_transaction_table(transaction))
    {
        OvsAgentApiError("%s: failed for Id: %u\n", __func__, id);
        free(transaction);
        return false;
    }
    OvsAgentApiDebug("%s: succeeded for Transaction %p Id: %u\n",
        __func__, transaction, id);
    return true;
}

static bool update_transaction_uuid(unsigned int id, const char * uuid)
{
    Transaction_Entry * transaction = NULL;
    OvsAgentApiDebug("%s: Id: %d, %s\n", __func__, id, (uuid ? uuid : "NULL"));

    if (!uuid)
    {
        return false;
    }

    transaction = get_transaction(id);
    if (!transaction)
    {
        OvsAgentApiError("%s failed to find transaction with Id: %u, Uuid: %s\n",
            __func__, id, uuid);
        return false;
    }
    strncpy(transaction->uuid, uuid, MAX_UUID_LEN);
    transaction->uuid[MAX_UUID_LEN] = '\0';
    transaction->state = TRANSACTION_UUID_RECV_ST;

    OvsAgentApiDebug("%s: succeeded for Transaction %p Id: %u, Uuid: %s\n",
        __func__, transaction, id, (uuid ? uuid : "NULL"));
    return true;
}

bool update_transaction(const char * rid, const char * uuid)
{
    unsigned int id = 0;
    OvsAgentApiDebug("%s: rId: %s, Uuid: %s\n", __func__,
        (rid ? rid : "NULL"), (uuid ? uuid : "NULL"));

    if (!rid || !uuid)
    {
        OvsAgentApiError("%s rId or Uuid is NULL\n", __func__);
        return false;
    }

    id = atoi(rid);
    return update_transaction_uuid(id, uuid);
}

bool complete_transaction(char * uuid, OVS_STATUS status, bool * found)
{
    unsigned int key = 0;
    Transaction_Entry * transaction = NULL;
    OvsAgentApiDebug("%s: Uuid: %s, Status: %d\n", __func__,
        (uuid ? uuid : "NULL"), status);

    if (!uuid || !found)
    {
        OvsAgentApiError("%s Input parameter is NULL\n", __func__);
        return false;
    }

    *found = false;
    if (!find_transaction_key(uuid, &key))
    {
        OvsAgentApiDebug("%s unable to find Uuid %s\n", __func__, uuid);
        return false;
    }
    *found = true;

    // Get the transaction entry, update it, call callback and finally remove it
    transaction = remove_transaction_table(key);
    if (!transaction)
    {
        OvsAgentApiError("%s failed to extract transaction with Uuid %s at key %u\n",
            __func__, uuid, key);
        return false;
    }
    OvsAgentApiDebug("%s: Transaction %p Id: %u, Uuid: %s\n", __func__,
        transaction, transaction->id, transaction->uuid);
    transaction->status = status;
    transaction->state = TRANSACTION_COMPLETE_ST;
    if (transaction->callback)
    {
        OvsAgentApiDebug(
            "%s calling callback for Id: %u, Uuid: %s, Status: %d, Table: %d, Config: %p\n",
            __func__, transaction->id, uuid, status, transaction->table_config.table.id,
            transaction->table_config.config);
        transaction->callback(status, &transaction->table_config);
    }
    return destroy_transaction(transaction);
}
