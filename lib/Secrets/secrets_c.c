/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "secrets_c.h"

#include <dbus/dbus.h>
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int Sailfish_Secrets__getServerPeerToPeerAddress(
        char ** p2pAddr,
        DBusConnection **sessionBus)
{
    DBusMessage* msg;
    DBusMessageIter args;
    DBusError err;
    DBusPendingCall* pending;
    char *param = NULL;

    if (p2pAddr == NULL || sessionBus == NULL) {
        fprintf(stderr, "Invalid parameters!\n");
        return 0;
    }

    /* initialise the error */
    dbus_error_init(&err);

    /* connect to the session bus */
    *sessionBus = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Connection Error (%s)\n", err.message);
        dbus_error_free(&err);
    }
    if (*sessionBus == NULL) {
        return 0;
    }

    /* create a new method call and check for errors */
    msg = dbus_message_new_method_call(
                "org.sailfishos.secrets.daemon.discovery",
                "/Sailfish/Secrets/Discovery",
                "org.sailfishos.secrets.daemon.discovery",
                "peerToPeerAddress");
    if (msg == NULL) {
        fprintf(stderr, "Message Null\n");
        dbus_error_free(&err);
        return 0;
    }

    /* send message and get a handle for a reply */
    dbus_connection_send_with_reply(
                *sessionBus,
                msg,
                &pending,
                -1);

    if (pending == NULL) {
        fprintf(stderr, "Pending Call Null\n");
        dbus_error_free(&err);
        dbus_message_unref(msg);
        return 0;
    }

    dbus_connection_flush(*sessionBus);
    dbus_message_unref(msg);
    dbus_pending_call_block(pending);
    msg = dbus_pending_call_steal_reply(pending);
    dbus_pending_call_unref(pending);
    if (msg == NULL) {
        fprintf(stderr, "Reply Null\n");
        dbus_error_free(&err);
        return 0;
    }

    /* read the address return argument */
    if (!dbus_message_iter_init(msg, &args)) {
        fprintf(stderr, "Message has no arguments!\n");
    } else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
        fprintf(stderr, "Argument is not string!\n");
    } else {
        dbus_message_iter_get_basic(&args, &param);
    }

    *p2pAddr = strdup(param);

    dbus_error_free(&err);
    dbus_message_unref(msg);

    return 1;
}

static struct Sailfish_Secrets_DBus_Connection {
    DBusConnection *sessionBus;
    DBusConnection* p2pBus;
    DBusMessage* msg;
    DBusPendingCall* pending;
    char *p2pAddr;
} daemon_connection = {
    .sessionBus = NULL,
    .p2pBus = NULL,
    .msg = NULL,
    .pending = NULL,
    .p2pAddr = NULL
};

static int Sailfish_Secrets__isConnectedToServer()
{
    return daemon_connection.p2pBus == NULL ? 0 : 1;
}

static int Sailfish_Secrets__connectToServer()
{
    DBusError daemon_connection_error;

    if (daemon_connection.p2pBus != NULL) {
        fprintf(stderr, "Already connected to secrets daemon!\n");
        return 1; /* Return "ok" */
    }

    /* Get the peer to peer address of the daemon via the session bus */
    if (!daemon_connection.p2pAddr &&
            !Sailfish_Secrets__getServerPeerToPeerAddress(
                &daemon_connection.p2pAddr,
                &daemon_connection.sessionBus)) {
        return 0;
    }

    /* Open a private peer to peer connection to the daemon */
    dbus_error_init(&daemon_connection_error);
    daemon_connection.p2pBus = dbus_connection_open_private(
                daemon_connection.p2pAddr,
                &daemon_connection_error);
    if (dbus_error_is_set(&daemon_connection_error)) {
        fprintf(stderr,
                "Connection Error (%s) to: %s\n",
                daemon_connection_error.message,
                daemon_connection.p2pAddr);
        dbus_error_free(&daemon_connection_error);
    }
    if (daemon_connection.p2pBus == NULL) {
        return 0;
    }

    return 1;
}

void Sailfish_Secrets_disconnectFromServer()
{
    if (daemon_connection.p2pBus) {
        dbus_connection_close(daemon_connection.p2pBus);
        dbus_connection_unref(daemon_connection.p2pBus);
        daemon_connection.p2pBus = NULL;
        free(daemon_connection.p2pAddr);
        daemon_connection.p2pAddr = NULL;
    }
}

static void Sailfish_Secrets__appendEnumArg(
        DBusMessageIter *in_args,
        DBusMessageIter *enum_struct,
        int *arg)
{
    dbus_message_iter_open_container(
                in_args,
                DBUS_TYPE_STRUCT,
                NULL,
                enum_struct);
    dbus_message_iter_append_basic(
                enum_struct,
                DBUS_TYPE_INT32,
                arg);
    dbus_message_iter_close_container(
                in_args,
                enum_struct);
}

static void Sailfish_Secrets__appendSecretIdentifierArg(
        DBusMessageIter *args,
        struct Sailfish_Secrets_Secret_Identifier *ident)
{
    DBusMessageIter ident_struct;

    dbus_message_iter_open_container(
                args,
                DBUS_TYPE_STRUCT,
                NULL,
                &ident_struct);

    dbus_message_iter_append_basic(
                &ident_struct,
                DBUS_TYPE_STRING,
                &ident->name);

    dbus_message_iter_append_basic(
                &ident_struct,
                DBUS_TYPE_STRING,
                &ident->collectionName);

    dbus_message_iter_close_container(
                args,
                &ident_struct);
}

static void Sailfish_Secrets__appendSecretArg(
        DBusMessageIter *in_args,
        struct Sailfish_Secrets_Secret *secret)
{
    DBusMessageIter secret_struct;
    DBusMessageIter data_array;
    DBusMessageIter filter_dict;
    struct Sailfish_Secrets_Secret_FilterDatum *next = secret->filterData;

    dbus_message_iter_open_container(
                in_args,
                DBUS_TYPE_STRUCT,
                NULL,
                &secret_struct);

    /* append the identifier */
    Sailfish_Secrets__appendSecretIdentifierArg(&secret_struct,
                                                secret->identifier);

    /* append the data array */
    dbus_message_iter_open_container(
                &secret_struct,
                DBUS_TYPE_ARRAY,
                "y",
                &data_array);

    dbus_message_iter_append_fixed_array(
                &data_array,
                DBUS_TYPE_BYTE,
                &secret->data,
                secret->dataSize);

    dbus_message_iter_close_container(
                &secret_struct,
                &data_array);

    /* append the filter dict */
    dbus_message_iter_open_container(
                &secret_struct,
                DBUS_TYPE_ARRAY,
                "{sv}",
                &filter_dict);

    while (next) {
        DBusMessageIter key_value;
        DBusMessageIter value;
        char signature[2];
        signature[0] = DBUS_TYPE_STRING;
        signature[1] = 0;

        dbus_message_iter_open_container(
                    &filter_dict,
                    DBUS_TYPE_DICT_ENTRY,
                    NULL,
                    &key_value);
        dbus_message_iter_append_basic(
                    &key_value,
                    DBUS_TYPE_STRING,
                    &next->field);
        dbus_message_iter_open_container(
                    &key_value,
                    DBUS_TYPE_VARIANT,
                    signature,
                    &value);
        dbus_message_iter_append_basic(
                    &value,
                    DBUS_TYPE_STRING,
                    &next->value);
        dbus_message_iter_close_container(
                    &key_value,
                    &value);
        dbus_message_iter_close_container(
                    &filter_dict,
                    &key_value);
        next = next->next;
    }

    dbus_message_iter_close_container(
                &secret_struct,
                &filter_dict);

    dbus_message_iter_close_container(
                in_args,
                &secret_struct);
}

static int Sailfish_Secrets__readResultStruct(
        DBusMessageIter *args,
        struct Sailfish_Secrets_Result **result)
{
    if (args == NULL
            || result == NULL
            || *result != NULL) {
        fprintf(stderr, "Invalid parameters, cannot read result!\n");
        return 0;
    }

    if (dbus_message_iter_get_arg_type(args) != DBUS_TYPE_STRUCT) {
        fprintf(stderr, "Argument is not result struct!\n");
        if (dbus_message_iter_get_arg_type(args) == DBUS_TYPE_STRING) {
            char *resultStr;
            dbus_message_iter_get_basic(args, &resultStr);
            fprintf(stderr, "Got result str: %s\n", resultStr);
        }
        return 0;
    } else {
        DBusMessageIter res_struct;
        int code;
        int errorCode;
        char *errorMessage;

        dbus_message_iter_recurse(args, &res_struct);

        if (dbus_message_iter_get_arg_type(&res_struct) != DBUS_TYPE_INT32) {
            fprintf(stderr, "First result struct arg not an integer!\n");
            return 0;
        }

        dbus_message_iter_get_basic(&res_struct, &code);

        dbus_message_iter_next(&res_struct);

        if (dbus_message_iter_get_arg_type(&res_struct) != DBUS_TYPE_INT32) {
            fprintf(stderr, "Second result struct arg not an integer!\n");
            return 0;
        }

        dbus_message_iter_get_basic(&res_struct, &errorCode);

        dbus_message_iter_next(&res_struct);

        if (dbus_message_iter_get_arg_type(&res_struct) != DBUS_TYPE_STRING) {
            fprintf(stderr, "Third result struct arg not a string!\n");
            return 0;
        }

        dbus_message_iter_get_basic(&res_struct, &errorMessage);

        *result = Sailfish_Secrets_Result_new(
                    code, errorCode, errorMessage);
    }

    return 1;
}


static int Sailfish_Secrets__readSecretStruct(
        DBusMessageIter *args,
        struct Sailfish_Secrets_Secret **secret)
{
    if (args == NULL
            || secret == NULL
            || *secret != NULL) {
        fprintf(stderr, "Invalid parameters, cannot read secret!\n");
        return 0;
    }

    if (dbus_message_iter_get_arg_type(args) != DBUS_TYPE_STRUCT) {
        fprintf(stderr, "Argument is not result struct!\n");
        if (dbus_message_iter_get_arg_type(args) == DBUS_TYPE_STRING) {
            char *resultStr;
            dbus_message_iter_get_basic(args, &resultStr);
            fprintf(stderr, "Got result str: %s\n", resultStr);
        }
        return 0;
    } else {
        DBusMessageIter sec_struct;
        DBusMessageIter id_struct;
        DBusMessageIter data_array;
        struct Sailfish_Secrets_Secret_FilterDatum *first = NULL;
        const char *idName;
        const char *idCName;
        const unsigned char *data = NULL;
        int n_bytes = 0;

        dbus_message_iter_recurse(args, &sec_struct);

        if (!dbus_message_iter_has_next(&sec_struct)) {
            fprintf(stderr, "Sec struct doesn't contain any values!\n");
            return 0;
        }

        /* Read the identifier data */
        dbus_message_iter_recurse(&sec_struct, &id_struct);
        if (dbus_message_iter_get_arg_type(&id_struct) != DBUS_TYPE_STRING) {
            fprintf(stderr, "First ident struct arg not a string!\n");
            return 0;
        }
        dbus_message_iter_get_basic(&id_struct, &idName);
        dbus_message_iter_next(&id_struct);
        if (dbus_message_iter_get_arg_type(&id_struct) != DBUS_TYPE_STRING) {
            fprintf(stderr, "Second ident struct arg not a string!\n");
            return 0;
        }
        dbus_message_iter_get_basic(&id_struct,
                                    &idCName);

        /* Read the secret blob data */
        dbus_message_iter_next(&sec_struct);
        dbus_message_iter_recurse(&sec_struct, &data_array);
        dbus_message_iter_get_fixed_array(&data_array,
                                          &data,
                                          &n_bytes);
        if (!data || !n_bytes) {
            fprintf(stderr, "Unable to read data from secret struct!\n");
            return 0;
        }

        /* Read the filter data */
        if (dbus_message_iter_has_next(&sec_struct)) {
            DBusMessageIter filter_dict;
            DBusMessageIter dict_entry;
            DBusMessageIter dict_val;
            char *field;
            char *value;
            struct Sailfish_Secrets_Secret_FilterDatum *prev = NULL;
            dbus_message_iter_next(&sec_struct);
            dbus_message_iter_recurse(&sec_struct, &filter_dict);
            while (dbus_message_iter_has_next(&filter_dict)) {
                dbus_message_iter_next(&filter_dict);
                dbus_message_iter_recurse(&filter_dict, &dict_entry);
                if (dbus_message_iter_get_arg_type(&dict_entry)
                        != DBUS_TYPE_STRING) {
                    if (first) {
                        Sailfish_Secrets_Secret_FilterDatum_delete(first);
                    }
                    fprintf(stderr, "Dict entry field not a string!\n");
                    return 0;
                }
                dbus_message_iter_get_basic(&dict_entry, &field);
                dbus_message_iter_next(&dict_entry);
                dbus_message_iter_recurse(&dict_entry, &dict_val);
                if (dbus_message_iter_get_arg_type(&dict_val)
                        != DBUS_TYPE_STRING) {
                    if (first) {
                        Sailfish_Secrets_Secret_FilterDatum_delete(first);
                    }
                    fprintf(stderr, "Dict value not a string!\n");
                    return 0;
                }
                dbus_message_iter_get_basic(&dict_val, &value);

                struct Sailfish_Secrets_Secret_FilterDatum *f =
                      Sailfish_Secrets_Secret_FilterDatum_new(field, value);
                if (prev) {
                    prev->next = f;
                } else {
                    first = f;
                }
                prev = f;
            }
        }

        struct Sailfish_Secrets_Secret *retn = Sailfish_Secrets_Secret_new(
                    data, n_bytes);
        struct Sailfish_Secrets_Secret_Identifier *ident =
                Sailfish_Secrets_Secret_Identifier_new(idName, idCName);
        retn->identifier = ident;
        retn->filterData = first;
        *secret = retn;
    }

    return 1;
}

/******************************* new / delete *******************************/

struct Sailfish_Secrets_Result*
Sailfish_Secrets_Result_new(
        enum Sailfish_Secrets_Result_Code code,
        int errorCode,
        const char *errorMessage)
{
    struct Sailfish_Secrets_Result *result =
            (struct Sailfish_Secrets_Result *)malloc(
                        sizeof(struct Sailfish_Secrets_Result));

    result->code = code;
    result->errorCode = errorCode;
    result->errorMessage = errorMessage ? strndup(errorMessage, 512) : NULL;
    return result;
}

void Sailfish_Secrets_Result_delete(
        struct Sailfish_Secrets_Result *result)
{
    if (result) {
        free(result->errorMessage);
        free(result);
    }
}

struct Sailfish_Secrets_Secret_Identifier*
Sailfish_Secrets_Secret_Identifier_new(
        const char *name,
        const char *collectionName)
{
    struct Sailfish_Secrets_Secret_Identifier *ident =
            (struct Sailfish_Secrets_Secret_Identifier*)malloc(
                        sizeof(struct Sailfish_Secrets_Secret_Identifier));

    ident->name = name
            ? strndup(name, 512)
            : NULL;
    ident->collectionName = collectionName
            ? strndup(collectionName, 512)
            : NULL;

    return ident;
}

void Sailfish_Secrets_Secret_Identifier_delete(
        struct Sailfish_Secrets_Secret_Identifier *ident)
{
    if (ident) {
        free(ident->name);
        free(ident->collectionName);
        free(ident);
    }
}

struct Sailfish_Secrets_Secret_FilterDatum*
Sailfish_Secrets_Secret_FilterDatum_new(
        const char *field,
        const char *value)
{
    struct Sailfish_Secrets_Secret_FilterDatum *filter =
            (struct Sailfish_Secrets_Secret_FilterDatum *)malloc(
                        sizeof(struct Sailfish_Secrets_Secret_FilterDatum));

    filter->field = field ? strndup(field, 512) : NULL;
    filter->value = value ? strndup(value, 512) : NULL;
    filter->next = NULL;

    return filter;
}

void Sailfish_Secrets_Secret_FilterDatum_delete(
        struct Sailfish_Secrets_Secret_FilterDatum *filter)
{
    if (filter) {
        struct Sailfish_Secrets_Secret_FilterDatum *curr = filter;
        struct Sailfish_Secrets_Secret_FilterDatum *next = filter->next
                ? filter->next : NULL;

        while (curr) {
            free(curr->field);
            free(curr->value);
            free(curr);
            curr = next;
            next = curr ? curr->next : NULL;
        }
    }
}

struct Sailfish_Secrets_Secret*
Sailfish_Secrets_Secret_new(
        const unsigned char *data,
        size_t dataSize)
{
    struct Sailfish_Secrets_Secret *secret =
            (struct Sailfish_Secrets_Secret *)malloc(
                        sizeof(struct Sailfish_Secrets_Secret));

    if (data) {
        secret->dataSize = dataSize;
        secret->data = (unsigned char *)malloc(dataSize);
        memcpy(secret->data, data, dataSize);
    } else {
        secret->dataSize = 0;
        secret->data = NULL;
    }

    secret->identifier = NULL;
    secret->filterData = NULL;

    return secret;
}

void Sailfish_Secrets_Secret_delete(
        struct Sailfish_Secrets_Secret *secret)
{
    if (secret) {
        Sailfish_Secrets_Secret_FilterDatum_delete(secret->filterData);
        Sailfish_Secrets_Secret_Identifier_delete(secret->identifier);
        free(secret->data);
        free(secret);
    }
}

void Sailfish_Secrets_Secret_setIdentifier(
        struct Sailfish_Secrets_Secret *secret,
        const char *name,
        const char *collectionName)
{
    if (secret && name && collectionName) {
        Sailfish_Secrets_Secret_Identifier_delete(secret->identifier);
        secret->identifier = Sailfish_Secrets_Secret_Identifier_new(
                    name, collectionName);
    }
}

void Sailfish_Secrets_Secret_addFilter(
        struct Sailfish_Secrets_Secret *secret,
        const char *field,
        const char *value)
{
    if (secret && field && value) {
        if (!secret->filterData) {
            secret->filterData = Sailfish_Secrets_Secret_FilterDatum_new(
                        field, value);
        } else {
            struct Sailfish_Secrets_Secret_FilterDatum *filter =
                    secret->filterData;
            while (filter->next) {
                filter = filter->next;
            }
            filter->next = Sailfish_Secrets_Secret_FilterDatum_new(
                        field, value);
        }
    }
}

/******************************* SecretManager ******************************/

int Sailfish_Secrets_SecretManager_createCollection(
        const char *collectionName,
        const char *storagePluginName,
        const char *encryptionPluginName,
        enum Sailfish_Secrets_SecretManager_DeviceLockUnlockSemantic unlockSemantic,
        enum Sailfish_Secrets_SecretManager_AccessControlMode accessControlMode,
        struct Sailfish_Secrets_Result **out_result)
{
    DBusMessageIter out_args;
    DBusMessageIter in_args;
    DBusMessageIter unlockSemantic_arg;
    DBusMessageIter accessControlMode_arg;
    int iUnlockSemantic = (int)(unlockSemantic);
    int iAccessControlMode = (int)(accessControlMode);

    if (collectionName == NULL
            || storagePluginName == NULL
            || encryptionPluginName == NULL
            || out_result == NULL
            || *out_result != NULL) {
        fprintf(stderr, "Invalid parameters!\n");
        return 0;
    }

    if (!Sailfish_Secrets__isConnectedToServer()) {
        if (!Sailfish_Secrets__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                      /* service name */
                "/Sailfish/Secrets",       /* object */
                "org.sailfishos.secrets",  /* interface */
                "createCollection");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);

    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &collectionName);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &storagePluginName);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &encryptionPluginName);
    Sailfish_Secrets__appendEnumArg(
                &in_args,
                &unlockSemantic_arg,
                &iUnlockSemantic);
    Sailfish_Secrets__appendEnumArg(
                &in_args,
                &accessControlMode_arg,
                &iAccessControlMode);

    /* send message and get a handle for a reply */
    dbus_connection_send_with_reply(
                daemon_connection.p2pBus,
                daemon_connection.msg,
                &daemon_connection.pending,
                -1);

    if (daemon_connection.pending == NULL) {
        fprintf(stderr, "Pending Call Null\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_connection_flush(daemon_connection.p2pBus);
    dbus_message_unref(daemon_connection.msg);
    dbus_pending_call_block(daemon_connection.pending);
    daemon_connection.msg = dbus_pending_call_steal_reply(
                daemon_connection.pending);
    dbus_pending_call_unref(daemon_connection.pending);
    daemon_connection.pending = NULL;

    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Reply Null\n");
        return 0;
    }

    /* read the return argument */
    if (!dbus_message_iter_init(daemon_connection.msg,
                                &out_args)) {
        fprintf(stderr, "Message has no arguments!\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    if (!Sailfish_Secrets__readResultStruct(&out_args, out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Secrets_SecretManager_deleteCollection(
        const char *collectionName,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
        struct Sailfish_Secrets_Result **out_result)
{
    DBusMessageIter out_args;
    DBusMessageIter in_args;
    DBusMessageIter uiMode_arg;
    int iUiMode = (int)(uiMode);

    if (collectionName == NULL
            || out_result == NULL
            || *out_result != NULL) {
        fprintf(stderr, "Invalid parameters!\n");
        return 0;
    }

    if (!Sailfish_Secrets__isConnectedToServer()) {
        if (!Sailfish_Secrets__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                      /* service name */
                "/Sailfish/Secrets",       /* object */
                "org.sailfishos.secrets",  /* interface */
                "deleteCollection");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);

    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &collectionName);
    Sailfish_Secrets__appendEnumArg(
                &in_args,
                &uiMode_arg,
                &iUiMode);

    /* send message and get a handle for a reply */
    dbus_connection_send_with_reply(
                daemon_connection.p2pBus,
                daemon_connection.msg,
                &daemon_connection.pending,
                -1);

    if (daemon_connection.pending == NULL) {
        fprintf(stderr, "Pending Call Null\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_connection_flush(daemon_connection.p2pBus);
    dbus_message_unref(daemon_connection.msg);
    dbus_pending_call_block(daemon_connection.pending);
    daemon_connection.msg = dbus_pending_call_steal_reply(
                daemon_connection.pending);
    dbus_pending_call_unref(daemon_connection.pending);
    daemon_connection.pending = NULL;

    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Reply Null\n");
        return 0;
    }

    /* read the return argument */
    if (!dbus_message_iter_init(daemon_connection.msg,
                                &out_args)) {
        fprintf(stderr, "Message has no arguments!\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    if (!Sailfish_Secrets__readResultStruct(&out_args, out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Secrets_SecretManager_setSecret(
        struct Sailfish_Secrets_Secret *secret,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
        const char *uiServiceAddress,
        struct Sailfish_Secrets_Result **out_result)
{
    DBusMessageIter out_args;
    DBusMessageIter in_args;
    DBusMessageIter uiMode_arg;
    int iUiMode = (int)(uiMode);

    if (secret == NULL
            || uiServiceAddress == NULL
            || out_result == NULL
            || *out_result != NULL) {
        fprintf(stderr, "Invalid parameters!\n");
        return 0;
    }

    if (!Sailfish_Secrets__isConnectedToServer()) {
        if (!Sailfish_Secrets__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                      /* service name */
                "/Sailfish/Secrets",       /* object */
                "org.sailfishos.secrets",  /* interface */
                "setSecret");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Secrets__appendSecretArg(
                &in_args,
                secret);
    Sailfish_Secrets__appendEnumArg(
                &in_args,
                &uiMode_arg,
                &iUiMode);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &uiServiceAddress);

    /* send message and get a handle for a reply */
    dbus_connection_send_with_reply(
                daemon_connection.p2pBus,
                daemon_connection.msg,
                &daemon_connection.pending,
                -1);

    if (daemon_connection.pending == NULL) {
        fprintf(stderr, "Pending Call Null\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_connection_flush(daemon_connection.p2pBus);
    dbus_message_unref(daemon_connection.msg);
    dbus_pending_call_block(daemon_connection.pending);
    daemon_connection.msg = dbus_pending_call_steal_reply(
                daemon_connection.pending);
    dbus_pending_call_unref(daemon_connection.pending);
    daemon_connection.pending = NULL;

    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Reply Null\n");
        return 0;
    }

    /* read the return argument */
    if (!dbus_message_iter_init(daemon_connection.msg,
                                &out_args)) {
        fprintf(stderr, "Message has no arguments!\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    if (!Sailfish_Secrets__readResultStruct(&out_args, out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Secrets_SecretManager_getSecret(
        struct Sailfish_Secrets_Secret_Identifier *ident,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
        const char *uiServiceAddress,
        struct Sailfish_Secrets_Result **out_result,
        struct Sailfish_Secrets_Secret **out_secret)
{
    DBusMessageIter out_args;
    DBusMessageIter in_args;
    DBusMessageIter uiMode_arg;
    int iUiMode = (int)(uiMode);

    if (ident == NULL
            || uiServiceAddress == NULL
            || out_result == NULL
            || out_secret == NULL
            || *out_result != NULL
            || *out_secret != NULL) {
        fprintf(stderr, "Invalid parameters!\n");
        return 0;
    }

    if (!Sailfish_Secrets__isConnectedToServer()) {
        if (!Sailfish_Secrets__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                      /* service name */
                "/Sailfish/Secrets",       /* object */
                "org.sailfishos.secrets",  /* interface */
                "getSecret");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Secrets__appendSecretIdentifierArg(
                &in_args,
                ident);
    Sailfish_Secrets__appendEnumArg(
                &in_args,
                &uiMode_arg,
                &iUiMode);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &uiServiceAddress);

    /* send message and get a handle for a reply */
    dbus_connection_send_with_reply(
                daemon_connection.p2pBus,
                daemon_connection.msg,
                &daemon_connection.pending,
                -1);

    if (daemon_connection.pending == NULL) {
        fprintf(stderr, "Pending Call Null\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_connection_flush(daemon_connection.p2pBus);
    dbus_message_unref(daemon_connection.msg);
    dbus_pending_call_block(daemon_connection.pending);
    daemon_connection.msg = dbus_pending_call_steal_reply(
                daemon_connection.pending);
    dbus_pending_call_unref(daemon_connection.pending);
    daemon_connection.pending = NULL;

    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Reply Null\n");
        return 0;
    }

    /* read the return arguments */
    if (!dbus_message_iter_init(daemon_connection.msg,
                                &out_args)) {
        fprintf(stderr, "Message has no arguments!\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    if (!Sailfish_Secrets__readResultStruct(&out_args, out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);

    if (!Sailfish_Secrets__readSecretStruct(&out_args, out_secret)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Secrets_SecretManager_deleteSecret(
        struct Sailfish_Secrets_Secret_Identifier *ident,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
        const char *uiServiceAddress,
        struct Sailfish_Secrets_Result **out_result)
{
    DBusMessageIter out_args;
    DBusMessageIter in_args;
    DBusMessageIter uiMode_arg;
    int iUiMode = (int)(uiMode);

    if (ident == NULL
            || uiServiceAddress == NULL
            || out_result == NULL
            || *out_result != NULL) {
        fprintf(stderr, "Invalid parameters!\n");
        return 0;
    }

    if (!Sailfish_Secrets__isConnectedToServer()) {
        if (!Sailfish_Secrets__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                      /* service name */
                "/Sailfish/Secrets",       /* object */
                "org.sailfishos.secrets",  /* interface */
                "deleteSecret");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Secrets__appendSecretIdentifierArg(
                &in_args,
                ident);
    Sailfish_Secrets__appendEnumArg(
                &in_args,
                &uiMode_arg,
                &iUiMode);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &uiServiceAddress);

    /* send message and get a handle for a reply */
    dbus_connection_send_with_reply(
                daemon_connection.p2pBus,
                daemon_connection.msg,
                &daemon_connection.pending,
                -1);

    if (daemon_connection.pending == NULL) {
        fprintf(stderr, "Pending Call Null\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_connection_flush(daemon_connection.p2pBus);
    dbus_message_unref(daemon_connection.msg);
    dbus_pending_call_block(daemon_connection.pending);
    daemon_connection.msg = dbus_pending_call_steal_reply(
                daemon_connection.pending);
    dbus_pending_call_unref(daemon_connection.pending);
    daemon_connection.pending = NULL;

    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Reply Null\n");
        return 0;
    }

    /* read the return argument */
    if (!dbus_message_iter_init(daemon_connection.msg,
                                &out_args)) {
        fprintf(stderr, "Message has no arguments!\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    if (!Sailfish_Secrets__readResultStruct(&out_args, out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}
