/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/crypto_c.h"
#include "Crypto/key.h"

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <QVector>
#include <QMap>

#include <dbus/dbus.h>
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static int Sailfish_Crypto__getServerPeerToPeerAddress(
        char ** p2pAddr,
        DBusConnection **sessionBus)
{
    DBusMessage* msg;
    DBusMessageIter args;
    DBusError err;
    DBusPendingCall* pending;
    char *param = NULL;

    if (p2pAddr == NULL || sessionBus == NULL) {
        fprintf(stderr, "Invalid parameters, cannot get p2p address!\n");
        return 0;
    }

    /* initialise the error */
    dbus_error_init(&err);

    /* connect to the session bus */
    *sessionBus = dbus_bus_get(DBUS_BUS_SESSION, &err);
    if (dbus_error_is_set(&err)) {
        fprintf(stderr, "Connection Error (%s)\n", err.message);
        dbus_error_free(&err);
        *sessionBus = NULL;
    }
    if (*sessionBus == NULL) {
        return 0;
    }

    /* create a new method call and check for errors */
    msg = dbus_message_new_method_call(
                "org.sailfishos.crypto.daemon.discovery",
                "/Sailfish/Crypto/Discovery",
                "org.sailfishos.crypto.daemon.discovery",
                "peerToPeerAddress");
    if (msg == NULL) {
        fprintf(stderr, "Message Null\n");
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
        return 0;
    }

    /* read the address return argument */
    if (!dbus_message_iter_init(msg, &args)) {
        fprintf(stderr, "Message has no arguments!\n");
        dbus_message_unref(msg);
        return 0;
    } else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) {
        fprintf(stderr, "Argument is not string!\n");
        dbus_message_unref(msg);
        return 0;
    } else {
        dbus_message_iter_get_basic(&args, &param);
    }

    if (param == NULL) {
        fprintf(stderr, "Unable to read peer to peer address value!\n");
        dbus_message_unref(msg);
        return 0;
    }

    *p2pAddr = strdup(param);
    dbus_message_unref(msg);

    return 1;
}

static struct Sailfish_Crypto_DBus_Connection {
    DBusConnection *sessionBus;
    DBusConnection* p2pBus;
    DBusMessage* msg;
    DBusPendingCall* pending;
    char* p2pAddr;
} daemon_connection = {
    .sessionBus = NULL,
    .p2pBus = NULL,
    .msg = NULL,
    .pending = NULL,
    .p2pAddr = NULL
};

static int Sailfish_Crypto__isConnectedToServer()
{
    return daemon_connection.p2pBus == NULL ? 0 : 1;
}

static int Sailfish_Crypto__connectToServer()
{
    DBusError daemon_connection_err;

    if (daemon_connection.p2pBus != NULL) {
        fprintf(stderr, "Already connected to crypto daemon!\n");
        return 1; /* Return "ok" */
    }

    /* Get the peer to peer address of the daemon via the session bus */
    if (!daemon_connection.p2pAddr &&
            !Sailfish_Crypto__getServerPeerToPeerAddress(
                &daemon_connection.p2pAddr,
                &daemon_connection.sessionBus)) {
        return 0;
    }

    /* initialise the error */
    dbus_error_init(&daemon_connection_err);

    /* Open a private peer to peer connection to the daemon */
    daemon_connection.p2pBus = dbus_connection_open_private(
                daemon_connection.p2pAddr,
                &daemon_connection_err);
    if (dbus_error_is_set(&daemon_connection_err)) {
        fprintf(stderr,
                "Connection Error (%s) to: %s\n",
                daemon_connection_err.message,
                daemon_connection.p2pAddr);
        dbus_error_free(&daemon_connection_err);
    }
    if (daemon_connection.p2pBus == NULL) {
        return 0;
    }

    return 1;
}

void Sailfish_Crypto_disconnectFromServer()
{
    if (daemon_connection.p2pBus) {
        dbus_connection_close(daemon_connection.p2pBus);
        dbus_connection_unref(daemon_connection.p2pBus);
        daemon_connection.p2pBus = NULL;
        free(daemon_connection.p2pAddr);
        daemon_connection.p2pAddr = NULL;
    }
}

static void Sailfish_Crypto__appendEnumArg(
        DBusMessageIter *in_args,
        int *arg)
{
    DBusMessageIter enum_struct;
    dbus_message_iter_open_container(
                in_args,
                DBUS_TYPE_STRUCT,
                NULL,
                &enum_struct);
    dbus_message_iter_append_basic(
                &enum_struct,
                DBUS_TYPE_INT32,
                arg);
    dbus_message_iter_close_container(
                in_args,
                &enum_struct);
}

static void Sailfish_Crypto__appendDataArg(
        DBusMessageIter *in_args,
        const unsigned char *data,
        size_t dataSize)
{
    DBusMessageIter data_array;
    dbus_message_iter_open_container(
                in_args,
                DBUS_TYPE_ARRAY,
                "y",
                &data_array);
    dbus_message_iter_append_fixed_array(
                &data_array,
                DBUS_TYPE_BYTE,
                &data,
                dataSize);
    dbus_message_iter_close_container(
                in_args,
                &data_array);
}

static void Sailfish_Crypto__appendKeyIdentifierArg(
        DBusMessageIter *args,
        struct Sailfish_Crypto_Key_Identifier *ident)
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

static void Sailfish_Crypto__appendKeyArg(
        DBusMessageIter *in_args,
        struct Sailfish_Crypto_Key *key)
{
    DBusMessageIter key_struct;
    DBusMessageIter data_array;

    /* Convert the key to the C++ form so we can serialise it properly */
    Sailfish::Crypto::Key cppKey;
    cppKey.setIdentifier(Sailfish::Crypto::Key::Identifier(
                QLatin1String(key->identifier->name),
                QLatin1String(key->identifier->collectionName)));
    cppKey.setOrigin(static_cast<Sailfish::Crypto::Key::Origin>(
                key->origin));
    cppKey.setAlgorithm(static_cast<Sailfish::Crypto::Key::Algorithm>(
                key->algorithm));
    cppKey.setBlockModes(static_cast<Sailfish::Crypto::Key::BlockModes>(
                key->blockModes));
    cppKey.setEncryptionPaddings(
                static_cast<Sailfish::Crypto::Key::EncryptionPaddings>(
                key->encryptionPaddings));
    cppKey.setSignaturePaddings(
                static_cast<Sailfish::Crypto::Key::SignaturePaddings>(
                key->signaturePaddings));
    cppKey.setDigests(static_cast<Sailfish::Crypto::Key::Digests>(
                key->digests));
    cppKey.setOperations(static_cast<Sailfish::Crypto::Key::Operations>(
                key->operations));
    cppKey.setSecretKey(QByteArray((const char *)key->secretKey,
                                   (int)key->secretKeySize));
    cppKey.setPrivateKey(QByteArray((const char *)key->privateKey,
                                    (int)key->privateKeySize));
    cppKey.setPublicKey(QByteArray((const char *)key->publicKey,
                                   (int)key->publicKeySize));
    cppKey.setValidityStart(QDateTime::fromTime_t(key->validityStart));
    cppKey.setValidityEnd(QDateTime::fromTime_t(key->validityEnd));
    QVector<QByteArray> cppKeyCp;
    struct Sailfish_Crypto_Key_CustomParameter *currParameter =
                key->customParameters;
    while (currParameter) {
        QByteArray cpdata((const char *)currParameter->parameter,
                          (int)currParameter->parameterSize);
        cppKeyCp.append(cpdata);
        currParameter = currParameter->next;
    }
    cppKey.setCustomParameters(cppKeyCp);
    QMap<QString,QString> cppKeyFd;
    struct Sailfish_Crypto_Key_FilterDatum *currFilter = key->filterData;
    while (currFilter) {
        QByteArray fielddata(currFilter->field);
        QByteArray valuedata(currFilter->value);
        cppKeyFd.insert(QString(fielddata), QString(valuedata));
        currFilter = currFilter->next;
    }
    cppKey.setFilterData(cppKeyFd);
    QByteArray keyData = Sailfish::Crypto::Key::serialise(
                cppKey, Sailfish::Crypto::Key::LosslessSerialisationMode);
    const char *keyDataPtr = keyData.data();

    /* Now marshal it for dbus */
    dbus_message_iter_open_container(
                in_args,
                DBUS_TYPE_STRUCT,
                NULL,
                &key_struct);

    dbus_message_iter_open_container(
                &key_struct,
                DBUS_TYPE_ARRAY,
                "y",
                &data_array);

    dbus_message_iter_append_fixed_array(
                &data_array,
                DBUS_TYPE_BYTE,
                &keyDataPtr,
                keyData.size());

    dbus_message_iter_close_container(
                &key_struct,
                &data_array);

    dbus_message_iter_close_container(
                in_args,
                &key_struct);
}

static int Sailfish_Crypto__readResultStruct(
        DBusMessageIter *args,
        struct Sailfish_Crypto_Result **result)
{
    if (args == NULL || result == NULL || *result != NULL) {
        fprintf(stderr, "Cannot read result: invalid parameters!\n");
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
        int storageErrorCode;
        const char *errorMessage;

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

        if (dbus_message_iter_get_arg_type(&res_struct) != DBUS_TYPE_INT32) {
            fprintf(stderr, "Third result struct arg not an integer!\n");
            return 0;
        }

        dbus_message_iter_get_basic(&res_struct, &storageErrorCode);

        dbus_message_iter_next(&res_struct);

        if (dbus_message_iter_get_arg_type(&res_struct) != DBUS_TYPE_STRING) {
            fprintf(stderr, "Fourth result struct arg not a string!\n");
            return 0;
        }

        dbus_message_iter_get_basic(&res_struct, &errorMessage);

        *result = Sailfish_Crypto_Result_new(
                    (Sailfish_Crypto_Result_Code)code,
                    errorCode, storageErrorCode, errorMessage);
    }

    return 1;
}

static int Sailfish_Crypto__readKeyStruct(
        DBusMessageIter *args,
        struct Sailfish_Crypto_Key **key)
{
    if (args == NULL || key == NULL || *key != NULL) {
        fprintf(stderr, "Cannot read key: invalid parameters!\n");
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
        DBusMessageIter key_struct;
        DBusMessageIter data_array;
        unsigned char *data = NULL;
        int n_bytes = 0;

        /* Read the key blob data */
        dbus_message_iter_recurse(args, &key_struct);
        dbus_message_iter_recurse(&key_struct, &data_array);
        dbus_message_iter_get_fixed_array(&data_array,
                                          &data,
                                          &n_bytes);
        if (!data || !n_bytes) {
            fprintf(stderr, "Unable to read data from key struct!\n");
            return 0;
        }

        /* Convert the key blob data into a key */
        QByteArray cppKeyData((const char *)data, n_bytes);
        bool ok = true;
        Sailfish::Crypto::Key cppKey(Sailfish::Crypto::Key::deserialise(
                                         cppKeyData, &ok));
        if (!ok) {
            fprintf(stderr, "Unable to deserialise key data!\n");
            return 0;
        }

        Sailfish_Crypto_Key *retn = Sailfish_Crypto_Key_new(
                cppKey.identifier().name().toLatin1().constData(),
                cppKey.identifier().collectionName().toLatin1().constData());
        retn->origin = (Sailfish_Crypto_Key_Origin)cppKey.origin();
        retn->algorithm = (Sailfish_Crypto_Key_Algorithm)cppKey.algorithm();
        retn->blockModes = (int)cppKey.blockModes();
        retn->encryptionPaddings = (int)cppKey.encryptionPaddings();
        retn->signaturePaddings = (int)cppKey.signaturePaddings();
        retn->digests = (int)cppKey.digests();
        retn->operations = (int)cppKey.operations();
        retn->validityStart = cppKey.validityStart().toTime_t();
        retn->validityEnd = cppKey.validityEnd().toTime_t();
        Sailfish_Crypto_Key_setSecretKey(retn,
                                         (const unsigned char *)
                                            cppKey.secretKey().constData(),
                                         cppKey.secretKey().size());
        Sailfish_Crypto_Key_setPublicKey(retn,
                                         (const unsigned char *)
                                            cppKey.publicKey().constData(),
                                         cppKey.publicKey().size());
        Sailfish_Crypto_Key_setPrivateKey(retn,
                                          (const unsigned char *)
                                            cppKey.privateKey().constData(),
                                          cppKey.privateKey().size());
        for (const QByteArray &customParameter : cppKey.customParameters()) {
            Sailfish_Crypto_Key_addCustomParameter(
                        retn,
                        (const unsigned char *)customParameter.constData(),
                        customParameter.size());
        }
        const QMap<QString, QString> filterData = cppKey.filterData();
        for (QMap<QString, QString>::const_iterator
             it = filterData.constBegin(); it != filterData.constEnd(); it++) {
            Sailfish_Crypto_Key_addFilter(
                        retn,
                        it.key().toLatin1().constData(),
                        it.value().toLatin1().constData());
        }
        *key = retn;
    }

    return 1;
}

/******************************* Methods ************************************/

struct Sailfish_Crypto_Result*
Sailfish_Crypto_Result_new(
        enum Sailfish_Crypto_Result_Code code,
        int errorCode,
        int storageErrorCode,
        const char *errorMessage)
{
    struct Sailfish_Crypto_Result *result =
            (struct Sailfish_Crypto_Result *)malloc(
                        sizeof(struct Sailfish_Crypto_Result));

    result->code = code;
    result->errorCode = errorCode;
    result->storageErrorCode = storageErrorCode;
    result->errorMessage = errorMessage ? strndup(errorMessage, 512) : NULL;
    return result;
}

void Sailfish_Crypto_Result_delete(
        struct Sailfish_Crypto_Result *result)
{
    if (result) {
        free(result->errorMessage);
        free(result);
    }
}

struct Sailfish_Crypto_Key_Identifier*
Sailfish_Crypto_Key_Identifier_new(
        const char *name,
        const char *collectionName)
{
    struct Sailfish_Crypto_Key_Identifier *ident =
            (struct Sailfish_Crypto_Key_Identifier*)malloc(
                        sizeof(struct Sailfish_Crypto_Key_Identifier));

    ident->name = name
            ? strndup(name, 512)
            : NULL;
    ident->collectionName = collectionName
            ? strndup(collectionName, 512)
            : NULL;

    return ident;
}

void Sailfish_Crypto_Key_Identifier_delete(
        struct Sailfish_Crypto_Key_Identifier *ident)
{
    if (ident) {
        free(ident->name);
        free(ident->collectionName);
        free(ident);
    }
}

struct Sailfish_Crypto_Key_FilterDatum*
Sailfish_Crypto_Key_FilterDatum_new(
        const char *field,
        const char *value)
{
    struct Sailfish_Crypto_Key_FilterDatum *filter =
            (struct Sailfish_Crypto_Key_FilterDatum *)malloc(
                        sizeof(struct Sailfish_Crypto_Key_FilterDatum));

    filter->field = field ? strndup(field, 512) : NULL;
    filter->value = value ? strndup(value, 512) : NULL;
    filter->next = NULL;

    return filter;
}

void Sailfish_Crypto_Key_FilterDatum_delete(
        struct Sailfish_Crypto_Key_FilterDatum *filter)
{
    if (filter) {
        struct Sailfish_Crypto_Key_FilterDatum *curr = filter;
        struct Sailfish_Crypto_Key_FilterDatum *next = filter->next
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

struct Sailfish_Crypto_Key_CustomParameter*
Sailfish_Crypto_Key_CustomParameter_new(
        const unsigned char *parameter,
        size_t parameterSize)
{
    if (parameter && parameterSize) {
        struct Sailfish_Crypto_Key_CustomParameter *param =
                (struct Sailfish_Crypto_Key_CustomParameter *)malloc(
                            sizeof(struct Sailfish_Crypto_Key_CustomParameter));

        param->parameter = (unsigned char *)malloc(parameterSize);
        memcpy(param->parameter, parameter, parameterSize);
        param->parameterSize = parameterSize;
        param->next = NULL;

        return param;
    }

    return NULL;
}

void Sailfish_Crypto_Key_CustomParameter_delete(
        struct Sailfish_Crypto_Key_CustomParameter *param)
{
    if (param) {
        struct Sailfish_Crypto_Key_CustomParameter *curr = param;
        struct Sailfish_Crypto_Key_CustomParameter *next = param->next
                ? param->next : NULL;

        while (curr) {
            free(curr->parameter);
            free(curr);
            curr = next;
            next = curr ? curr->next : NULL;
        }
    }
}

struct Sailfish_Crypto_Key*
Sailfish_Crypto_Key_new(
        const char *name,
        const char *collectionName)
{
    struct Sailfish_Crypto_Key* key =
            (struct Sailfish_Crypto_Key*)malloc(
                        sizeof(struct Sailfish_Crypto_Key));

    key->identifier = Sailfish_Crypto_Key_Identifier_new(
            name, collectionName);

    key->secretKey = NULL;
    key->publicKey = NULL;
    key->privateKey = NULL;
    key->customParameters = NULL;
    key->filterData = NULL;

    key->origin = Sailfish_Crypto_Key_OriginUnknown;
    key->algorithm = Sailfish_Crypto_Key_AlgorithmUnknown;
    key->blockModes = Sailfish_Crypto_Key_BlockModeUnknown;
    key->encryptionPaddings = Sailfish_Crypto_Key_EncryptionPaddingUnknown;
    key->signaturePaddings = Sailfish_Crypto_Key_SignaturePaddingUnknown;
    key->digests = Sailfish_Crypto_Key_DigestUnknown;
    key->operations = Sailfish_Crypto_Key_OperationUnknown;

    return key;
}

void Sailfish_Crypto_Key_setPrivateKey(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *privateKey,
        size_t privateKeySize)
{
    if (key) {
        free(key->privateKey);
        if (privateKeySize && privateKey) {
            key->privateKeySize = privateKeySize;
            key->privateKey = (unsigned char *)malloc(privateKeySize);
            memcpy(key->privateKey, privateKey, privateKeySize);
        } else {
            key->privateKeySize = 0;
            key->privateKey = NULL;
        }
    }
}

void Sailfish_Crypto_Key_setPublicKey(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *publicKey,
        size_t publicKeySize)
{
    if (key) {
        free(key->publicKey);
        if (publicKeySize && publicKey) {
            key->publicKeySize = publicKeySize;
            key->publicKey = (unsigned char *)malloc(publicKeySize);
            memcpy(key->publicKey, publicKey, publicKeySize);
        } else {
            key->publicKeySize = 0;
            key->publicKey = NULL;
        }
    }
}

void Sailfish_Crypto_Key_setSecretKey(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *secretKey,
        size_t secretKeySize)
{
    if (key) {
        free(key->secretKey);
        if (secretKeySize && secretKey) {
            key->secretKeySize = secretKeySize;
            key->secretKey = (unsigned char *)malloc(secretKeySize);
            memcpy(key->secretKey, secretKey, secretKeySize);
        } else {
            key->secretKeySize = 0;
            key->secretKey = NULL;
        }
    }
}

void Sailfish_Crypto_Key_addFilter(
        struct Sailfish_Crypto_Key *key,
        const char *field,
        const char *value)
{
    if (key && field && value) {
        if (!key->filterData) {
            key->filterData = Sailfish_Crypto_Key_FilterDatum_new(
                        field, value);
        } else {
            struct Sailfish_Crypto_Key_FilterDatum *filter =
                    key->filterData;
            while (filter->next) {
                filter = filter->next;
            }
            filter->next = Sailfish_Crypto_Key_FilterDatum_new(
                        field, value);
        }
    }
}

void Sailfish_Crypto_Key_addCustomParameter(
        struct Sailfish_Crypto_Key *key,
        const unsigned char *parameter,
        size_t parameterSize)
{
    if (key && parameter && parameterSize) {
        if (!key->customParameters) {
            key->customParameters = Sailfish_Crypto_Key_CustomParameter_new(
                        parameter, parameterSize);
        } else {
            struct Sailfish_Crypto_Key_CustomParameter *param =
                    key->customParameters;
            while (param->next) {
                param = param->next;
            }
            param->next = Sailfish_Crypto_Key_CustomParameter_new(
                        parameter, parameterSize);
        }
    }
}

void Sailfish_Crypto_Key_delete(
        struct Sailfish_Crypto_Key *key)
{
    if (key) {
        Sailfish_Crypto_Key_Identifier_delete(key->identifier);
        Sailfish_Crypto_Key_CustomParameter_delete(key->customParameters);
        Sailfish_Crypto_Key_FilterDatum_delete(key->filterData);
        free(key->publicKey);
        free(key->privateKey);
        free(key->secretKey);
        free(key);
    }
}

/****************************** Crypto Manager ******************************/

int Sailfish_Crypto_CryptoManager_generateKey(
        struct Sailfish_Crypto_Key *keyTemplate,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        struct Sailfish_Crypto_Key **out_key)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;

    if (keyTemplate == NULL
            || cryptosystemProviderName == NULL
            || out_result == NULL
            || out_key == NULL
            || *out_result != NULL
            || *out_key != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "generateKey");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendKeyArg(
                &in_args,
                keyTemplate);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &cryptosystemProviderName);

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
    if (!dbus_message_iter_init(daemon_connection.msg, &out_args)) {
        fprintf(stderr, "Message has no arguments!\n");
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    if (!Sailfish_Crypto__readResultStruct(&out_args, out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);

    if (!Sailfish_Crypto__readKeyStruct(&out_args, out_key)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Crypto_CryptoManager_generateStoredKey(
        struct Sailfish_Crypto_Key *keyTemplate,
        const char *cryptosystemProviderName,
        const char *storageProviderName,
        struct Sailfish_Crypto_Result **out_result,
        struct Sailfish_Crypto_Key **out_keyReference)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;

    if (keyTemplate == NULL
            || cryptosystemProviderName == NULL
            || storageProviderName == NULL
            || out_result == NULL
            || out_keyReference == NULL
            || *out_result != NULL
            || *out_keyReference != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "generateStoredKey");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendKeyArg(
                &in_args,
                keyTemplate);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &cryptosystemProviderName);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &storageProviderName);

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

    if (!Sailfish_Crypto__readResultStruct(&out_args,
                                           out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);

    if (!Sailfish_Crypto__readKeyStruct(&out_args,
                                        out_keyReference)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Crypto_CryptoManager_storedKey(
        struct Sailfish_Crypto_Key_Identifier *ident,
        struct Sailfish_Crypto_Result **out_result,
        struct Sailfish_Crypto_Key **out_key)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;

    if (ident == NULL
            || out_result == NULL
            || out_key == NULL
            || *out_result != NULL
            || *out_key != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "storedKey");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendKeyIdentifierArg(
                &in_args,
                ident);

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

    if (!Sailfish_Crypto__readResultStruct(&out_args,
                                           out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);

    if (!Sailfish_Crypto__readKeyStruct(&out_args, out_key)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Crypto_CryptoManager_deleteStoredKey(
        struct Sailfish_Crypto_Key_Identifier *ident,
        struct Sailfish_Crypto_Result **out_result)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;

    if (ident == NULL
            || out_result == NULL
            || *out_result != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "deleteStoredKey");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendKeyIdentifierArg(
                &in_args,
                ident);

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

    if (!Sailfish_Crypto__readResultStruct(&out_args,
                                           out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Crypto_CryptoManager_sign(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        Sailfish_Crypto_Key_SignaturePadding padding,
        Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        unsigned char **out_signature,
        size_t *out_signature_size)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;
    DBusMessageIter sig_array;

    int iPadding = (int)padding;
    int iDigest = (int)digest;

    unsigned char *out_sig = NULL;
    int out_sig_size = 0;

    if (data == NULL
            || key == NULL
            || cryptosystemProviderName == NULL
            || out_result == NULL
            || out_signature == NULL
            || out_signature_size == NULL
            || *out_result != NULL
            || *out_signature != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "sign");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendDataArg(&in_args, data, dataSize);
    Sailfish_Crypto__appendKeyArg(&in_args, key);
    Sailfish_Crypto__appendEnumArg(&in_args, &iPadding);
    Sailfish_Crypto__appendEnumArg(&in_args, &iDigest);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &cryptosystemProviderName);

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

    if (!Sailfish_Crypto__readResultStruct(&out_args,
                                           out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);

    dbus_message_iter_recurse(&out_args, &sig_array);
    dbus_message_iter_get_fixed_array(&sig_array,
                                      &out_sig,
                                      &out_sig_size);

    *out_signature_size = (size_t)out_sig_size;
    *out_signature = (unsigned char *)malloc(*out_signature_size);
    memcpy(*out_signature, out_sig, *out_signature_size);

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Crypto_CryptoManager_verify(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        Sailfish_Crypto_Key_SignaturePadding padding,
        Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        int *out_verified)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;
    dbus_bool_t verified = FALSE;

    int iPadding = (int)padding;
    int iDigest = (int)digest;

    if (data == NULL
            || key == NULL
            || cryptosystemProviderName == NULL
            || out_result == NULL
            || out_verified == NULL
            || *out_result != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "verify");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendDataArg(&in_args, data, dataSize);
    Sailfish_Crypto__appendKeyArg(&in_args, key);
    Sailfish_Crypto__appendEnumArg(&in_args, &iPadding);
    Sailfish_Crypto__appendEnumArg(&in_args, &iDigest);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &cryptosystemProviderName);

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

    if (!Sailfish_Crypto__readResultStruct(&out_args,
                                           out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);
    dbus_message_iter_get_basic(&out_args, &verified);
    *out_verified = (verified == TRUE) ? 1 : 0;

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Crypto_CryptoManager_encrypt(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        Sailfish_Crypto_Key_BlockMode blockMode,
        Sailfish_Crypto_Key_EncryptionPadding padding,
        Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        unsigned char **out_ciphertext,
        size_t *out_ciphertext_size)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;
    DBusMessageIter ciphertext_array;

    int iBlockMode = (int)blockMode;
    int iPadding = (int)padding;
    int iDigest = (int)digest;

    unsigned char *out_ciph = NULL;
    int out_ciph_size = 0;

    if (data == NULL
            || key == NULL
            || cryptosystemProviderName == NULL
            || out_result == NULL
            || out_ciphertext == NULL
            || out_ciphertext_size == NULL
            || *out_result != NULL
            || *out_ciphertext != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "encrypt");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendDataArg(&in_args, data, dataSize);
    Sailfish_Crypto__appendKeyArg(&in_args, key);
    Sailfish_Crypto__appendEnumArg(&in_args, &iBlockMode);
    Sailfish_Crypto__appendEnumArg(&in_args, &iPadding);
    Sailfish_Crypto__appendEnumArg(&in_args, &iDigest);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &cryptosystemProviderName);

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

    if (!Sailfish_Crypto__readResultStruct(&out_args,
                                           out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);

    dbus_message_iter_recurse(&out_args, &ciphertext_array);
    dbus_message_iter_get_fixed_array(&ciphertext_array,
                                      &out_ciph,
                                      &out_ciph_size);

    *out_ciphertext_size = (size_t)out_ciph_size;
    *out_ciphertext = (unsigned char *)malloc(*out_ciphertext_size);
    memcpy(*out_ciphertext, out_ciph, *out_ciphertext_size);

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}

int Sailfish_Crypto_CryptoManager_decrypt(
        const unsigned char *data,
        size_t dataSize,
        struct Sailfish_Crypto_Key *key,
        Sailfish_Crypto_Key_BlockMode blockMode,
        Sailfish_Crypto_Key_EncryptionPadding padding,
        Sailfish_Crypto_Key_Digest digest,
        const char *cryptosystemProviderName,
        struct Sailfish_Crypto_Result **out_result,
        unsigned char **out_plaintext,
        size_t *out_plaintext_size)
{
    DBusMessageIter in_args;
    DBusMessageIter out_args;
    DBusMessageIter plaintext_array;

    int iBlockMode = (int)blockMode;
    int iPadding = (int)padding;
    int iDigest = (int)digest;

    unsigned char *out_pt = NULL;
    int out_pt_size = 0;

    if (data == NULL
            || key == NULL
            || cryptosystemProviderName == NULL
            || out_result == NULL
            || out_plaintext == NULL
            || out_plaintext_size == NULL
            || *out_result != NULL
            || *out_plaintext != NULL) {
        fprintf(stderr, "Invalid paramaters!\n");
        return 0;
    }

    if (!Sailfish_Crypto__isConnectedToServer()) {
        if (!Sailfish_Crypto__connectToServer()) {
            return 0;
        }
    }

    /* create a new method call and check for errors */
    daemon_connection.msg = dbus_message_new_method_call(
                NULL,                     /* service name */
                "/Sailfish/Crypto",       /* object */
                "org.sailfishos.crypto",  /* interface */
                "decrypt");
    if (daemon_connection.msg == NULL) {
        fprintf(stderr, "Message Null\n");
        return 0;
    }

    /* add parameters to the method call */
    dbus_message_iter_init_append(daemon_connection.msg, &in_args);
    Sailfish_Crypto__appendDataArg(&in_args, data, dataSize);
    Sailfish_Crypto__appendKeyArg(&in_args, key);
    Sailfish_Crypto__appendEnumArg(&in_args, &iBlockMode);
    Sailfish_Crypto__appendEnumArg(&in_args, &iPadding);
    Sailfish_Crypto__appendEnumArg(&in_args, &iDigest);
    dbus_message_iter_append_basic(
                &in_args,
                DBUS_TYPE_STRING,
                &cryptosystemProviderName);

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

    if (!Sailfish_Crypto__readResultStruct(&out_args,
                                           out_result)) {
        dbus_message_unref(daemon_connection.msg);
        daemon_connection.msg = NULL;
        return 0;
    }

    dbus_message_iter_next(&out_args);

    dbus_message_iter_recurse(&out_args, &plaintext_array);
    dbus_message_iter_get_fixed_array(&plaintext_array,
                                      &out_pt,
                                      &out_pt_size);


    *out_plaintext_size = (size_t)out_pt_size;
    *out_plaintext = (unsigned char *)malloc(*out_plaintext_size);
    memcpy(*out_plaintext, out_pt, *out_plaintext_size);

    dbus_message_unref(daemon_connection.msg);
    daemon_connection.msg = NULL;

    return 1;
}
