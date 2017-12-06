/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SECRETS_C_H
#define LIBSAILFISHSECRETS_SECRETS_C_H

/* This file provides a C-compatible wrapper for Secrets */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************** result ******************************/

enum Sailfish_Secrets_Result_Code {
    Sailfish_Secrets_Result_Succeeded = 0,
    Sailfish_Secrets_Result_Pending = 1,
    Sailfish_Secrets_Result_Failed = 2
};

struct Sailfish_Secrets_Result {
    enum Sailfish_Secrets_Result_Code code;
    int errorCode;
    char *errorMessage;
};

struct Sailfish_Secrets_Result*
Sailfish_Secrets_Result_new(
        enum Sailfish_Secrets_Result_Code code,
        int errorCode,
        const char *errorMessage);

void Sailfish_Secrets_Result_delete(
        struct Sailfish_Secrets_Result *result);

/****************************** secret ******************************/

struct Sailfish_Secrets_Secret_Identifier {
    char *name;
    char *collectionName;
};

struct Sailfish_Secrets_Secret_FilterDatum {
    char *field;
    char *value;
    struct Sailfish_Secrets_Secret_FilterDatum *next;
};

struct Sailfish_Secrets_Secret {
    struct Sailfish_Secrets_Secret_Identifier *identifier;
    struct Sailfish_Secrets_Secret_FilterDatum *filterData;
    unsigned char *data;
    size_t dataSize;
};

struct Sailfish_Secrets_Secret_Identifier*
Sailfish_Secrets_Secret_Identifier_new(
        const char *name,
        const char *collectionName);

void Sailfish_Secrets_Secret_Identifier_delete(
        struct Sailfish_Secrets_Secret_Identifier *ident);

struct Sailfish_Secrets_Secret_FilterDatum*
Sailfish_Secrets_Secret_FilterDatum_new(
        const char *field,
        const char *value);

void Sailfish_Secrets_Secret_FilterDatum_delete(
        struct Sailfish_Secrets_Secret_FilterDatum *filter);

struct Sailfish_Secrets_Secret*
Sailfish_Secrets_Secret_new(
        const unsigned char *data,
        size_t dataSize);

void Sailfish_Secrets_Secret_delete(
        struct Sailfish_Secrets_Secret *secret);

void Sailfish_Secrets_Secret_setIdentifier(
        struct Sailfish_Secrets_Secret *secret,
        const char *name,
        const char *collectionName);

void Sailfish_Secrets_Secret_addFilter(
        struct Sailfish_Secrets_Secret *secret,
        const char *field,
        const char *value);

/****************************** secret manager **********************/

enum Sailfish_Secrets_SecretManager_DeviceLockUnlockSemantic {
    Sailfish_Secrets_SecretManager_DeviceLockKeepUnlocked = 0,
    Sailfish_Secrets_SecretManager_DeviceLockRelock,
};

enum Sailfish_Secrets_SecretManager_AccessControlMode {
    Sailfish_Secrets_SecretManager_OwnerOnlyMode = 0,
    Sailfish_Secrets_SecretManager_SystemAccessControlMode
};

enum Sailfish_Secrets_SecretManager_UserInteractionMode {
    Sailfish_Secrets_SecretManager_PreventInteraction = 0,
    Sailfish_Secrets_SecretManager_SystemInteraction,
    Sailflish_Secrets_SecretManager_ApplicationInteraction
};

int Sailfish_Secrets_SecretManager_createCollection(
        const char *collectionName,
        const char *storagePluginName,
        const char *encryptionPluginName,
        enum Sailfish_Secrets_SecretManager_DeviceLockUnlockSemantic unlockSemantic,
        enum Sailfish_Secrets_SecretManager_AccessControlMode accessControlMode,
        struct Sailfish_Secrets_Result **out_result);

int Sailfish_Secrets_SecretManager_deleteCollection(
        const char *collectionName,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode interactionMode,
        struct Sailfish_Secrets_Result **out_result);

int Sailfish_Secrets_SecretManager_setSecret(
        struct Sailfish_Secrets_Secret *secret,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
        const char *interactionServiceAddress,
        struct Sailfish_Secrets_Result **out_result);

int Sailfish_Secrets_SecretManager_getSecret(
        struct Sailfish_Secrets_Secret_Identifier *ident,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
        const char *interactionServiceAddress,
        struct Sailfish_Secrets_Result **out_result,
        struct Sailfish_Secrets_Secret **out_secret);

int Sailfish_Secrets_SecretManager_deleteSecret(
        struct Sailfish_Secrets_Secret_Identifier *ident,
        enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
        const char *interactionServiceAddress,
        struct Sailfish_Secrets_Result **out_result);

void Sailfish_Secrets_disconnectFromServer();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBSAILFISHSECRETS_SECRETS_C_H */
