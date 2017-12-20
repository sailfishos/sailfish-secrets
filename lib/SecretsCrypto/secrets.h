/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETSCRYPTO_SECRETS_H
#define LIBSAILFISHSECRETSCRYPTO_SECRETS_H

/* This file provides a C-compatible wrapper for Secrets */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************** Result ******************************/

enum Sailfish_Secrets_Result_Code {
	Sailfish_Secrets_Result_Succeeded = 0,
	Sailfish_Secrets_Result_Pending = 1,
	Sailfish_Secrets_Result_Failed = 2
};

struct Sailfish_Secrets_Result {
	enum Sailfish_Secrets_Result_Code code;
	int errorCode;
	char *errorMessage;
	int refcount;
};

void Sailfish_Secrets_Result_ref(
		struct Sailfish_Secrets_Result *result);

void Sailfish_Secrets_Result_unref(
		struct Sailfish_Secrets_Result *result);

/****************************** Secret ******************************/

struct Sailfish_Secrets_Secret_Identifier {
	char *name;
	char *collectionName;
	char *storagePluginName;
	int refcount;
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
	int refcount;
};

struct Sailfish_Secrets_InteractionParameters {
	char *secretName;
	char *collectionName;
	char *pluginName;
	char *applicationId;
	int operation;
	char *authenticationPluginName;
	char *promptText;
	int inputType;
	int echoMode;
	int refcount;
};

struct Sailfish_Secrets_InteractionParameters*
Sailfish_Secrets_InteractionParameters_new(
		const char *authenticationPluginName,
		const char *promptText,
		int inputType,
		int echoMode);

void Sailfish_Secrets_InteractionParameters_ref(
		struct Sailfish_Secrets_InteractionParameters *params);

void Sailfish_Secrets_InteractionParameters_unref(
		struct Sailfish_Secrets_InteractionParameters *params);

struct Sailfish_Secrets_Secret_Identifier*
Sailfish_Secrets_Secret_Identifier_new(
		const char *name,
		const char *collectionName,
		const char *storagePluginName);

void Sailfish_Secrets_Secret_Identifier_ref(
		struct Sailfish_Secrets_Secret_Identifier *ident);

void Sailfish_Secrets_Secret_Identifier_unref(
		struct Sailfish_Secrets_Secret_Identifier *ident);

struct Sailfish_Secrets_Secret_FilterDatum*
Sailfish_Secrets_Secret_FilterDatum_new(
		const char *field,
		const char *value);

void Sailfish_Secrets_Secret_FilterDatum_ref(
		struct Sailfish_Secrets_Secret_FilterDatum *filter);

void Sailfish_Secrets_Secret_FilterDatum_unref(
		struct Sailfish_Secrets_Secret_FilterDatum *filter);

struct Sailfish_Secrets_Secret*
Sailfish_Secrets_Secret_new(
		const unsigned char *data,
		size_t dataSize);

void Sailfish_Secrets_Secret_ref(
		struct Sailfish_Secrets_Secret *secret);

void Sailfish_Secrets_Secret_unref(
		struct Sailfish_Secrets_Secret *secret);

void Sailfish_Secrets_Secret_setIdentifier(
		struct Sailfish_Secrets_Secret *secret,
		const char *name,
		const char *collectionName,
		const char *storagePluginName);

void Sailfish_Secrets_Secret_addFilter(
		struct Sailfish_Secrets_Secret *secret,
		const char *field,
		const char *value);

/****************************** Secret Manager **********************/

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
	Sailfish_Secrets_SecretManager_ApplicationInteraction
};

typedef void (*Sailfish_Secrets_SecretManager_createCollection_callback)
		(void *context, struct Sailfish_Secrets_Result *result);
typedef void (*Sailfish_Secrets_SecretManager_deleteCollection_callback)
		(void *context, struct Sailfish_Secrets_Result *result);
typedef void (*Sailfish_Secrets_SecretManager_setSecret_callback)
		(void *context, struct Sailfish_Secrets_Result *result);
typedef void (*Sailfish_Secrets_SecretManager_getSecret_callback)
		(void *context, struct Sailfish_Secrets_Result *result, struct Sailfish_Secrets_Secret *secret);
typedef void (*Sailfish_Secrets_SecretManager_deleteSecret_callback)
		(void *context, struct Sailfish_Secrets_Result *result);

int Sailfish_Secrets_SecretManager_createCollection(
		const char *collectionName,
		const char *storagePluginName,
		const char *encryptionPluginName,
		enum Sailfish_Secrets_SecretManager_DeviceLockUnlockSemantic unlockSemantic,
		enum Sailfish_Secrets_SecretManager_AccessControlMode accessControlMode,
		Sailfish_Secrets_SecretManager_createCollection_callback callback,
		void *callback_context);

int Sailfish_Secrets_SecretManager_deleteCollection(
		const char *collectionName,
		const char *storagePluginName,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode interactionMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_deleteCollection_callback callback,
		void *callback_context);

int Sailfish_Secrets_SecretManager_setSecret(
		struct Sailfish_Secrets_Secret *secret,
		struct Sailfish_Secrets_InteractionParameters *params,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_setSecret_callback callback,
		void *callback_context);

int Sailfish_Secrets_SecretManager_getSecret(
		struct Sailfish_Secrets_Secret_Identifier *ident,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_getSecret_callback callback,
		void *callback_context);

int Sailfish_Secrets_SecretManager_deleteSecret(
		struct Sailfish_Secrets_Secret_Identifier *ident,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_deleteSecret_callback callback,
		void *callback_context);

/****************************** Daemon Connection *******************/

typedef void (*Sailfish_Secrets_connectToServer_callback)
		(void *context, struct Sailfish_Secrets_Result *result);
typedef void (*Sailfish_Secrets_disconnectFromServer_callback)
		(void *context, struct Sailfish_Secrets_Result *result);

int Sailfish_Secrets_busy();

int Sailfish_Secrets_connectedToServer();

int Sailfish_Secrets_connectToServer(
		Sailfish_Secrets_connectToServer_callback callback,
		void *callback_context);

int Sailfish_Secrets_disconnectFromServer(
		Sailfish_Secrets_disconnectFromServer_callback callback,
		void *callback_context);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LIBSAILFISHSECRETSCRYPTO_SECRETS_H */
