/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "secrets.h"

#include <glib.h>
#include <gio/gio.h>
#ifdef G_OS_UNIX
#include <gio/gunixfdlist.h>
#endif

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/******************************* Data-Type Methods **************************/

static struct Sailfish_Secrets_Result *Sailfish_Secrets_Result_new(
		enum Sailfish_Secrets_Result_Code code,
		int errorCode,
		const char *errorMessage)
{
	struct Sailfish_Secrets_Result *result =
	    (struct Sailfish_Secrets_Result *)
	    malloc(sizeof(struct Sailfish_Secrets_Result));

	result->code = code;
	result->errorCode = errorCode;
	result->errorMessage = errorMessage ? strndup(errorMessage, 512) : NULL;
	result->refcount = 1;
	return result;
}

void Sailfish_Secrets_Result_ref(struct Sailfish_Secrets_Result *result)
{
	if (result)
		result->refcount = result->refcount + 1;
}

void Sailfish_Secrets_Result_unref(struct Sailfish_Secrets_Result *result)
{
	if (result) {
		result->refcount = result->refcount - 1;
		if (result->refcount == 0) {
			free(result->errorMessage);
			free(result);
		}
	}
}

struct Sailfish_Secrets_InteractionParameters*
Sailfish_Secrets_InteractionParameters_new(
		const char *authenticationPluginName,
		const char *promptText,
		int inputType,
		int echoMode)
{
	struct Sailfish_Secrets_InteractionParameters *params =
	    (struct Sailfish_Secrets_InteractionParameters *)
	    malloc(sizeof(struct Sailfish_Secrets_InteractionParameters));

	params->secretName = NULL;
	params->collectionName = NULL;
	params->pluginName = NULL;
	params->applicationId = NULL;
	params->authenticationPluginName = authenticationPluginName
		    ? strndup(authenticationPluginName, 512) : NULL;
	params->promptText = promptText ? strndup(promptText, 512) : NULL;
	params->inputType = inputType;
	params->echoMode = echoMode;
	params->refcount = 1;

	return params;
}

void Sailfish_Secrets_InteractionParameters_ref(
		struct Sailfish_Secrets_InteractionParameters *params)
{
	if (params)
		params->refcount = params->refcount + 1;
}

void Sailfish_Secrets_InteractionParameters_unref(
		struct Sailfish_Secrets_InteractionParameters *params)
{
	if (params) {
		params->refcount = params->refcount - 1;
		if (params->refcount == 0) {
			free(params->secretName);
			free(params->collectionName);
			free(params->pluginName);
			free(params->applicationId);
			free(params->authenticationPluginName);
			free(params->promptText);
			free(params);
		}
	}
}

struct Sailfish_Secrets_Secret_Identifier *
Sailfish_Secrets_Secret_Identifier_new(
		const char *name,
		const char *collectionName,
		const char *storagePluginName)
{
	struct Sailfish_Secrets_Secret_Identifier *ident =
	    (struct Sailfish_Secrets_Secret_Identifier *)
	    malloc(sizeof(struct Sailfish_Secrets_Secret_Identifier));

	ident->name = name ? strndup(name, 512) : NULL;
	ident->collectionName = collectionName
	    ? strndup(collectionName, 512) : NULL;
	ident->storagePluginName = storagePluginName
	    ? strndup(storagePluginName, 512) : NULL;
	ident->refcount = 1;

	return ident;
}

void Sailfish_Secrets_Secret_Identifier_ref(
		struct Sailfish_Secrets_Secret_Identifier *ident)
{
	if (ident)
		ident->refcount = ident->refcount + 1;
}

void Sailfish_Secrets_Secret_Identifier_unref(
		struct Sailfish_Secrets_Secret_Identifier *ident)
{
	if (ident) {
		ident->refcount = ident->refcount - 1;
		if (ident->refcount == 0) {
			free(ident->name);
			free(ident->collectionName);
			free(ident->storagePluginName);
			free(ident);
		}
	}
}

struct Sailfish_Secrets_Secret_FilterDatum *
Sailfish_Secrets_Secret_FilterDatum_new(
		const char *field,
		const char *value)
{
	struct Sailfish_Secrets_Secret_FilterDatum *filter =
	    (struct Sailfish_Secrets_Secret_FilterDatum *)
	    malloc(sizeof(struct Sailfish_Secrets_Secret_FilterDatum));

	filter->field = field ? strndup(field, 512) : NULL;
	filter->value = value ? strndup(value, 512) : NULL;
	filter->next = NULL;

	return filter;
}

void Sailfish_Secrets_Secret_FilterDatum_unref(
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

struct Sailfish_Secrets_Secret *
Sailfish_Secrets_Secret_new(
		const unsigned char *data, size_t dataSize)
{
	struct Sailfish_Secrets_Secret *secret =
	    (struct Sailfish_Secrets_Secret *)
	    malloc(sizeof(struct Sailfish_Secrets_Secret));

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
	secret->refcount = 1;

	return secret;
}

void Sailfish_Secrets_Secret_ref(struct Sailfish_Secrets_Secret *secret)
{
	if (secret)
		secret->refcount = secret->refcount + 1;
}

void Sailfish_Secrets_Secret_unref(struct Sailfish_Secrets_Secret *secret)
{
	if (secret) {
		secret->refcount = secret->refcount - 1;
		if (secret->refcount == 0) {
			Sailfish_Secrets_Secret_FilterDatum_unref(secret->
								  filterData);
			Sailfish_Secrets_Secret_Identifier_unref(secret->
								 identifier);
			free(secret->data);
			free(secret);
		}
	}
}

void Sailfish_Secrets_Secret_setIdentifier(
		struct Sailfish_Secrets_Secret *secret,
		const char *name,
		const char *collectionName,
		const char *storagePluginName)
{
	if (secret && name && collectionName) {
		Sailfish_Secrets_Secret_Identifier_unref(secret->identifier);
		secret->identifier =
		    Sailfish_Secrets_Secret_Identifier_new(
			    name, collectionName, storagePluginName);
	}
}

void Sailfish_Secrets_Secret_addFilter(
		struct Sailfish_Secrets_Secret *secret,
		const char *field,
		const char *value)
{
	if (secret && field && value) {
		if (!secret->filterData) {
			secret->filterData =
			    Sailfish_Secrets_Secret_FilterDatum_new(field,
								    value);
		} else {
			struct Sailfish_Secrets_Secret_FilterDatum *filter =
			    secret->filterData;
			while (filter->next) {
				filter = filter->next;
			}
			filter->next =
			    Sailfish_Secrets_Secret_FilterDatum_new(field,
								    value);
		}
	}
}

/******************************* Internal Callback Wrapping *****************/

typedef void (*Sailfish_Secrets_SecretManager_result_callback) (
		void *context, struct Sailfish_Secrets_Result *result);
typedef void (*Sailfish_Secrets_SecretManager_secret_result_callback) (
		void *context, struct Sailfish_Secrets_Result *result,
		struct Sailfish_Secrets_Secret *secret);

struct Sailfish_Secrets_Callback_Data {
	Sailfish_Secrets_SecretManager_result_callback result_callback;
	Sailfish_Secrets_SecretManager_secret_result_callback
	    secret_result_callback;
	void *callback_context;
	int refcount;
};

struct Sailfish_Secrets_Callback_Data *
Sailfish_Secrets_Callback_Data_new(
		Sailfish_Secrets_SecretManager_result_callback rc,
		Sailfish_Secrets_SecretManager_secret_result_callback src,
		void *cc)
{
	struct Sailfish_Secrets_Callback_Data *cbd =
	    (struct Sailfish_Secrets_Callback_Data *)
	    malloc(sizeof(struct Sailfish_Secrets_Callback_Data));

	cbd->result_callback = rc;
	cbd->secret_result_callback = src;
	cbd->callback_context = cc;
	cbd->refcount = 1;

	return cbd;
}

void Sailfish_Secrets_Callback_Data_ref(
		struct Sailfish_Secrets_Callback_Data *cbd)
{
	cbd->refcount = cbd->refcount + 1;
}

void Sailfish_Secrets_Callback_Data_unref(
		struct Sailfish_Secrets_Callback_Data *cbd)
{
	cbd->refcount = cbd->refcount - 1;
	if (cbd->refcount == 0)
		free(cbd);
}

/******************************* Internal Daemon Connection *****************/

static struct Sailfish_Secrets_DBus_Connection {
	GDBusProxy *discoveryProxy;
	char *p2pAddr;
	GDBusConnection *p2pBus;
	GDBusProxy *secretsProxy;
	int busy;
} daemon_connection = {
	.discoveryProxy = NULL,
	.p2pAddr = NULL,
	.p2pBus = NULL,
	.secretsProxy = NULL,
	.busy = 0
};

void Sailfish_Secrets_proxyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GDBusProxy *proxy = g_dbus_proxy_new_finish(res, NULL);
	(void)source_object;
	if (proxy) {
		/* Success, we're connected! */
		struct Sailfish_Secrets_Result *result =
		    Sailfish_Secrets_Result_new
		    (Sailfish_Secrets_Result_Succeeded, 0, "");
		struct Sailfish_Secrets_Callback_Data *cbd =
		    (struct Sailfish_Secrets_Callback_Data *)user_data;
		daemon_connection.secretsProxy = proxy;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Secrets_Result_unref(result);
		Sailfish_Secrets_Callback_Data_unref(cbd);
	} else {
		struct Sailfish_Secrets_Result *result =
		    Sailfish_Secrets_Result_new(
				    Sailfish_Secrets_Result_Failed,
				    5,
				    "Unable to create secrets interface");
		struct Sailfish_Secrets_Callback_Data *cbd =
		    (struct Sailfish_Secrets_Callback_Data *)user_data;
		g_dbus_connection_close_sync(daemon_connection.p2pBus, NULL,
					     NULL);
		g_object_unref(daemon_connection.p2pBus);
		daemon_connection.p2pBus = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Secrets_Result_unref(result);
		Sailfish_Secrets_Callback_Data_unref(cbd);
	}
}

void Sailfish_Secrets_connectionReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	daemon_connection.p2pBus =
	    g_dbus_connection_new_for_address_finish(res, NULL);
	(void)source_object;
	if (daemon_connection.p2pBus) {
		free(daemon_connection.p2pAddr);
		daemon_connection.p2pAddr = NULL;
		g_dbus_proxy_new(
		    daemon_connection.p2pBus,
		    G_DBUS_PROXY_FLAGS_NONE,
		    NULL,
		    NULL, /* bus name */
		    "/Sailfish/Secrets",
		    "org.sailfishos.secrets",
		    NULL, /* GCancellable */
		    Sailfish_Secrets_proxyReady,
		    user_data);
	} else {
		struct Sailfish_Secrets_Result *result =
		    Sailfish_Secrets_Result_new(
				    Sailfish_Secrets_Result_Failed,
				    5,
				    "Unable to connect to sailfishsecretsd bus");
		struct Sailfish_Secrets_Callback_Data *cbd =
		    (struct Sailfish_Secrets_Callback_Data *)user_data;
		free(daemon_connection.p2pAddr);
		daemon_connection.p2pAddr = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Secrets_Result_unref(result);
		Sailfish_Secrets_Callback_Data_unref(cbd);
	}
}

void Sailfish_Secrets_peerToPeerAddressReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GVariant *p2pAddrResult =
	    g_dbus_proxy_call_finish(daemon_connection.discoveryProxy, res,
				     NULL);
	(void)source_object;
	if (p2pAddrResult) {
		g_variant_get(p2pAddrResult, "(s)", &daemon_connection.p2pAddr);
		g_variant_unref(p2pAddrResult);
	}
	g_object_unref(daemon_connection.discoveryProxy);
	daemon_connection.discoveryProxy = NULL;
	if (daemon_connection.p2pAddr) {
		/* We have discovered the p2p bus address of sailfishsecretsd's secrets API */
		g_dbus_connection_new_for_address(
		    daemon_connection.p2pAddr,
		    G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT,
		    NULL, /* observer */
		    NULL, /* cancellable */
		    Sailfish_Secrets_connectionReady,
		    user_data);
	} else {
		struct Sailfish_Secrets_Result *result =
		    Sailfish_Secrets_Result_new(
				    Sailfish_Secrets_Result_Failed,
				    6,
				    "Unable to discover sailfishsecretsd bus");
		struct Sailfish_Secrets_Callback_Data *cbd =
		    (struct Sailfish_Secrets_Callback_Data *)user_data;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Secrets_Result_unref(result);
		Sailfish_Secrets_Callback_Data_unref(cbd);
	}
}

void Sailfish_Secrets_discoveryProxyReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GDBusProxy *discoveryProxy = g_dbus_proxy_new_for_bus_finish(res, NULL);
	daemon_connection.discoveryProxy = discoveryProxy;
	(void)source_object;
	if (discoveryProxy) {
		g_dbus_proxy_call(
		    discoveryProxy,
		    "peerToPeerAddress",
		    g_variant_new("()"),
		    G_DBUS_CALL_FLAGS_NONE,
		    -1,
		    NULL, /* GCancellable */
		    Sailfish_Secrets_peerToPeerAddressReady,
		    user_data);
	} else {
		struct Sailfish_Secrets_Result *result =
		    Sailfish_Secrets_Result_new(
				    Sailfish_Secrets_Result_Failed,
				    6,
				    "Unable to connect to sailfishsecretsd discovery service");
		struct Sailfish_Secrets_Callback_Data *cbd =
		    (struct Sailfish_Secrets_Callback_Data *)user_data;
		g_object_unref(daemon_connection.discoveryProxy);
		daemon_connection.discoveryProxy = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Secrets_Result_unref(result);
		Sailfish_Secrets_Callback_Data_unref(cbd);
	}
}

void Sailfish_Secrets_disconnectReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	GError *error = NULL;
	(void)source_object;
	if (g_dbus_connection_close_finish(
			daemon_connection.p2pBus, res, &error)) {
		struct Sailfish_Secrets_Result *result =
		    Sailfish_Secrets_Result_new
		    (Sailfish_Secrets_Result_Succeeded, 0, "");
		struct Sailfish_Secrets_Callback_Data *cbd =
		    (struct Sailfish_Secrets_Callback_Data *)user_data;
		g_object_unref(daemon_connection.secretsProxy);
		daemon_connection.secretsProxy = NULL;
		g_object_unref(daemon_connection.p2pBus);
		daemon_connection.p2pBus = NULL;
		daemon_connection.busy = 0;
		cbd->result_callback(cbd->callback_context, result);
		Sailfish_Secrets_Result_unref(result);
		Sailfish_Secrets_Callback_Data_unref(cbd);
	} else {
		/* check to see if the error was that the connection was already closed */
		if (error->code == G_IO_ERROR_CLOSED) {
			struct Sailfish_Secrets_Result *result =
			    Sailfish_Secrets_Result_new
			    (Sailfish_Secrets_Result_Succeeded, 0, "");
			struct Sailfish_Secrets_Callback_Data *cbd =
			    (struct Sailfish_Secrets_Callback_Data *)user_data;
			g_object_unref(daemon_connection.secretsProxy);
			daemon_connection.secretsProxy = NULL;
			g_object_unref(daemon_connection.p2pBus);
			daemon_connection.p2pBus = NULL;
			daemon_connection.busy = 0;
			cbd->result_callback(cbd->callback_context, result);
			Sailfish_Secrets_Result_unref(result);
			Sailfish_Secrets_Callback_Data_unref(cbd);
		} else {
			struct Sailfish_Secrets_Result *result =
			    Sailfish_Secrets_Result_new
			    (Sailfish_Secrets_Result_Failed, 2,
			     "Unable to disconnect from the secrets daemon");
			struct Sailfish_Secrets_Callback_Data *cbd =
			    (struct Sailfish_Secrets_Callback_Data *)user_data;
			daemon_connection.busy = 0;
			cbd->result_callback(cbd->callback_context, result);
			Sailfish_Secrets_Result_unref(result);
			Sailfish_Secrets_Callback_Data_unref(cbd);
		}
		g_error_free(error);
	}
}

/******************************* Internal DBus Marshalling ******************/


GVariant *Sailfish_Secrets_variantFromInteractionParameters(
		struct Sailfish_Secrets_InteractionParameters *params)
{
	GVariantBuilder *promptTextBuilder = NULL;

	if (params == NULL)
		return NULL;

	promptTextBuilder = g_variant_builder_new(G_VARIANT_TYPE("a{is}"));
	if (params->promptText) {
		g_variant_builder_add(promptTextBuilder, "{is}",
			  0, /* InteractionParameters::Message */
			  g_variant_new("s", params->promptText));
	}

	return g_variant_new("(ssss@(i)s@a{is}@(i)@(i))",
			    params->secretName,
			    params->collectionName,
			    params->pluginName,
			    params->applicationId,
			    g_variant_new("(i)", params->operation),
			    params->authenticationPluginName,
			    g_variant_builder_end(promptTextBuilder),
			    g_variant_new("(i)", params->inputType),
			    g_variant_new("(i)", params->echoMode));
}

GVariant *Sailfish_Secrets_variantFromSecretIdentifier(
		struct Sailfish_Secrets_Secret_Identifier *ident)
{
	if (ident == NULL)
		return NULL;

	return g_variant_new("(sss)",
			    ident->name,
			    ident->collectionName,
			    ident->storagePluginName);
}

GVariant *Sailfish_Secrets_variantFromSecret(
		struct Sailfish_Secrets_Secret *secret)
{
	GVariant *result = NULL;
	GVariantBuilder *dataBuilder = NULL;
	GVariantBuilder *filterDataBuilder = NULL;
	struct Sailfish_Secrets_Secret_FilterDatum *currFilter = NULL;
	size_t i = 0;

	if (secret == NULL)
		return NULL;

	dataBuilder = g_variant_builder_new(G_VARIANT_TYPE_BYTESTRING);
	for (i = 0; i < secret->dataSize; i++)
		g_variant_builder_add(dataBuilder, "y", secret->data[i]);

	filterDataBuilder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	currFilter = secret->filterData;
	while (currFilter) {
		g_variant_builder_add(filterDataBuilder, "{sv}",
				      currFilter->field,
				      g_variant_new("s", currFilter->value));
		currFilter = currFilter->next;
	}

	result = g_variant_new(
			    "(@(sss)@ay@a{sv})",
			    Sailfish_Secrets_variantFromSecretIdentifier(secret->identifier),
			    g_variant_builder_end(dataBuilder),
			    g_variant_builder_end(filterDataBuilder));

	g_variant_builder_unref(dataBuilder);
	g_variant_builder_unref(filterDataBuilder);

	return result;
}

struct Sailfish_Secrets_Secret *
Sailfish_Secrets_secretFromVariant(GVariant *variant)
{
	struct Sailfish_Secrets_Secret *secret = NULL;
	GVariant *identVariant = NULL;
	char *secretName = NULL;
	char *collectionName = NULL;
	char *storagePluginName = NULL;
	GVariantIter *dataIter;
	unsigned char datum = 0;
	unsigned char *data =
	    (unsigned char *)malloc(2048 * sizeof(unsigned char));
	size_t dataSize = 0;
	size_t allocatedSize = 2048 * sizeof(unsigned char);
	GVariantIter *filterIter;
	char *field = NULL;
	GVariant *value = NULL;

	g_variant_get(variant, "(@(sss)aya{sv})",
		      &identVariant, &dataIter, &filterIter);

	memset(data, 0, 2048 * sizeof(unsigned char));
	while (g_variant_iter_next(dataIter, "y", &datum)) {
		dataSize += sizeof(unsigned char);
		if (allocatedSize < dataSize) {
			unsigned char *newData = NULL;
			unsigned char *oldData = data;
			size_t newAllocSize = allocatedSize * 2;
			newData = (unsigned char *)malloc(newAllocSize);
			memset(newData, 0, newAllocSize);
			memcpy(newData, data, allocatedSize);
			data = newData;
			free(oldData);
		}
		data[dataSize - 1] = datum;
	}

	secret = Sailfish_Secrets_Secret_new(data, dataSize);
	free(data);
	data = NULL;

	g_variant_get(identVariant, "(sss)", &secretName, &collectionName,
			    &storagePluginName);
	Sailfish_Secrets_Secret_setIdentifier(secret, secretName,
			    collectionName, storagePluginName);

	while (g_variant_iter_next(filterIter, "{sv}", &field, &value)) {
		Sailfish_Secrets_Secret_addFilter(secret, field,
						  g_variant_get_string(value,
								       NULL));
		g_variant_unref(value);
		g_free(field);
	}

	g_variant_iter_free(dataIter);
	g_variant_iter_free(filterIter);
	g_variant_unref(identVariant);
	g_free(storagePluginName);
	g_free(collectionName);
	g_free(secretName);

	return secret;
}

/******************************* Internal Secrets Manager *******************/

void Sailfish_Secrets_createCollectionReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Secrets_Result *result = NULL;
	struct Sailfish_Secrets_Callback_Data *cbd =
	    (struct Sailfish_Secrets_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.secretsProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		gchar *errorMessage = NULL;
		g_variant_get(
		    daemon_result, "((iis))",
		    &resultCode,
		    &errorCode,
		    &errorMessage);
		result = Sailfish_Secrets_Result_new(
		    resultCode,
		    errorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Secrets_Result_new(
		    Sailfish_Secrets_Result_Failed,
		    5,
		    "Unable to finish create collection call");
	}

	daemon_connection.busy = 0;
	cbd->result_callback(cbd->callback_context, result);
	Sailfish_Secrets_Result_unref(result);
	free(cbd);
}

void Sailfish_Secrets_deleteCollectionReady(GObject * source_object,
					    GAsyncResult * res,
					    gpointer user_data)
{
	struct Sailfish_Secrets_Result *result = NULL;
	struct Sailfish_Secrets_Callback_Data *cbd =
	    (struct Sailfish_Secrets_Callback_Data *)user_data;
	GError *error = NULL;
	GVariant *daemon_result =
		g_dbus_proxy_call_finish(
			daemon_connection.secretsProxy, res, &error);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		gchar *errorMessage = NULL;
		g_variant_get(
		    daemon_result, "((iis))",
		    &resultCode,
		    &errorCode,
		    &errorMessage);
		result = Sailfish_Secrets_Result_new(
		    resultCode,
		    errorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Secrets_Result_new(
		    Sailfish_Secrets_Result_Failed,
		    5,
		    "Unable to finish delete collection call");
	}

	daemon_connection.busy = 0;
	cbd->result_callback(cbd->callback_context, result);
	Sailfish_Secrets_Result_unref(result);
	g_error_free(error);
	free(cbd);
}

void Sailfish_Secrets_setSecretReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Secrets_Result *result = NULL;
	struct Sailfish_Secrets_Callback_Data *cbd =
	    (struct Sailfish_Secrets_Callback_Data *)user_data;
	GError *error = NULL;
	GVariant *daemon_result = g_dbus_proxy_call_finish(
	    daemon_connection.secretsProxy, res, &error);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		gchar *errorMessage = NULL;
		g_variant_get(
		    daemon_result,
		    "((iis))",
		    &resultCode,
		    &errorCode,
		    &errorMessage);
		result = Sailfish_Secrets_Result_new(
		    resultCode,
		    errorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Secrets_Result_new(
		    Sailfish_Secrets_Result_Failed,
		    5,
		    "Unable to finish set secret call");
	}

	daemon_connection.busy = 0;
	cbd->result_callback(cbd->callback_context, result);
	Sailfish_Secrets_Result_unref(result);
	g_error_free(error);
	free(cbd);
}

void Sailfish_Secrets_getSecretReady(
		GObject *source_object,
		GAsyncResult *res,
		gpointer user_data)
{
	struct Sailfish_Secrets_Result *result = NULL;
	struct Sailfish_Secrets_Secret *secret = NULL;
	struct Sailfish_Secrets_Callback_Data *cbd =
	    (struct Sailfish_Secrets_Callback_Data *)user_data;
	GVariant *daemon_return =
	    g_dbus_proxy_call_finish(daemon_connection.secretsProxy, res, NULL);
	(void)source_object;
	if (daemon_return) {
		GVariant *daemon_result = NULL;
		GVariant *daemon_secret = NULL;
		int resultCode = 0;
		int errorCode = 0;
		gchar *errorMessage = NULL;
		g_variant_get(
		    daemon_return, "(@(iis)@((sss)aya{sv}))",
		    &daemon_result,
		    &daemon_secret);
		g_variant_get(
		    daemon_result, "(iis)",
		    &resultCode,
		    &errorCode,
		    &errorMessage);
		result = Sailfish_Secrets_Result_new(
		    resultCode, errorCode, errorMessage);
		secret = Sailfish_Secrets_secretFromVariant(daemon_secret);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
		g_variant_unref(daemon_secret);
		g_variant_unref(daemon_return);
	} else {
		unsigned char nullchar = '\0';
		secret = Sailfish_Secrets_Secret_new(&nullchar, 0);
		result = Sailfish_Secrets_Result_new(
		    Sailfish_Secrets_Result_Failed,
		    5,
		    "Unable to finish get secret call");
	}

	daemon_connection.busy = 0;
	cbd->secret_result_callback(cbd->callback_context, result, secret);
	Sailfish_Secrets_Result_unref(result);
	Sailfish_Secrets_Secret_unref(secret);
	free(cbd);
}

void Sailfish_Secrets_deleteSecretReady(GObject * source_object,
					GAsyncResult * res, gpointer user_data)
{
	struct Sailfish_Secrets_Result *result = NULL;
	struct Sailfish_Secrets_Callback_Data *cbd =
	    (struct Sailfish_Secrets_Callback_Data *)user_data;
	GVariant *daemon_result =
	    g_dbus_proxy_call_finish(daemon_connection.secretsProxy, res, NULL);
	(void)source_object;
	if (daemon_result) {
		int resultCode = 0;
		int errorCode = 0;
		gchar *errorMessage = NULL;
		g_variant_get(
		    daemon_result, "((iis))",
		    &resultCode,
		    &errorCode,
		    &errorMessage);
		result = Sailfish_Secrets_Result_new(
		    resultCode,
		    errorCode,
		    errorMessage);
		g_free(errorMessage);
		g_variant_unref(daemon_result);
	} else {
		result = Sailfish_Secrets_Result_new(
		    Sailfish_Secrets_Result_Failed,
		    5,
		    "Unable to finish delete secret call");
	}

	daemon_connection.busy = 0;
	cbd->result_callback(cbd->callback_context, result);
	Sailfish_Secrets_Result_unref(result);
	free(cbd);
}

/****************************** Secret Manager **********************/

int Sailfish_Secrets_SecretManager_createCollection(
		const char *collectionName,
		const char *storagePluginName,
		const char *encryptionPluginName,
		enum Sailfish_Secrets_SecretManager_DeviceLockUnlockSemantic unlockSemantic,
		enum Sailfish_Secrets_SecretManager_AccessControlMode accessControlMode,
		Sailfish_Secrets_SecretManager_createCollection_callback callback,
		void *callback_context)
{
	if (Sailfish_Secrets_busy() || !Sailfish_Secrets_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Secrets_Callback_Data *cbd =
		    Sailfish_Secrets_Callback_Data_new(
			    (Sailfish_Secrets_SecretManager_result_callback)callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.secretsProxy,
				  "createCollection",
				  g_variant_new("(sss@(i)@(i))",
						collectionName,
						storagePluginName,
						encryptionPluginName,
						g_variant_new("(i)",
							      unlockSemantic),
						g_variant_new("(i)",
							      accessControlMode)),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Secrets_createCollectionReady, cbd);
		return 1;
	}
}

int Sailfish_Secrets_SecretManager_deleteCollection(
		const char *collectionName,
		const char *storagePluginName,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_deleteCollection_callback callback,
		void *callback_context)
{
	if (Sailfish_Secrets_busy() || !Sailfish_Secrets_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Secrets_Callback_Data *cbd =
		    Sailfish_Secrets_Callback_Data_new(
			    (Sailfish_Secrets_SecretManager_result_callback)callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.secretsProxy,
				  "deleteCollection",
				  g_variant_new("(ss@(i)s)",
						collectionName,
						storagePluginName,
						g_variant_new("(i)", uiMode),
						interactionServiceAddress),
				  G_DBUS_CALL_FLAGS_NONE,
				  -1,
				  NULL,
				  Sailfish_Secrets_deleteCollectionReady, cbd);
		return 1;
	}
}

int Sailfish_Secrets_SecretManager_setSecret(
		struct Sailfish_Secrets_Secret *secret,
		struct Sailfish_Secrets_InteractionParameters *params,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_setSecret_callback callback,
		void *callback_context)
{
	if (Sailfish_Secrets_busy() || !Sailfish_Secrets_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Secrets_Callback_Data *cbd =
		    Sailfish_Secrets_Callback_Data_new(
			    (Sailfish_Secrets_SecretManager_result_callback)callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.secretsProxy,
				  "setSecret",
				  g_variant_new("(@((sss)aya{sv})@(ssss(i)sa{is}(i)(i))@(i)s)",
						Sailfish_Secrets_variantFromSecret(secret),
						Sailfish_Secrets_variantFromInteractionParameters(params),
						g_variant_new("(i)", uiMode),
						interactionServiceAddress),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Secrets_setSecretReady, cbd);
		return 1;
	}
}

int Sailfish_Secrets_SecretManager_getSecret(
		struct Sailfish_Secrets_Secret_Identifier *ident,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_getSecret_callback callback,
		void *callback_context)
{
	if (Sailfish_Secrets_busy() || !Sailfish_Secrets_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Secrets_Callback_Data *cbd =
		    Sailfish_Secrets_Callback_Data_new(
			    NULL,
			    (Sailfish_Secrets_SecretManager_secret_result_callback) callback,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_call(daemon_connection.secretsProxy,
				  "getSecret",
				  g_variant_new("(@(sss)@(i)s)",
						Sailfish_Secrets_variantFromSecretIdentifier(ident),
						g_variant_new("(i)", uiMode),
						interactionServiceAddress),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Secrets_getSecretReady, cbd);
		return 1;
	}
}

int Sailfish_Secrets_SecretManager_deleteSecret(
		struct Sailfish_Secrets_Secret_Identifier *ident,
		enum Sailfish_Secrets_SecretManager_UserInteractionMode uiMode,
		const char *interactionServiceAddress,
		Sailfish_Secrets_SecretManager_deleteSecret_callback callback,
		void *callback_context)
{
	if (Sailfish_Secrets_busy() || !Sailfish_Secrets_connectedToServer()) {
		return 0;
	} else {
		struct Sailfish_Secrets_Callback_Data *cbd =
		    Sailfish_Secrets_Callback_Data_new(
			    (Sailfish_Secrets_SecretManager_result_callback) callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;

		g_dbus_proxy_call(daemon_connection.secretsProxy,
				  "deleteSecret",
				  g_variant_new("(@(sss)@(i)s)",
						Sailfish_Secrets_variantFromSecretIdentifier(ident),
						g_variant_new("(i)", uiMode),
						interactionServiceAddress),
				  G_DBUS_CALL_FLAGS_NONE, -1, NULL,
				  Sailfish_Secrets_deleteSecretReady, cbd);
		return 1;
	}
}

/****************************** Daemon Connection *******************/

int Sailfish_Secrets_busy()
{
	return daemon_connection.busy;
}

int Sailfish_Secrets_connectedToServer()
{
	return daemon_connection.secretsProxy != NULL;
}

int Sailfish_Secrets_connectToServer(
		Sailfish_Secrets_connectToServer_callback callback,
		void *callback_context)
{
	if (Sailfish_Secrets_connectedToServer()) {
		return 2;	/* already connected */
	} else if (daemon_connection.busy) {
		return 0;	/* currently connecting */
	} else {
		struct Sailfish_Secrets_Callback_Data *cbd =
		    Sailfish_Secrets_Callback_Data_new(
			   (Sailfish_Secrets_SecretManager_result_callback)callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_proxy_new_for_bus(
		    G_BUS_TYPE_SESSION,
		    G_DBUS_PROXY_FLAGS_NONE,
		    NULL, /* info */
		    "org.sailfishos.secrets.daemon.discovery",
		    "/Sailfish/Secrets/Discovery",
		    "org.sailfishos.secrets.daemon.discovery",
		    NULL, /* cancellable */
		    Sailfish_Secrets_discoveryProxyReady,
		    cbd);
		return 1;	/* starting to connect */
	}
}

int Sailfish_Secrets_disconnectFromServer(
		Sailfish_Secrets_disconnectFromServer_callback callback,
 		void *callback_context)
{
	if (!daemon_connection.p2pBus) {
		return 2;
	} else {
		struct Sailfish_Secrets_Callback_Data *cbd =
		    Sailfish_Secrets_Callback_Data_new(
			    (Sailfish_Secrets_SecretManager_result_callback) callback,
			    NULL,
			    callback_context);
		daemon_connection.busy = 1;
		g_dbus_connection_close(
		    daemon_connection.p2pBus,
		    NULL,
		    Sailfish_Secrets_disconnectReady,
		    cbd);
		return 1;
	}
}
