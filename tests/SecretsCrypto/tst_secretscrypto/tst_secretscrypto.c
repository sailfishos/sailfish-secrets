/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <SecretsCrypto/secrets.h>

#include <glib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int tst_secretscrypto_complete = 0;
static int tst_secretscrypto_return = 0;

struct CallbackContext {
    struct Sailfish_Secrets_Secret *secret;
    struct Sailfish_Secrets_InteractionParameters *params;
    int refcount;
};

struct CallbackContext*
CallbackContext_new(
        struct Sailfish_Secrets_Secret *secret,
        struct Sailfish_Secrets_InteractionParameters *params)
{
    struct CallbackContext *ctxt =
        (struct CallbackContext *)
        malloc(sizeof(struct CallbackContext));

    ctxt->secret = secret;
    ctxt->params = params;
    ctxt->refcount = 1;

    return ctxt;
}

void CallbackContext_ref(struct CallbackContext *ctxt)
{
    if (ctxt)
        ctxt->refcount = ctxt->refcount + 1;
}

void CallbackContext_unref(struct CallbackContext *ctxt)
{
    if (ctxt) {
        ctxt->refcount = ctxt->refcount - 1;
        if (ctxt->refcount == 0) {
            Sailfish_Secrets_Secret_unref(ctxt->secret);
            Sailfish_Secrets_InteractionParameters_unref(ctxt->params);
            free(ctxt);
        }
    }
}

void deleteCollection_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to delete collection: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
    } else {
        tst_secretscrypto_return = 0; /* success! */
    }
    tst_secretscrypto_complete = 1;
}

void getSecret_callback(void *context, struct Sailfish_Secrets_Result *result, struct Sailfish_Secrets_Secret *secret)
{
    struct CallbackContext *cb_ctxt = (struct CallbackContext *)context;
    struct Sailfish_Secrets_Secret *set_secret = cb_ctxt->secret;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to get secret: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    } else if (secret->dataSize != set_secret->dataSize) {
        fprintf(stderr, "Retrieved secret data size different! %d != %d\n",
                secret->dataSize, set_secret->dataSize);
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    } else if (memcmp(secret->data,
                      set_secret->data,
                      set_secret->dataSize) != 0) {
        fprintf(stderr, "Retrieved secret data different!\n");
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    } else if (!Sailfish_Secrets_SecretManager_deleteCollection(
                "tst_capi_collection",
                "org.sailfishos.secrets.plugin.storage.sqlite.test",
                Sailfish_Secrets_SecretManager_PreventInteraction,
                "",
                deleteCollection_callback,
                NULL)) {
        fprintf(stderr, "Unable to call deleteCollection!\n");
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    }
    CallbackContext_unref(cb_ctxt);
}

void setSecret_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    struct CallbackContext *cb_ctxt = (struct CallbackContext *)context;
    struct Sailfish_Secrets_Secret *set_secret = cb_ctxt->secret;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to set secret: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    } else if (!Sailfish_Secrets_SecretManager_getSecret(
                    set_secret->identifier,
                    Sailfish_Secrets_SecretManager_PreventInteraction,
                    "",
                    getSecret_callback,
                    cb_ctxt)) {
        fprintf(stderr, "Unable to call getSecret!\n");
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    }
}

void createCollection_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to create collection: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    } else {
        unsigned char set_secret_data[16] = {
            's', 'e', 'c', 'r', 'e', 't',
            ' ', 'd', 'a', 't', 'a', '\0',
            '\0', '\0', '\0', '\0'
        };
        struct Sailfish_Secrets_Secret *set_secret
                = Sailfish_Secrets_Secret_new(set_secret_data, 16);
        Sailfish_Secrets_Secret_setIdentifier(
                    set_secret, "tst_capi_secret", "tst_capi_collection",
                    "org.sailfishos.secrets.plugin.storage.sqlite.test");
        Sailfish_Secrets_Secret_addFilter(set_secret, "type", "blob");
        Sailfish_Secrets_Secret_addFilter(set_secret, "test", "true");

        struct Sailfish_Secrets_InteractionParameters *ui_params
                = Sailfish_Secrets_InteractionParameters_new(
                    "", "", 0, 0);

        struct CallbackContext *cb_ctxt = CallbackContext_new(
                    set_secret, ui_params);

        if (!Sailfish_Secrets_SecretManager_setSecret(
                    set_secret,
                    ui_params,
                    Sailfish_Secrets_SecretManager_PreventInteraction,
                    "",
                    setSecret_callback,
                    cb_ctxt)) {
            fprintf(stderr, "Unable to call setSecret!\n");
            tst_secretscrypto_return = 1;
            tst_secretscrypto_complete = 1;
        }
    }
}

void connectToServer_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to connect to sailfishsecretsd: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    } else if (!Sailfish_Secrets_SecretManager_createCollection(
                        "tst_capi_collection",
                        "org.sailfishos.secrets.plugin.storage.sqlite.test",
                        "org.sailfishos.secrets.plugin.encryption.openssl.test",
                        Sailfish_Secrets_SecretManager_DeviceLockKeepUnlocked,
                        Sailfish_Secrets_SecretManager_OwnerOnlyMode,
                        createCollection_callback,
                        NULL)) {
        fprintf(stderr, "Unable to call createCollection!\n");
        tst_secretscrypto_return = 1;
        tst_secretscrypto_complete = 1;
    }
}

gboolean end_test_if_complete(gpointer user_data)
{
    if (tst_secretscrypto_complete) {
        g_main_loop_quit((GMainLoop*)user_data);
        return FALSE;
    }
    return TRUE;
}

int main(int argc, char *argv[])
{
    GMainLoop *loop = g_main_loop_new(NULL, FALSE);
    (void)argc;
    (void)argv;
    g_timeout_add (50, end_test_if_complete, loop);
    if (!Sailfish_Secrets_connectToServer(connectToServer_callback, NULL)) {
        fprintf(stderr, "Unable to connect to sailfishsecretsd!\n");
        tst_secretscrypto_return = 1;
    } else {
        g_main_loop_run(loop);
        g_main_loop_unref(loop);
    }
    if (tst_secretscrypto_return == 0) {
        fprintf(stdout, "PASS!\n");
    } else {
        fprintf(stdout, "FAIL!\n");
    }
    return tst_secretscrypto_return;
}
