/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <SecretsCrypto/secrets.h>
#include <SecretsCrypto/crypto.h>

#include <glib.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* TODO: this should be rewritten as a centrally-dispatched state machine */

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

static struct Sailfish_Crypto_Key *tst_secretscrypto_generatedkey = NULL;
static struct Sailfish_Crypto_Key *tst_secretscrypto_storedkey = NULL;
static size_t tst_secretscrypto_generatedkey_encrypted_size = 0;
static unsigned char *tst_secretscrypto_generatedkey_encrypted = NULL;
static size_t tst_secretscrypto_storedkey_encrypted_size = 0;
static unsigned char *tst_secretscrypto_storedkey_encrypted = NULL;
static size_t tst_secretscrypto_plaintext_size = 16;
static unsigned char tst_secretscrypto_plaintext[16] = {
    's', 'e', 'c', 'r', 'e', 't',
    ' ', 'd', 'a', 't', 'a', '\0',
    '\0', '\0', '\0', '\0'
};

void secrets_disconnect_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to disconnect from secrets daemon: %s\n", result->errorMessage);
    }
    tst_secretscrypto_complete = 1;
}

void crypto_disconnect_callback(void *context, struct Sailfish_Crypto_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to disconnect from crypto daemon: %s\n", result->errorMessage);
    }
    if (!Sailfish_Secrets_disconnectFromServer(secrets_disconnect_callback, NULL)) {
        fprintf(stderr, "Unable to disconnect from secrets daemon after disconnecting from crypto daemon!\n");
        tst_secretscrypto_complete = 1;
    }
}

void cleanup_connections()
{
    if (!Sailfish_Crypto_disconnectFromServer(crypto_disconnect_callback, NULL)) {
        fprintf(stderr, "Unable to disconnect from crypto daemon!\n");
        if (!Sailfish_Secrets_disconnectFromServer(secrets_disconnect_callback, NULL)) {
            fprintf(stderr, "Unable to disconnect from secrets daemon!\n");
            tst_secretscrypto_complete = 1;
        }
    }
}

void crypto_deleteCollection_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to delete crypto collection: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        /* successfully finished test */
        tst_secretscrypto_return = 0;
        cleanup_connections();
    }
}

void crypto_storedKey_decrypt_callback(void *context, struct Sailfish_Crypto_Result *result, unsigned char *data, size_t dataSize)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to decrypt with stored key: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        if (!data || !dataSize) {
            fprintf(stderr, "Invalid data decrypted with generated key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else if (dataSize != tst_secretscrypto_plaintext_size) {
            fprintf(stderr, "Invalid data size decrypted with stored key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else if (memcmp(tst_secretscrypto_plaintext, data, tst_secretscrypto_plaintext_size) != 0) {
            fprintf(stderr, "Different data decrypted with stored key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else if (!Sailfish_Secrets_SecretManager_deleteCollection(
                    "tstcapicryptocollection",
                    "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                    Sailfish_Secrets_SecretManager_PreventInteraction,
                    "",
                    crypto_deleteCollection_callback,
                    NULL)) {
            fprintf(stderr, "Unable to call deleteCollection for crypto!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        }
    }
}

void crypto_storedKey_encrypt_callback(void *context, struct Sailfish_Crypto_Result *result, unsigned char *data, size_t dataSize)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to encrypt with stored key: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        if (!data || !dataSize) {
            fprintf(stderr, "Invalid data encrypted with stored key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else {
            tst_secretscrypto_storedkey_encrypted_size = dataSize;
            tst_secretscrypto_storedkey_encrypted = (unsigned char *)malloc(dataSize);
            memcpy(tst_secretscrypto_storedkey_encrypted, data, dataSize);
            if (!Sailfish_Crypto_CryptoManager_decrypt(
                        tst_secretscrypto_storedkey_encrypted,
                        tst_secretscrypto_storedkey_encrypted_size,
                        tst_secretscrypto_storedkey,
                        Sailfish_Crypto_BlockModeCbc,
                        Sailfish_Crypto_EncryptionPaddingNone,
                        Sailfish_Crypto_DigestSha256,
                        "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                        crypto_storedKey_decrypt_callback,
                        NULL)) {
                fprintf(stderr, "Unable to call decrypt with storedKey!\n");
                tst_secretscrypto_return = 1;
                cleanup_connections();
            }
        }
    }
}

void crypto_generateStoredKey_callback(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *key)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to generate stored crypto key: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        Sailfish_Crypto_Key_ref(key);
        tst_secretscrypto_storedkey = key;
        if (!Sailfish_Crypto_CryptoManager_encrypt(
                    tst_secretscrypto_plaintext,
                    16,
                    tst_secretscrypto_storedkey,
                    Sailfish_Crypto_BlockModeCbc,
                    Sailfish_Crypto_EncryptionPaddingNone,
                    Sailfish_Crypto_DigestSha256,
                    "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                    crypto_storedKey_encrypt_callback,
                    NULL)) {
            fprintf(stderr, "Unable to call encrypt with storedKey!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        }
    }
}

void crypto_generatedKey_decrypt_callback(void *context, struct Sailfish_Crypto_Result *result, unsigned char *data, size_t dataSize)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to decrypt with generated key: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        if (!data || !dataSize) {
            fprintf(stderr, "Invalid data decrypted with generated key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else if (dataSize != tst_secretscrypto_plaintext_size) {
            fprintf(stderr, "Invalid data size decrypted with generated key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else if (memcmp(tst_secretscrypto_plaintext, data, tst_secretscrypto_plaintext_size) != 0) {
            fprintf(stderr, "Different data decrypted with generated key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else {
            struct Sailfish_Crypto_Key *key_template = Sailfish_Crypto_Key_new(
                        "tstcapicryptosecret", "tstcapicryptocollection",
                        "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test");
            key_template->origin = Sailfish_Crypto_Key_OriginDevice;
            key_template->algorithm = Sailfish_Crypto_AlgorithmAes;
            key_template->operations = Sailfish_Crypto_Key_OperationEncrypt
                | Sailfish_Crypto_Key_OperationDecrypt;
            key_template->componentConstraints = Sailfish_Crypto_Key_MetaData
                | Sailfish_Crypto_Key_PublicKeyData
                | Sailfish_Crypto_Key_PrivateKeyData;
            key_template->size = 256;
            Sailfish_Crypto_Key_addFilter(key_template, "test", "true");
            if (!Sailfish_Crypto_CryptoManager_generateStoredKey(
                        key_template,
                        "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                        crypto_generateStoredKey_callback,
                        NULL)) {
                fprintf(stderr, "Unable to call generateStoredKey!\n");
                tst_secretscrypto_return = 1;
                cleanup_connections();
            }
            Sailfish_Crypto_Key_unref(key_template);
        }
    }
}

void crypto_generatedKey_encrypt_callback(void *context, struct Sailfish_Crypto_Result *result, unsigned char *data, size_t dataSize)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to encrypt with generated key: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        if (!data || !dataSize) {
            fprintf(stderr, "Invalid data encrypted with generated key!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        } else {
            tst_secretscrypto_generatedkey_encrypted_size = dataSize;
            tst_secretscrypto_generatedkey_encrypted = (unsigned char *)malloc(dataSize);
            memcpy(tst_secretscrypto_generatedkey_encrypted, data, dataSize);
            if (!Sailfish_Crypto_CryptoManager_decrypt(
                        tst_secretscrypto_generatedkey_encrypted,
                        tst_secretscrypto_generatedkey_encrypted_size,
                        tst_secretscrypto_generatedkey,
                        Sailfish_Crypto_BlockModeCbc,
                        Sailfish_Crypto_EncryptionPaddingNone,
                        Sailfish_Crypto_DigestSha256,
                        "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                        crypto_generatedKey_decrypt_callback,
                        NULL)) {
                fprintf(stderr, "Unable to call decrypt with generatedKey!\n");
                tst_secretscrypto_return = 1;
                cleanup_connections();
            }
        }
    }
}

void crypto_generateKey_callback(void *context, struct Sailfish_Crypto_Result *result, struct Sailfish_Crypto_Key *key)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to generate crypto key: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        Sailfish_Crypto_Key_ref(key);
        tst_secretscrypto_generatedkey = key;
        if (!Sailfish_Crypto_CryptoManager_encrypt(
                    tst_secretscrypto_plaintext,
                    16,
                    tst_secretscrypto_generatedkey,
                    Sailfish_Crypto_BlockModeCbc,
                    Sailfish_Crypto_EncryptionPaddingNone,
                    Sailfish_Crypto_DigestSha256,
                    "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                    crypto_generatedKey_encrypt_callback,
                    NULL)) {
            fprintf(stderr, "Unable to call encrypt with generatedKey!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        }
    }
}

void crypto_createCollection_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to create crypto collection: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        struct Sailfish_Crypto_Key *key_template = Sailfish_Crypto_Key_new(
                    "tst_capi_crypto_secret", "", "");
        key_template->origin = Sailfish_Crypto_Key_OriginDevice;
        key_template->algorithm = Sailfish_Crypto_AlgorithmAes;
        key_template->operations = Sailfish_Crypto_Key_OperationEncrypt
                | Sailfish_Crypto_Key_OperationDecrypt;
        key_template->componentConstraints = Sailfish_Crypto_Key_MetaData
                | Sailfish_Crypto_Key_PublicKeyData
                | Sailfish_Crypto_Key_PrivateKeyData;
        key_template->size = 256;
        Sailfish_Crypto_Key_addFilter(key_template, "test", "true");
        if (!Sailfish_Crypto_CryptoManager_generateKey(
                    key_template,
                    "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                    crypto_generateKey_callback,
                    NULL)) {
            fprintf(stderr, "Unable to call generateKey!\n");
            tst_secretscrypto_return = 1;
            cleanup_connections();
        }
        Sailfish_Crypto_Key_unref(key_template);
    }
}

void crypto_connectToServer_callback(void *context, struct Sailfish_Crypto_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Failed to connect to crypto endpoint: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else if (!Sailfish_Secrets_SecretManager_createCollection(
                        "tstcapicryptocollection",
                        "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                        "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                        Sailfish_Secrets_SecretManager_DeviceLockKeepUnlocked,
                        Sailfish_Secrets_SecretManager_OwnerOnlyMode,
                        crypto_createCollection_callback,
                        NULL)) {
        fprintf(stderr, "Unable to call createCollection for crypto storage!\n");
        tst_secretscrypto_return = 1;
        cleanup_connections();
    }
}

void deleteCollection_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to delete collection: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else if (!Sailfish_Crypto_connectToServer(crypto_connectToServer_callback, NULL)) {
        fprintf(stderr, "Unable to connect to crypto endpoint!\n");
        tst_secretscrypto_return = 1;
        cleanup_connections();
    }
}

void getSecret_callback(void *context, struct Sailfish_Secrets_Result *result, struct Sailfish_Secrets_Secret *secret)
{
    struct CallbackContext *cb_ctxt = (struct CallbackContext *)context;
    struct Sailfish_Secrets_Secret *set_secret = cb_ctxt->secret;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to get secret: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else if (secret->dataSize != set_secret->dataSize) {
        fprintf(stderr, "Retrieved secret data size different! %d != %d\n",
                secret->dataSize, set_secret->dataSize);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else if (memcmp(secret->data,
                      set_secret->data,
                      set_secret->dataSize) != 0) {
        fprintf(stderr, "Retrieved secret data different!\n");
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else if (!Sailfish_Secrets_SecretManager_deleteCollection(
                "tst_capi_collection",
                "org.sailfishos.secrets.plugin.storage.sqlite.test",
                Sailfish_Secrets_SecretManager_PreventInteraction,
                "",
                deleteCollection_callback,
                NULL)) {
        fprintf(stderr, "Unable to call deleteCollection!\n");
        tst_secretscrypto_return = 1;
        cleanup_connections();
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
        cleanup_connections();
    } else if (!Sailfish_Secrets_SecretManager_getSecret(
                    set_secret->identifier,
                    Sailfish_Secrets_SecretManager_PreventInteraction,
                    "",
                    getSecret_callback,
                    cb_ctxt)) {
        fprintf(stderr, "Unable to call getSecret!\n");
        tst_secretscrypto_return = 1;
        cleanup_connections();
    }
}

void createCollection_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to create collection: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
    } else {
        struct Sailfish_Secrets_Secret *set_secret
                = Sailfish_Secrets_Secret_new(
                    tst_secretscrypto_plaintext,
                    tst_secretscrypto_plaintext_size);
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
            cleanup_connections();
        }
    }
}

void connectToServer_callback(void *context, struct Sailfish_Secrets_Result *result)
{
    (void)context;
    if (result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Failed to connect to sailfishsecretsd: %s\n", result->errorMessage);
        tst_secretscrypto_return = 1;
        cleanup_connections();
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
        cleanup_connections();
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
    Sailfish_Crypto_Key_unref(tst_secretscrypto_generatedkey);
    Sailfish_Crypto_Key_unref(tst_secretscrypto_storedkey);
    free(tst_secretscrypto_generatedkey_encrypted);
    free(tst_secretscrypto_storedkey_encrypted);
    if (tst_secretscrypto_return == 0) {
        fprintf(stdout, "PASS!\n");
    } else {
        fprintf(stdout, "FAIL!\n");
    }
    return tst_secretscrypto_return;
}
