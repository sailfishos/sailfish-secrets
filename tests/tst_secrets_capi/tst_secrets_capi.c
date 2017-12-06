#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <Secrets/secrets_c.h>

int main(int argc, char *argv[])
{
    struct Sailfish_Secrets_Result *result = NULL;
    struct Sailfish_Secrets_Secret *get_secret = NULL;

    unsigned char set_secret_data[16] = {
        's', 'e', 'c', 'r', 'e', 't',
        ' ', 'd', 'a', 't', 'a', '\0',
        '\0', '\0', '\0', '\0'
    };
    struct Sailfish_Secrets_Secret *set_secret = Sailfish_Secrets_Secret_new(
                set_secret_data, 16);
    Sailfish_Secrets_Secret_setIdentifier(set_secret,
                                          "tst_capi_secret",
                                          "tst_capi_collection");
    Sailfish_Secrets_Secret_addFilter(set_secret, "type", "blob");
    Sailfish_Secrets_Secret_addFilter(set_secret, "test", "true");

    (void)argc;
    (void)argv;

    if (!Sailfish_Secrets_SecretManager_createCollection(
                "tst_capi_collection",
                "org.sailfishos.secrets.plugin.storage.sqlite.test",
                "org.sailfishos.secrets.plugin.encryption.openssl.test",
                Sailfish_Secrets_SecretManager_DeviceLockKeepUnlocked,
                Sailfish_Secrets_SecretManager_OwnerOnlyMode,
                &result)) {
        fprintf(stderr, "Call to createCollection failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Call to createCollection failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    }
    Sailfish_Secrets_Result_delete(result);
    result = NULL;

    if (!Sailfish_Secrets_SecretManager_setSecret(
                set_secret,
                Sailfish_Secrets_SecretManager_PreventInteraction,
                "",
                &result)) {
        fprintf(stderr, "Call to setSecret failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Call to setSecret failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    }
    Sailfish_Secrets_Result_delete(result);
    result = NULL;

    if (!Sailfish_Secrets_SecretManager_getSecret(
                set_secret->identifier,
                Sailfish_Secrets_SecretManager_PreventInteraction,
                "",
                &result,
                &get_secret)) {
        fprintf(stderr, "Call to getSecret failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Call to getSecret failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (get_secret->dataSize != set_secret->dataSize) {
        fprintf(stderr, "Retrieved secret data size different! %d != %d\n",
                get_secret->dataSize, set_secret->dataSize);
        return -1;
    } else if (memcmp(get_secret->data,
                      set_secret->data,
                      set_secret->dataSize) != 0) {
        fprintf(stderr, "Retrieved secret data different!\n");
        return -1;
    }
    Sailfish_Secrets_Result_delete(result);
    result = NULL;

    if (!Sailfish_Secrets_SecretManager_deleteCollection(
                "tst_capi_collection",
                Sailfish_Secrets_SecretManager_PreventInteraction,
                &result)) {
        fprintf(stderr, "Call to deleteCollection failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Call to deleteCollection failed: %d: %s\n",
                result ? result->errorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    }

    Sailfish_Secrets_Result_delete(result);
    Sailfish_Secrets_Secret_delete(set_secret);
    Sailfish_Secrets_Secret_delete(get_secret);

    fprintf(stdout, "PASS!\n");

    return 0;
}
