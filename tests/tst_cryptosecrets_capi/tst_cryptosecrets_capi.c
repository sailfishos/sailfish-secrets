#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <Crypto/crypto_c.h>
#include <Secrets/secrets_c.h>

int main(int argc, char *argv[])
{
    struct Sailfish_Secrets_Result *secrets_result = NULL;
    struct Sailfish_Crypto_Result *result = NULL;
    struct Sailfish_Crypto_Key *get_key = NULL;
    struct Sailfish_Crypto_Key_Identifier *ident = NULL;

    unsigned char *ciphertext = NULL;
    size_t ciphertext_size = 0;
    unsigned char *decrypted = NULL;
    size_t decrypted_size = 0;

    unsigned char plaintext[32] = {
        'a', 'b', 'c', 'd',
        'e', 'f', 'g', 'h',
        'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p',
        'q', 'r', 's', 't',
        'u', 'v', 'w', 'x',
        'y', 'z', '0', '1',
        '2', '3', '4', '\0'
    };

    struct Sailfish_Crypto_Key *set_key = Sailfish_Crypto_Key_new(
                "tstcapikey",
                "tstcapicollection");
    Sailfish_Crypto_Key_addFilter(set_key, "type", "blob");
    Sailfish_Crypto_Key_addFilter(set_key, "test", "true");
    set_key->origin = Sailfish_Crypto_Key_OriginDevice;
    set_key->algorithm = Sailfish_Crypto_Key_Aes256;
    set_key->blockModes = Sailfish_Crypto_Key_BlockModeCBC;
    set_key->encryptionPaddings = Sailfish_Crypto_Key_EncryptionPaddingNone;
    set_key->signaturePaddings = Sailfish_Crypto_Key_SignaturePaddingNone;
    set_key->digests = Sailfish_Crypto_Key_DigestSha256;
    set_key->operations = Sailfish_Crypto_Key_Encrypt | Sailfish_Crypto_Key_Decrypt;

    (void)argc;
    (void)argv;

    if (!Sailfish_Secrets_SecretManager_createCollection(
                "tstcapicollection",
                "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                Sailfish_Secrets_SecretManager_DeviceLockKeepUnlocked,
                Sailfish_Secrets_SecretManager_OwnerOnlyMode,
                &secrets_result)) {
        fprintf(stderr, "Call to createCollection failed: %d: %s\n",
                secrets_result ? secrets_result->errorCode : 0,
                secrets_result && secrets_result->errorMessage
                    ? secrets_result->errorMessage
                    : "");
        return -1;
    } else if (secrets_result && secrets_result->code !=
               Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Call to createCollection failed: %d: %s\n",
                secrets_result ? secrets_result->errorCode : 0,
                secrets_result && secrets_result->errorMessage
                    ? secrets_result->errorMessage
                    : "");
        return -1;
    }
    Sailfish_Secrets_Result_delete(secrets_result);
    secrets_result = NULL;

    if (!Sailfish_Crypto_CryptoManager_generateStoredKey(
                set_key,
                "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                &result,
                &get_key)) {
        fprintf(stderr, "Call to generateKey failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Call to generateKey failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    }
    Sailfish_Crypto_Result_delete(result);
    result = NULL;

    if (!Sailfish_Crypto_CryptoManager_encrypt(
                plaintext,
                32,
                get_key,
                Sailfish_Crypto_Key_BlockModeCBC,
                Sailfish_Crypto_Key_EncryptionPaddingNone,
                Sailfish_Crypto_Key_DigestSha256,
                "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                &result,
                &ciphertext,
                &ciphertext_size)) {
        fprintf(stderr, "Call to encrypt failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Call to encrypt failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    }
    Sailfish_Crypto_Result_delete(result);
    result = NULL;

    if (!Sailfish_Crypto_CryptoManager_decrypt(
                ciphertext, ciphertext_size,
                get_key,
                Sailfish_Crypto_Key_BlockModeCBC,
                Sailfish_Crypto_Key_EncryptionPaddingNone,
                Sailfish_Crypto_Key_DigestSha256,
                "org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test",
                &result,
                &decrypted,
                &decrypted_size)) {
        fprintf(stderr, "Call to decrypt failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Call to decrypt failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    }
    Sailfish_Crypto_Result_delete(result);
    result = NULL;

    if (decrypted_size != 32 || memcmp(decrypted, plaintext, 32) != 0) {
        fprintf(stderr, "Decrypted text not equal to original plaintext!"
                        " %d\n", decrypted_size);
        return -1;
    }

    Sailfish_Crypto_Key_delete(set_key);
    set_key = NULL;
    Sailfish_Crypto_Key_delete(get_key);
    get_key = NULL;
    free(ciphertext);
    ciphertext = NULL;
    free(decrypted);
    decrypted = NULL;

    ident = Sailfish_Crypto_Key_Identifier_new(
                "tstcapikey",
                "tstcapicollection");
    if (Sailfish_Crypto_CryptoManager_deleteStoredKey(
                ident,
                &result) < 0) {
        fprintf(stderr, "Call to deleteStoredKey failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    } else if (result && result->code != Sailfish_Crypto_Result_Succeeded) {
        fprintf(stderr, "Call to deleteStoredKey failed: %d: %d: %s\n",
                result ? result->errorCode : 0,
                result ? result->storageErrorCode : 0,
                result && result->errorMessage ? result->errorMessage : "");
        return -1;
    }
    Sailfish_Crypto_Result_delete(result);
    result = NULL;
    Sailfish_Crypto_Key_Identifier_delete(ident);
    ident = NULL;

    if (!Sailfish_Secrets_SecretManager_deleteCollection(
                "tstcapicollection",
                Sailfish_Secrets_SecretManager_PreventInteraction,
                &secrets_result)) {
        fprintf(stderr, "Call to deleteCollection failed: %d: %s\n",
                secrets_result ? secrets_result->errorCode : 0,
                secrets_result && secrets_result->errorMessage
                    ? secrets_result->errorMessage
                    : "");
        return -1;
    } else if (secrets_result && secrets_result->code !=
               Sailfish_Secrets_Result_Succeeded) {
        fprintf(stderr, "Call to deleteCollection failed: %d: %s\n",
                secrets_result ? secrets_result->errorCode : 0,
                secrets_result && secrets_result->errorMessage
                    ? secrets_result->errorMessage
                    : "");
        return -1;
    }
    Sailfish_Secrets_Result_delete(secrets_result);
    secrets_result = NULL;

    Sailfish_Crypto_disconnectFromServer();

    fprintf(stdout, "PASS!\n");

    return 0;
}
