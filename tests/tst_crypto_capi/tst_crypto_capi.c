#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include <Crypto/crypto_c.h>

int main(int argc, char *argv[])
{
    struct Sailfish_Crypto_Result *result = NULL;
    struct Sailfish_Crypto_Key *get_key = NULL;

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
                "tst_capi_key",
                "tst_capi_collection");
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

    if (!Sailfish_Crypto_CryptoManager_generateKey(
                set_key,
                "org.sailfishos.crypto.plugin.crypto.openssl.test",
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
                "org.sailfishos.crypto.plugin.crypto.openssl.test",
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
                "org.sailfishos.crypto.plugin.crypto.openssl.test",
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
    Sailfish_Crypto_Key_delete(get_key);
    free(ciphertext);
    free(decrypted);

    Sailfish_Crypto_disconnectFromServer();

    fprintf(stdout, "PASS!\n");

    return 0;
}
