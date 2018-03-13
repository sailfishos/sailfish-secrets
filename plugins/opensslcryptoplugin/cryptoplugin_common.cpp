/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"

#include <QtCore/QTimer>
#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>
#include <QtDebug>

#include <fstream>
#include <cstdlib>
#include <limits>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#define CIPHER_SESSION_INACTIVITY_TIMEOUT 60000 /* 1 minute, change to 10 sec for timeout test */
#define MAX_CIPHER_SESSIONS_PER_CLIENT 5
#define SAILFISH_CRYPTO_GCM_TAG_SIZE 16

class CipherSessionData
{
public:
    QByteArray iv;
    Sailfish::Crypto::Key key;
    Sailfish::Crypto::CryptoManager::Operation operation = Sailfish::Crypto::CryptoManager::OperationUnknown;
    Sailfish::Crypto::CryptoManager::BlockMode blockMode = Sailfish::Crypto::CryptoManager::BlockModeUnknown;
    Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding = Sailfish::Crypto::CryptoManager::EncryptionPaddingUnknown;
    Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding = Sailfish::Crypto::CryptoManager::SignaturePaddingUnknown;
    Sailfish::Crypto::CryptoManager::DigestFunction digestFunction = Sailfish::Crypto::CryptoManager::DigestUnknown;
    quint32 cipherSessionToken = 0;
    QByteArray generatedIV;
    EVP_MD_CTX *evp_md_ctx = nullptr;
    EVP_CIPHER_CTX *evp_cipher_ctx = nullptr;
    QTimer *timeout;
};
struct CipherSessionDataDeleter
{
    static inline void cleanup(CipherSessionData *csd)
    {
        if (csd->evp_cipher_ctx) {
            EVP_CIPHER_CTX_free(csd->evp_cipher_ctx);
        }
        if (csd->evp_md_ctx) {
            EVP_MD_CTX_destroy(csd->evp_md_ctx);
        }
        if (csd->timeout) {
            csd->timeout->deleteLater();
        }
        delete csd;
    }
};
struct LibCrypto_BN_Deleter
{
    static inline void cleanup(BIGNUM *pointer)
    {
        BN_free(pointer);
    }
};
struct LibCrypto_RSA_Deleter
{
    static inline void cleanup(RSA *pointer)
    {
        RSA_free(pointer);
    }
};
struct LibCrypto_BIO_Deleter
{
    static inline void cleanup(BIO *pointer)
    {
        BIO_free(pointer);
    }
};

namespace {
    quint32 getNextCipherSessionToken(QMap<quint64, QMap<quint32, CipherSessionData*> > *sessions, quint64 clientId)
    {
        if (!sessions->contains(clientId)) {
            return 1;
        } else for (quint32 possible = 1; possible < MAX_CIPHER_SESSIONS_PER_CLIENT; ++possible) {
            if (!sessions->value(clientId).contains(possible)) {
                return possible;
            }
        }
        return 0; // no cipher sessions available.
    }
}

QVector<Sailfish::Crypto::CryptoManager::Algorithm>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedAlgorithms() const
{
    QVector<Sailfish::Crypto::CryptoManager::Algorithm> retn;
    retn.append(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    return retn;
}

QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> >
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedBlockModes() const
{
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> > retn;
    retn.insert(Sailfish::Crypto::CryptoManager::AlgorithmAes, QVector<Sailfish::Crypto::CryptoManager::BlockMode>() << Sailfish::Crypto::CryptoManager::BlockModeCbc);
    return retn;
}

QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> >
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedEncryptionPaddings() const
{
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> > retn;
    retn.insert(Sailfish::Crypto::CryptoManager::AlgorithmAes, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding>() << Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> >
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedSignaturePaddings() const
{
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> > retn;
    retn.insert(Sailfish::Crypto::CryptoManager::AlgorithmAes, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding>() << Sailfish::Crypto::CryptoManager::SignaturePaddingNone);
    return retn;
}

QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> >
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedDigests() const
{
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> > retn;
    retn.insert(Sailfish::Crypto::CryptoManager::AlgorithmAes, QVector<Sailfish::Crypto::CryptoManager::DigestFunction>() << Sailfish::Crypto::CryptoManager::DigestSha256);
    return retn;
}

QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::MessageAuthenticationCode> >
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedMessageAuthenticationCodes() const
{
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::MessageAuthenticationCode> > retn;
    retn.insert(Sailfish::Crypto::CryptoManager::AlgorithmAes, QVector<Sailfish::Crypto::CryptoManager::MessageAuthenticationCode>() << Sailfish::Crypto::CryptoManager::MacHmac);
    return retn;
}

QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::KeyDerivationFunction> >
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedKeyDerivationFunctions() const
{
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::KeyDerivationFunction> > retn;
    retn.insert(Sailfish::Crypto::CryptoManager::AlgorithmAes, QVector<Sailfish::Crypto::CryptoManager::KeyDerivationFunction>() << Sailfish::Crypto::CryptoManager::KdfPkcs5Pbkdf2);
    return retn;
}

QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations>
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::supportedOperations() const
{
    // TODO: should this be algorithm specific?  not sure?
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations> retn;
    retn.insert(Sailfish::Crypto::CryptoManager::AlgorithmAes, Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    return retn;
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        QByteArray *randomData)
{
    Q_UNUSED(callerIdent)

    static const int maxBytes = 4096;
    bool useDevURandom = false;

    if (csprngEngineName == QStringLiteral("/dev/urandom")) {
        useDevURandom = true;
    } else if (csprngEngineName != Sailfish::Crypto::GenerateRandomDataRequest::DefaultCsprngEngineName) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                        QLatin1String("This crypto plugin only supports default and /dev/urandom engines"));
    }

    if (!numberBytes || numberBytes > maxBytes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                        QLatin1String("This crypto plugin can only generate up to 4096 bytes of random data at a time"));
    }

    int nbytes = numberBytes;
    QScopedArrayPointer<char> buf(new char[nbytes]);
    if (useDevURandom) {
        std::ifstream rand("/dev/urandom");
        rand.read(buf.data(), nbytes);
        rand.close();
    } else if (RAND_bytes(reinterpret_cast<unsigned char*>(buf.data()), nbytes) != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginRandomDataError,
                                        QLatin1String("This crypto plugin failed to generate the random data"));
    }

    *randomData = QByteArray(reinterpret_cast<const char *>(buf.data()), nbytes);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::validateCertificateChain(
        const QVector<Sailfish::Crypto::Certificate> &chain,
        bool *validated)
{
    Q_UNUSED(chain);
    Q_UNUSED(validated);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: validateCertificateChain"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        Sailfish::Crypto::Key *key)
{
    // generate an asymmetrical key pair if required
    if (kpgParams.isValid()) {
        if (kpgParams.keyPairType() != Sailfish::Crypto::KeyPairGenerationParameters::KeyPairRsa
                || keyTemplate.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmRsa) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("TODO: algorithms other than Rsa"));
        }
        Sailfish::Crypto::RsaKeyPairGenerationParameters rsakpgp(kpgParams);
        if (rsakpgp.modulusLength() < 8 || rsakpgp.modulusLength() > 8192 || (rsakpgp.modulusLength() % 8) != 0) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("Unsupported modulus length specified"));
        }
        if (rsakpgp.publicExponent() > std::numeric_limits<quint32>::max()) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("Unsupported public exponent, too large"));
        }
        if (rsakpgp.numberPrimes() != 2) {
            // RSA_generate_multi_prime_key doesn't exist in our version of openssl it seems.
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("Unsupported number of primes"));
        }

        quint32 publicExponent = rsakpgp.publicExponent();
        QScopedPointer<BIGNUM, LibCrypto_BN_Deleter> pubExp(BN_new());
        if (BN_set_word(pubExp.data(), publicExponent) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                            QLatin1String("Failed to set public exponent"));
        }

        QScopedPointer<RSA, LibCrypto_RSA_Deleter> rsa(RSA_new());
        if (RSA_generate_key_ex(rsa.data(), rsakpgp.modulusLength(), pubExp.data(), NULL) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                            QLatin1String("Failed to initialise RSA key pair generation"));
        }

        QScopedPointer<BIO, LibCrypto_BIO_Deleter> pubbio(BIO_new(BIO_s_mem()));
        if (PEM_write_bio_RSAPublicKey(pubbio.data(), rsa.data()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                            QLatin1String("Failed to write public key data to memory"));
        }
        size_t pubkeylen = BIO_pending(pubbio.data());
        QScopedArrayPointer<unsigned char> pubdata(new unsigned char[pubkeylen]);
        if (BIO_read(pubbio.data(), pubdata.data(), pubkeylen) < 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                            QLatin1String("Failed to read public key data from memory"));
        }

        QScopedPointer<BIO, LibCrypto_BIO_Deleter> privbio(BIO_new(BIO_s_mem()));
        if (PEM_write_bio_RSAPrivateKey(privbio.data(), rsa.data(), NULL, NULL, 0, NULL, NULL) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                            QLatin1String("Failed to write private key data to memory"));
        }
        size_t privkeylen = BIO_pending(privbio.data());
        QScopedArrayPointer<unsigned char> privdata(new unsigned char[privkeylen]);
        if (BIO_read(privbio.data(), privdata.data(), privkeylen) < 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                            QLatin1String("Failed to read private key data from memory"));
        }

        *key = keyTemplate;
        key->setPublicKey(QByteArray(reinterpret_cast<const char *>(pubdata.data()), pubkeylen));
        key->setPrivateKey(QByteArray(reinterpret_cast<const char *>(privdata.data()), privkeylen));
        key->setSize(rsakpgp.modulusLength());
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    }

    // otherwise generate a random symmetric key unless a key derivation function is required
    if (!skdfParams.isValid()) {
        if (keyTemplate.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("TODO: algorithms other than Aes"));
        }
        if (keyTemplate.size() < 8 || keyTemplate.size() > 2048 || (keyTemplate.size() % 8) != 0) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("Unsupported key size specified"));
        }
        QByteArray randomKey;
        Sailfish::Crypto::Result randomResult = generateRandomData(
                    0, QStringLiteral("/dev/urandom"), keyTemplate.size() / 8, &randomKey);
        if (randomResult.code() == Sailfish::Crypto::Result::Failed) {
            return randomResult;
        }
        *key = keyTemplate;
        key->setSecretKey(randomKey);
        key->setSize(keyTemplate.size());
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    }

    // use key derivation to derive a key from input data.
    if (skdfParams.keyDerivationFunction() != Sailfish::Crypto::CryptoManager::KdfPkcs5Pbkdf2) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("Unsupported key derivation function specified"));
    }

    if (skdfParams.keyDerivationMac() != Sailfish::Crypto::CryptoManager::MacHmac) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("Unsupported key derivation message authentication code specified"));
    }

    if (skdfParams.keyDerivationDigestFunction() != Sailfish::Crypto::CryptoManager::DigestSha1
            && skdfParams.keyDerivationDigestFunction() != Sailfish::Crypto::CryptoManager::DigestSha256
            && skdfParams.keyDerivationDigestFunction() != Sailfish::Crypto::CryptoManager::DigestSha512) {
        // TODO: support other digest functions with HMAC...
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("Unsupported key derivation digest function specified"));
    }

    if (skdfParams.outputKeySize() < 8 || skdfParams.outputKeySize() > 2048 || (skdfParams.outputKeySize() % 8) != 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("Unsupported derived key size specified"));
    }

    if (skdfParams.iterations() < 0 || skdfParams.iterations() > 32768) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("Unsupported iterations specified"));
    }

    int nbytes = skdfParams.outputKeySize() / 8;
    QScopedArrayPointer<char> buf(new char[nbytes]);
    const EVP_MD *md = skdfParams.keyDerivationDigestFunction() == Sailfish::Crypto::CryptoManager::DigestSha1
                     ? EVP_sha1()
                     : skdfParams.keyDerivationDigestFunction() == Sailfish::Crypto::CryptoManager::DigestSha256
                     ? EVP_sha256()
                     : EVP_sha512();
    if (PKCS5_PBKDF2_HMAC(
            skdfParams.inputData().isEmpty()
                    ? NULL
                    : skdfParams.inputData().constData(),
            skdfParams.inputData().size(),
            skdfParams.salt().isEmpty()
                    ? NULL
                    : reinterpret_cast<const unsigned char*>(skdfParams.salt().constData()),
            skdfParams.salt().size(),
            skdfParams.iterations(),
            md,
            nbytes,
            reinterpret_cast<unsigned char*>(buf.data())) != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                        QLatin1String("The crypto plugin failed to derive the key data"));
    }

    *key = keyTemplate;
    key->setSecretKey(QByteArray(buf.data(), nbytes));
    key->setSize(skdfParams.outputKeySize());
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::calculateDigest(
        const QByteArray &data,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        QByteArray *digest)
{
    // TODO: support more operations and algorithms in this plugin!
    Q_UNUSED(data);
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(digest);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: calculateDigest"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        QByteArray *signature)
{
    // TODO: support more operations and algorithms in this plugin!
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(signature);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: sign"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        bool *verified)
{
    // TODO: support more operations and algorithms in this plugin!
    Q_UNUSED(signature);
    Q_UNUSED(data);
    Q_UNUSED(key);
    Q_UNUSED(padding);
    Q_UNUSED(digestFunction);
    Q_UNUSED(verified);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("TODO: verify"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        QByteArray *encrypted)
{
    Sailfish::Crypto::Key fullKey = getFullKey(key);
    if (fullKey.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot encrypt with empty secret key"));
    }

    if (fullKey.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes"));
    }

    if (padding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    if (fullKey.secretKey().size() * 8 != fullKey.size()) {
        // The secret is not of the expected length (e.g. 128-bit, 256-bit)
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                        QLatin1String("Secret key size does not match"));
    }

    // Ensure the IV has the correct size. The IV size for *most* modes is the same as the block size.
    QByteArray initVector = iv;
    if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeCbc) {
        // For AES, the block size is 128 bits (i.e. 16 bytes).
        if (initVector.size() > 16) {
            initVector.chop(initVector.size() - 16);
        } else while (initVector.size() < 16) {
            initVector.append('\0');
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: block modes other than CBC"));
    }

    // encrypt plaintext
    QByteArray ciphertext = aes_encrypt_plaintext(blockMode, data, fullKey.secretKey(), initVector);

    // return result
    if (ciphertext.size()) {
        *encrypted = ciphertext;
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                     QLatin1String("OpenSSL crypto plugin failed to encrypt the data"));
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        QByteArray *decrypted)
{
    Sailfish::Crypto::Key fullKey = getFullKey(key);
    if (fullKey.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot decrypt with empty secret key"));
    }

    if (fullKey.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes"));
    }

    if (padding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    // Ensure the IV has the correct size. The IV size for most modes is the same as the block size.
    QByteArray initVector = iv;
    if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeCbc) {
        // For AES, the block size is 128 bits (i.e. 16 bytes).
        if (initVector.size() > 16) {
            initVector.chop(initVector.size() - 16);
        } else while (initVector.size() < 16) {
            initVector.append('\0');
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: block modes other than CBC"));
    }
    // decrypt ciphertext
    QByteArray plaintext = aes_decrypt_ciphertext(blockMode, data, fullKey.secretKey(), initVector);
    if (!plaintext.size() || (plaintext.size() == 1 && plaintext.at(0) == 0)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDecryptionError,
                                         QLatin1String("Failed to decrypt the secret"));
    }

    // return result
    *decrypted = plaintext;
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::initialiseCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::CryptoManager::Operation operation,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        quint32 *cipherSessionToken,
        QByteArray *generatedIV)
{
    Sailfish::Crypto::Key fullKey = getFullKey(key);
    if (fullKey.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot create a cipher session with empty secret key"));
    }

    if (fullKey.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes256"));
    }

    if (blockMode != Sailfish::Crypto::CryptoManager::BlockModeCbc) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: block modes other than CBC"));
    }

    if (encryptionPadding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    if (signaturePadding != Sailfish::Crypto::CryptoManager::SignaturePaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: signature padding other than None"));
    }

    if (digestFunction != Sailfish::Crypto::CryptoManager::DigestSha256) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: digests other than Sha256"));
    }

    quint32 sessionToken = getNextCipherSessionToken(&m_cipherSessions, clientId);
    if (sessionToken == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Too many concurrent cipher sessions initiated by client"));
    }

    QByteArray initIV(iv);
    if (operation == Sailfish::Crypto::CryptoManager::OperationEncrypt
            && fullKey.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        if (iv.size() != 16) {
            // the user-supplied IV is the wrong size.
            // generate an appropriately sized IV.
            unsigned char ivBuf[16] = { 0 };
            if (RAND_bytes(ivBuf, 16) != 1) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to generate initialisation vector"));
            }
            *generatedIV = QByteArray(reinterpret_cast<char*>(ivBuf), 16);
            initIV = *generatedIV;
        }
    }

    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_CIPHER_CTX *evp_cipher_ctx = NULL;
    if (operation == Sailfish::Crypto::CryptoManager::OperationEncrypt) {
        evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (evp_cipher_ctx == NULL) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Unable to initialise cipher context for encryption"));
        }
        if (fullKey.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmAes
                && blockMode == Sailfish::Crypto::CryptoManager::BlockModeCbc) {
            const EVP_CIPHER *evp_cipher = osslevp_aes_cipher(blockMode, fullKey.secretKey().size());
            if (evp_cipher == NULL) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Invalid key size for AES CBC operation"));
            }
            if (EVP_EncryptInit_ex(evp_cipher_ctx, evp_cipher, NULL,
                                   reinterpret_cast<const unsigned char*>(fullKey.secretKey().constData()),
                                   reinterpret_cast<const unsigned char*>(initIV.constData())) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialise encryption cipher context in AES 256 CBC mode"));
            }
        }
    } else if (operation == Sailfish::Crypto::CryptoManager::OperationDecrypt) {
        evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (evp_cipher_ctx == NULL) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Unable to initialise cipher context for decryption"));
        }
        if (fullKey.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmAes
                && blockMode == Sailfish::Crypto::CryptoManager::BlockModeCbc) {
            const EVP_CIPHER *evp_cipher = osslevp_aes_cipher(blockMode, fullKey.secretKey().size());
            if (evp_cipher == NULL) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Invalid key size for AES CBC operation"));
            }
            if (EVP_DecryptInit_ex(evp_cipher_ctx, evp_cipher, NULL,
                                   reinterpret_cast<const unsigned char *>(fullKey.secretKey().constData()),
                                   reinterpret_cast<const unsigned char *>(initIV.constData())) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialise decryption cipher context in AES 256 CBC mode"));
            }
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify data!"));
    }

    CipherSessionData *csd = new CipherSessionData;
    csd->iv = initIV;
    csd->key = fullKey;
    csd->operation = operation;
    csd->blockMode = blockMode;
    csd->encryptionPadding = encryptionPadding;
    csd->signaturePadding = signaturePadding;
    csd->digestFunction = digestFunction;
    csd->cipherSessionToken = sessionToken;
    csd->generatedIV = *generatedIV;
    csd->evp_cipher_ctx = evp_cipher_ctx;
    csd->evp_md_ctx = evp_md_ctx;
    QTimer *timeout = new QTimer(this);
    timeout->setSingleShot(true);
    timeout->setInterval(CIPHER_SESSION_INACTIVITY_TIMEOUT);
    QObject::connect(timeout, &QTimer::timeout,
                     [this, timeout] {
        CipherSessionLookup lookup(this->m_cipherSessionTimeouts.take(timeout));
        if (lookup.csd) {
            this->m_cipherSessions[lookup.clientId].remove(lookup.sessionToken);
            QScopedPointer<CipherSessionData,CipherSessionDataDeleter> csdd(lookup.csd);
        } else {
            timeout->deleteLater();
        }
    });
    timeout->start();
    csd->timeout = timeout;
    m_cipherSessions[clientId].insert(sessionToken, csd);

    CipherSessionLookup lookup;
    lookup.csd = csd;
    lookup.sessionToken = sessionToken;
    lookup.clientId = clientId;
    m_cipherSessionTimeouts.insert(timeout, lookup);

    *cipherSessionToken = sessionToken;
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        quint32 cipherSessionToken)
{
    if (!m_cipherSessions.contains(clientId)
            || !m_cipherSessions[clientId].contains(cipherSessionToken)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Unknown cipher session token provided"));
    }

    CipherSessionData *csd = m_cipherSessions[clientId].value(cipherSessionToken);
    if (csd->blockMode != Sailfish::Crypto::CryptoManager::BlockModeGcm) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Block mode is not GCM, cannot update authentication data"));
    } else if (csd->evp_cipher_ctx == NULL) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Cipher context has not been initialised"));
    }

    csd->timeout->start(); // restart the timeout due to activity.
    int len = 0;
    if (csd->operation == Sailfish::Crypto::CryptoManager::OperationEncrypt) {
        if (EVP_EncryptUpdate(csd->evp_cipher_ctx, NULL, &len,
                              reinterpret_cast<const unsigned char *>(authenticationData.constData()),
                              authenticationData.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update encryption cipher authentication data"));
        }
    } else if (csd->operation == Sailfish::Crypto::CryptoManager::OperationDecrypt) {
        if (EVP_DecryptUpdate(csd->evp_cipher_ctx, NULL, &len,
                              reinterpret_cast<const unsigned char *>(authenticationData.constData()),
                              authenticationData.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update decryption cipher authentication data"));
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify authentication data!"));
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken,
        QByteArray *generatedData)
{
    if (!m_cipherSessions.contains(clientId)
            || !m_cipherSessions[clientId].contains(cipherSessionToken)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Unknown cipher session token provided"));
    }

    CipherSessionData *csd = m_cipherSessions[clientId].value(cipherSessionToken);
    if (csd->evp_cipher_ctx == NULL) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Cipher context has not been initialised"));
    }

    csd->timeout->start(); // restart the timeout due to activity.
    int blockSizeForCipher = 16; // TODO: lookup for different algorithms, but AES is 128 bit blocks = 16 bytes
    QScopedArrayPointer<unsigned char> generatedDataBuf(new unsigned char[data.size() + blockSizeForCipher]);
    int generatedDataSize = 0;
    if (csd->operation == Sailfish::Crypto::CryptoManager::OperationEncrypt) {
        if (EVP_EncryptUpdate(csd->evp_cipher_ctx,
                              generatedDataBuf.data(), &generatedDataSize,
                              reinterpret_cast<const unsigned char *>(data.constData()),
                              data.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update encryption cipher data"));
        }
    } else if (csd->operation == Sailfish::Crypto::CryptoManager::OperationDecrypt) {
        if (EVP_DecryptUpdate(csd->evp_cipher_ctx,
                              generatedDataBuf.data(), &generatedDataSize,
                              reinterpret_cast<const unsigned char *>(data.constData()),
                              data.size()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to update decryption cipher data"));
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify data!"));
    }

    *generatedData = QByteArray(reinterpret_cast<const char *>(generatedDataBuf.data()), generatedDataSize);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::finaliseCipherSession(
        quint64 clientId,
        const QByteArray &data,
        quint32 cipherSessionToken,
        QByteArray *generatedData,
        bool *verified)
{
    if (!m_cipherSessions.contains(clientId)
            || !m_cipherSessions[clientId].contains(cipherSessionToken)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Unknown cipher session token provided"));
    }

    CipherSessionData *csd = m_cipherSessions[clientId].value(cipherSessionToken);
    if (csd->evp_cipher_ctx == NULL) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Cipher context has not been initialised"));
    }

    QScopedPointer<CipherSessionData,CipherSessionDataDeleter> csdd(m_cipherSessions[clientId].take(cipherSessionToken));
    m_cipherSessionTimeouts.remove(csd->timeout);
    int blockSizeForCipher = 16; // TODO: lookup for different algorithms, but AES is 128 bit blocks = 16 bytes
    QScopedArrayPointer<unsigned char> generatedDataBuf(new unsigned char[blockSizeForCipher*2]); // final 1 or 2 blocks.
    int generatedDataSize = 0;
    if (csd->operation == Sailfish::Crypto::CryptoManager::OperationEncrypt) {
        if (EVP_EncryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to finalise encryption cipher"));
        }
        if (csd->blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
            // in GCM mode, the finalisation above does not write extra ciphertext.
            // instead, we should retrieve the tag.
            if (generatedDataSize > 0) {
                // This should never happen.
                qWarning() << "INTERNAL ERROR: GCM finalisation produced ciphertext data!";
            }
            generatedDataBuf.reset(new unsigned char[SAILFISH_CRYPTO_GCM_TAG_SIZE]);
            generatedDataSize = SAILFISH_CRYPTO_GCM_TAG_SIZE;
            if (EVP_CIPHER_CTX_ctrl(csd->evp_cipher_ctx, EVP_CTRL_GCM_GET_TAG, generatedDataSize, generatedDataBuf.data()) != 1) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Failed to retrieve authentication tag"));
            }
        }
    } else if (csd->operation == Sailfish::Crypto::CryptoManager::OperationDecrypt) {
        if (csd->blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
            // in GCM mode, the finalisation requires setting the provided tag data.
            if (data.size() != SAILFISH_CRYPTO_GCM_TAG_SIZE) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("GCM tag data is not the expected size"));
            }
            QByteArray tagData(data);
            if (!EVP_CIPHER_CTX_ctrl(csd->evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG, data.size(),
                                     reinterpret_cast<void *>(tagData.data()))) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to set the GCM tag to finalise the cipher"));
            }
            int evpRet = EVP_DecryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize);
            *verified = evpRet > 0;
        } else {
            if (EVP_DecryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize) != 1) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Failed to finalise the decryption cipher"));
            }
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify authentication data!"));
    }

    *generatedData = QByteArray(reinterpret_cast<const char *>(generatedDataBuf.data()), generatedDataSize);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

QByteArray
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::aes_encrypt_plaintext(
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const QByteArray &plaintext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray encryptedData;
    unsigned char *encrypted = NULL;
    int size = osslevp_aes_encrypt_plaintext(blockMode,
                                             (const unsigned char *)init_vector.constData(),
                                             (const unsigned char *)key.constData(),
                                             key.size(),
                                             (const unsigned char *)plaintext.constData(),
                                             plaintext.size(),
                                             &encrypted);
    if (size <= 0) {
        return encryptedData;
    }

    encryptedData = QByteArray((const char *)encrypted, size);
    free(encrypted);
    return encryptedData;
}

QByteArray
CRYPTOPLUGINCOMMON_NAMESPACE::CRYPTOPLUGINCOMMON_CLASS::aes_decrypt_ciphertext(
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const QByteArray &ciphertext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray decryptedData;
    unsigned char *decrypted = NULL;
    int size = osslevp_aes_decrypt_ciphertext(blockMode,
                                              (const unsigned char *)init_vector.constData(),
                                              (const unsigned char *)key.constData(),
                                              key.size(),
                                              (const unsigned char *)ciphertext.constData(),
                                              ciphertext.size(),
                                              &decrypted);
    if (size <= 0) {
        return decryptedData;
    }

    decryptedData = QByteArray((const char *)decrypted, size);
    free(decrypted);
    return decryptedData;
}
