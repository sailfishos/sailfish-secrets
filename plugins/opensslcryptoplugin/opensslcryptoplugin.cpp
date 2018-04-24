/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "opensslcryptoplugin.h"
#include "evp_p.h"
#include "evp_helpers_p.h"

#include "Crypto/key.h"
#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/seedrandomdatageneratorrequest.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>

#include <fstream>
#include <cstdlib>

#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>

Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)

using namespace Sailfish::Crypto;

Daemon::Plugins::OpenSslCryptoPlugin::OpenSslCryptoPlugin(QObject *parent)
    : QObject(parent)
{
    // initialize EVP
    OpenSslEvp::init();

    // seed the RNG
    char seed[1024] = {0};
    std::ifstream rand("/dev/urandom");
    rand.read(seed, 1024);
    rand.close();
    RAND_add(seed, 1024, 1.0);
}

Daemon::Plugins::OpenSslCryptoPlugin::~OpenSslCryptoPlugin()
{
    OpenSslEvp::cleanup();
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::seedRandomDataGenerator(
        quint64 callerIdent,
        const QString &csprngEngineName,
        const QByteArray &seedData,
        double entropyEstimate,
        const QVariantMap & /* customParameters */)
{
    Q_UNUSED(callerIdent)

    if (csprngEngineName != GenerateRandomDataRequest::DefaultCsprngEngineName) {
        return Result(Result::CryptoPluginRandomDataError,
                      QLatin1String("The OpenSSL crypto plugin doesn't currently support other RNG engines")); // TODO!
    }

    // Note: this will affect all clients, as we don't currently separate RNGs based on callerIdent.
    // TODO: initialize separate RNG engine instances for separate callers?
    RAND_add(seedData.constData(), seedData.size(), entropyEstimate);
    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::generateAndStoreKey(
        const Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap & /* customParameters */,
        Key *keyMetadata)
{
    Q_UNUSED(keyTemplate);
    Q_UNUSED(kpgParams);
    Q_UNUSED(skdfParams);
    Q_UNUSED(keyMetadata);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::importAndStoreKey(
        const Sailfish::Crypto::Key &key,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Key *keyMetadata)
{
    Q_UNUSED(key);
    Q_UNUSED(passphrase);
    Q_UNUSED(customParameters);
    Q_UNUSED(keyMetadata);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::storedKey(
        const Key::Identifier &identifier,
        Key::Components keyComponents,
        Key *key)
{
    Q_UNUSED(identifier);
    Q_UNUSED(keyComponents);
    Q_UNUSED(key);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Result
Daemon::Plugins::OpenSslCryptoPlugin::storedKeyIdentifiers(
        const QString &collectionName,
        QVector<Key::Identifier> *identifiers)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(identifiers);
    return Result(Result::UnsupportedOperation,
                  QLatin1String("The OpenSSL crypto plugin doesn't support storing keys"));
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::generateRandomData(
        quint64 callerIdent,
        const QString &csprngEngineName,
        quint64 numberBytes,
        const QVariantMap & /* customParameters */,
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
Daemon::Plugins::OpenSslCryptoPlugin::generateInitializationVector(
        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        int keySize,
        const QVariantMap & /* customParameters */,
        QByteArray *generatedIV)
{
    int ivSize = initializationVectorSize(algorithm, blockMode, keySize);
    if (ivSize < 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("Unable to generate initialization vector for this configuration"));
    }
    if (ivSize == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    }

    unsigned char *ivBuf = (unsigned char *)malloc(ivSize);
    memset(ivBuf, 0, ivSize);

    if (RAND_bytes(ivBuf, ivSize) <= 0) {
        free(ivBuf);
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("Unable to generate initialization vector"));
    }

    *generatedIV = QByteArray(reinterpret_cast<char*>(ivBuf), ivSize);
    free(ivBuf);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::generateRsaKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        Sailfish::Crypto::Key *key)
{
    Q_UNUSED(skdfParams);

    if (kpgParams.keyPairType() != Sailfish::Crypto::KeyPairGenerationParameters::KeyPairRsa
            || keyTemplate.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmRsa) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("This method can only generate RSA keys."));
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
                                        QLatin1String("Failed to initialize RSA key pair generation"));
    }

    QScopedPointer<BIO, LibCrypto_BIO_Deleter> pubbio(BIO_new(BIO_s_mem()));
    if (PEM_write_bio_RSA_PUBKEY(pubbio.data(), rsa.data()) != 1) {
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

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::generateEcKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        Sailfish::Crypto::Key *key)
{
    Q_UNUSED(skdfParams);

    if (kpgParams.keyPairType() != Sailfish::Crypto::KeyPairGenerationParameters::KeyPairEc
            || keyTemplate.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmEc) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("This method can only generate EC keys."));
    }

    EcKeyPairGenerationParameters ecParams(kpgParams);

    int curveNid = getEllipticCurveNid(ecParams.ellipticCurve());
    if (curveNid == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The given elliptic curve is not supported."));
    }

    int curveKeySize = getEllipticCurveKeySize(ecParams.ellipticCurve());
    if (curveKeySize == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The given elliptic curve is not supported."));
    }

    uint8_t *privateKeyBuffer = Q_NULLPTR;
    size_t privateKeySize = 0;
    uint8_t *publicKeyBuffer = Q_NULLPTR;
    size_t publicKeySize = 0;
    int r = OpenSslEvp::generate_ec_key(curveNid,
                                    &publicKeyBuffer,
                                    &publicKeySize,
                                    &privateKeyBuffer,
                                    &privateKeySize);

    // Check result from EVP
    if (r == -2) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The given elliptic curve is not supported by OpenSSL."));
    }
    if (r != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                        QLatin1String("Error happened while generating the EC key."));
    }

    // Set resulting key
    *key = keyTemplate;
    key->setAlgorithm(CryptoManager::AlgorithmEc);
    key->setPrivateKey(QByteArray(reinterpret_cast<const char*>(privateKeyBuffer), privateKeySize));
    key->setPublicKey(QByteArray(reinterpret_cast<const char*>(publicKeyBuffer), publicKeySize));
    key->setSize(curveKeySize);

    // Free the remaining OpenSSL data
    OPENSSL_free(privateKeyBuffer);
    OPENSSL_free(publicKeyBuffer);

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
        const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
        const QVariantMap & /* customParameters */,
        Sailfish::Crypto::Key *key)
{
    // generate an asymmetrical key pair if required
    if (kpgParams.isValid()) {
        switch (kpgParams.keyPairType()) {
            case Sailfish::Crypto::KeyPairGenerationParameters::KeyPairRsa:
                return generateRsaKey(keyTemplate,
                                      kpgParams,
                                      skdfParams,
                                      key);
            case Sailfish::Crypto::KeyPairGenerationParameters::KeyPairEc:
                return generateEcKey(keyTemplate,
                                     kpgParams,
                                     skdfParams,
                                     key);
            default:
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                                QLatin1String("Can't generate specified key type, it's not supported yet."));
        }
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
                    0, QStringLiteral("/dev/urandom"), keyTemplate.size() / 8, QVariantMap(),
                    &randomKey);
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
    if (OpenSslEvp::pkcs5_pbkdf2_hmac(
                skdfParams.inputData().constData(),
                skdfParams.inputData().size(),
                skdfParams.salt().isEmpty()
                        ? NULL
                        : reinterpret_cast<const unsigned char*>(skdfParams.salt().constData()),
                skdfParams.salt().size(),
                skdfParams.iterations(),
                static_cast<int>(skdfParams.keyDerivationDigestFunction()),
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

struct PassphraseData
{
    const QByteArray &passphrase;
    bool requested;
};

static int importKeyPassphraseCallback(char *buffer, int size, int, void *userData)
{
    PassphraseData * const passphraseData = static_cast<PassphraseData *>(userData);

    if (passphraseData->requested) { // Paranoid check in case the callback is called repeatedly.
        return 0;
    }

    passphraseData->requested = true;

    const int length = qMin(passphraseData->passphrase.length(), size);
    if (length > 0) {
        memcpy(buffer, passphraseData->passphrase.data(), length);
    }
    return length;
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::importKey(
        const Sailfish::Crypto::Key &key,
        const QByteArray &passphrase,
        const QVariantMap &customParameters,
        Sailfish::Crypto::Key *importedKey)
{
    Q_UNUSED(customParameters);

    *importedKey = key;

    QByteArray privateKey = key.privateKey();
    QByteArray publicKey = key.publicKey();

    if (privateKey.isEmpty()) {
        privateKey = key.secretKey();
    }

    importedKey->setPrivateKey(QByteArray());
    importedKey->setPublicKey(QByteArray());
    importedKey->setSecretKey(QByteArray());

    EVP_PKEY *pkeyPtr = Q_NULLPTR;

    PassphraseData passphraseData { passphrase, false };

    const bool exportPrivate = !privateKey.isEmpty();

    if (!privateKey.isEmpty()) {
        QScopedPointer<BIO, LibCrypto_BIO_Deleter> bio(
                    BIO_new_mem_buf(const_cast<char *>(privateKey.data()), privateKey.size()));

        PEM_read_bio_PrivateKey(bio.data(), &pkeyPtr, importKeyPassphraseCallback, &passphraseData);
    } else if (!publicKey.isEmpty()) {
        QScopedPointer<BIO, LibCrypto_BIO_Deleter> bio(
                    BIO_new_mem_buf(const_cast<char *>(publicKey.data()), publicKey.size()));

        PEM_read_bio_PUBKEY(bio.data(), &pkeyPtr, importKeyPassphraseCallback, &passphraseData);
    } else {
        return Result(Result::CryptoPluginKeyImportError, QLatin1String("No key data provided"));
    }

    if (!pkeyPtr) {
        if (passphraseData.requested) {
            return Result(Result::CryptoPluginIncorrectPassphrase, QLatin1String("Incorrect passphrase"));
        } else {
            return Result(Result::CryptoPluginKeyImportError, QLatin1String("Key read error"));
        }
    }

    QScopedPointer<EVP_PKEY, LibCrypto_EVP_PKEY_Deleter> pkey(pkeyPtr);

    switch (EVP_PKEY_base_id(pkey.data())) {
    case EVP_PKEY_RSA:
        importedKey->setAlgorithm(CryptoManager::AlgorithmRsa);
        break;
    case EVP_PKEY_DSA:
        importedKey->setAlgorithm(CryptoManager::AlgorithmDsa);
        break;
    case EVP_PKEY_DH:
        importedKey->setAlgorithm(CryptoManager::AlgorithmDh);
        break;
    case EVP_PKEY_EC:
        importedKey->setAlgorithm(CryptoManager::AlgorithmEc);
        break;
    default:
        importedKey->setAlgorithm(CryptoManager::AlgorithmUnknown);
        break;
    }

    {
        QScopedPointer<BIO, LibCrypto_BIO_Deleter> pubbio(BIO_new(BIO_s_mem()));
        if (PEM_write_bio_PUBKEY(pubbio.data(), pkey.data()) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyImportError,
                                            QLatin1String("Failed to write public key data to memory"));
        }

        publicKey.resize(BIO_pending(pubbio.data()));
        if (BIO_read(pubbio.data(), reinterpret_cast<unsigned char *>(publicKey.data()), publicKey.length()) < 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyImportError,
                                            QLatin1String("Failed to read public key data from memory"));
        }
    }

    if (exportPrivate) {
        QScopedPointer<BIO, LibCrypto_BIO_Deleter> privbio(BIO_new(BIO_s_mem()));
        if (PEM_write_bio_PrivateKey(privbio.data(), pkey.data(), NULL, NULL, 0, NULL, NULL) < 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyImportError,
                                            QLatin1String("Failed to write private key data to memory"));
        }

        privateKey.resize(BIO_pending(privbio.data()));
        if (BIO_read(privbio.data(), reinterpret_cast<unsigned char *>(privateKey.data()), privateKey.length()) < 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyImportError,
                                            QLatin1String("Failed to read private key data from memory"));
        }
    }

    importedKey->setSize(EVP_PKEY_bits(pkey.data()));
    importedKey->setPublicKey(publicKey);
    importedKey->setPrivateKey(privateKey);

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::calculateDigest(
        const QByteArray &data,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap & /* customParameters */,
        QByteArray *digest)
{
    if (digest == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDigestError,
                                        QLatin1String("Given output argument 'digest' was nullptr."));
    }

    if (data.length() == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptyData,
                                        QLatin1String("Can't digest data if there is no data."));
    }

    if (padding != Sailfish::Crypto::CryptoManager::SignaturePaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: digest padding other than None"));
    }

    // Get the EVP digest function
    const EVP_MD *evpDigestFunc = getEvpDigestFunction(digestFunction);
    if (!evpDigestFunc) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedDigest,
                                        QLatin1String("Unsupported digest function chosen."));
    }

    // Variables for storing the digest
    uint8_t *digestBytes = Q_NULLPTR;
    size_t digestLength = 0;

    // Create digest
    int r = OpenSslEvp::digest(evpDigestFunc, data.data(), data.length(), &digestBytes, &digestLength);
    if (r != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDigestError,
                                        QLatin1String("Failed to digest."));
    }

    // Copy the digest into the given QByteArray
    *digest = QByteArray((const char*) digestBytes, (int) digestLength);

    // Free the digest allocated by openssl
    OPENSSL_free(digestBytes);

    // Return result indicating success
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap & /* customParameters */,
        QByteArray *signature)
{
    if (signature == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginSigningError,
                                        QLatin1String("Given output argument 'signature' was nullptr."));
    }

    if (data.length() == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptyData,
                                        QLatin1String("Can't sign data if there is no data."));
    }

    if (key.privateKey().length() == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptyPrivateKey,
                                        QLatin1String("Can't sign without private key."));
    }

    if (padding != Sailfish::Crypto::CryptoManager::SignaturePaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: signature padding other than None"));
    }

    // Get the EVP digest function
    const EVP_MD *evpDigestFunc = getEvpDigestFunction(digestFunction);
    if (!evpDigestFunc) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedDigest,
                                        QLatin1String("Unsupported digest function chosen."));
    }

    QScopedPointer<BIO, LibCrypto_BIO_Deleter> bio(BIO_new(BIO_s_mem()));

    // Use BIO to write private key data
    int r = BIO_write(bio.data(), key.privateKey().data(), key.privateKey().length());
    if (r == 0 || r != key.privateKey().length()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginSigningError,
                                        QLatin1String("Failed to read private key data."));
    }

    // Read the private key data into an EVP_PKEY, which SHOULD handle different formats transparently.
    // See https://www.openssl.org/docs/man1.1.0/crypto/PEM_read_bio_PrivateKey.html
    EVP_PKEY *pkeyPtr = Q_NULLPTR;
    PEM_read_bio_PrivateKey(bio.data(), &pkeyPtr, Q_NULLPTR, Q_NULLPTR);
    if (pkeyPtr == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginSigningError,
                                        QLatin1String("Failed to read private key from PEM format."));
    }

    QScopedPointer<EVP_PKEY, LibCrypto_EVP_PKEY_Deleter> pkey(pkeyPtr);

    // Variables for storing the signature
    uint8_t *signatureBytes = Q_NULLPTR;
    size_t signatureLength = 0;

    // Create signature
    r = OpenSslEvp::sign(evpDigestFunc, pkeyPtr, data.data(), data.length(), &signatureBytes, &signatureLength);
    if (r != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginSigningError,
                                        QLatin1String("Failed to sign."));
    }

    // Copy the signature into the given QByteArray
    *signature = QByteArray((const char*) signatureBytes, (int) signatureLength);

    // Free the signature allocated by openssl
    OPENSSL_free(signatureBytes);

    // Return result indicating success
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::verify(
        const QByteArray &signature,
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::SignaturePadding padding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap & /* customParameters */,
        bool *verified)
{
    if (verified == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginVerificationError,
                                        QLatin1String("Given output argument 'verified' was nullptr."));
    }

    if (signature.length() == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySignature,
                                        QLatin1String("Can't verify without signature."));
    }

    if (key.publicKey().length() == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptyPublicKey,
                                        QLatin1String("Can't verify without public key."));
    }

    if (padding != Sailfish::Crypto::CryptoManager::SignaturePaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: signature padding other than None"));
    }

    // Get the EVP digest function
    const EVP_MD *evpDigestFunc = getEvpDigestFunction(digestFunction);
    if (!evpDigestFunc) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedDigest,
                                        QLatin1String("Unsupported digest function chosen."));
    }

    QScopedPointer<BIO, LibCrypto_BIO_Deleter> bio(BIO_new(BIO_s_mem()));

    // Use BIO to write public key data
    int r = BIO_write(bio.data(), key.publicKey().data(), key.publicKey().length());
    if (r != key.publicKey().length()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginVerificationError,
                                        QLatin1String("Failed to read public key data."));
    }

    // Read the public key data into an EVP_PKEY
    EVP_PKEY *pkeyPtr = Q_NULLPTR;
    PEM_read_bio_PUBKEY(bio.data(), &pkeyPtr, Q_NULLPTR, Q_NULLPTR);
    if (pkeyPtr == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginVerificationError,
                                        QLatin1String("Failed to read public key from PEM format."));
    }

    QScopedPointer<EVP_PKEY, LibCrypto_EVP_PKEY_Deleter> pkey(pkeyPtr);

    // Verify the signature
    r = OpenSslEvp::verify(evpDigestFunc, pkeyPtr, data.data(), data.length(), (const uint8_t*) signature.data(), (size_t) signature.length());
    if (r == 1) {
        // Verification performed without error, signature matched.
        *verified = true;
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    } else if (r == 0) {
        // Verification performed without error, but signature didn't match.
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
    } else {
        // Verification had errors.
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginVerificationError,
                                        QLatin1String("Error occoured while verifying the given signature."));
    }
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QVariantMap & /* customParameters */,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
{
    if (encrypted == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                        QLatin1String("The 'encrypted' argument SHOULD NOT be nullptr."));
    }

    if (key.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return this->encryptAes(data, iv, key, blockMode, padding, authenticationData, encrypted, authenticationTag);
    } else if (key.algorithm() >= Sailfish::Crypto::CryptoManager::FirstAsymmetricAlgorithm
               && key.algorithm() <= Sailfish::Crypto::CryptoManager::LastAsymmetricAlgorithm) {
        return this->encryptAsymmetric(data, iv, key, blockMode, padding, encrypted);
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("Unsupported encryption algorithm specified."));
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::encryptAsymmetric(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        QByteArray *encrypted)
{
    if (key.publicKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptyPublicKey,
                                        QLatin1String("Cannot encrypt if there is no public key to encrypt with."));
    }

    if (iv.size()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: initialization vectors are not yet supported with asymmetric encryption"));
    }

    if (key.algorithm() < Sailfish::Crypto::CryptoManager::FirstAsymmetricAlgorithm
           || key.algorithm() > Sailfish::Crypto::CryptoManager::LastAsymmetricAlgorithm) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("OpenSslCryptoPlugin::encryptAssymmetric only supports asymmetric algorithms"));
    }

    if (blockMode != Sailfish::Crypto::CryptoManager::BlockModeUnknown) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than Unknown"));
    }

    int opensslPadding = getOpenSslRsaPadding(padding);
    if (opensslPadding == 0 || (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmRsa && padding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The given padding type is not supported for the given algorithm."));
    }

    QScopedPointer<BIO, LibCrypto_BIO_Deleter> bio(BIO_new(BIO_s_mem()));

    // Use BIO to write public key data
    int r = BIO_write(bio.data(), key.publicKey().data(), key.publicKey().length());
    if (r == 0 || r != key.publicKey().length()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                        QLatin1String("Failed to read public key data."));
    }

    // Read the public key data into an EVP_PKEY, which SHOULD handle different formats transparently.
    EVP_PKEY *pkeyPtr = Q_NULLPTR;
    PEM_read_bio_PUBKEY(bio.data(), &pkeyPtr, Q_NULLPTR, Q_NULLPTR);
    if (pkeyPtr == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                        QLatin1String("Failed to read public key from PEM format."));
    }

    QScopedPointer<EVP_PKEY, LibCrypto_EVP_PKEY_Deleter> pkey(pkeyPtr);

    uint8_t *encryptedBytes = Q_NULLPTR;
    size_t encryptedBytesLength = 0;

    r = OpenSslEvp::pkey_encrypt_plaintext(pkeyPtr,
                                       opensslPadding,
                                       reinterpret_cast<const uint8_t*>(data.data()),
                                       data.length(),
                                       &encryptedBytes,
                                       &encryptedBytesLength);

    if (r != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                        QLatin1String("Failed to encrypt."));
    }

    *encrypted = QByteArray(reinterpret_cast<char*>(encryptedBytes),
                            static_cast<int>(encryptedBytesLength));

    OPENSSL_free(encryptedBytes);

    // Return result indicating success
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::encryptAes(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        QByteArray *encrypted,
        QByteArray *authenticationTag)
{
    if (key.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot encrypt with empty secret key"));
    }

    if (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("OpenSslCryptoPlugin::encryptAes should only be used with AES"));
    }

    if (padding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    if (key.secretKey().size() * 8 != key.size()) {
        // The secret is not of the expected length (e.g. 128-bit, 256-bit)
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginKeyGenerationError,
                                        QLatin1String("Secret key size does not match"));
    }

    unsigned int tagSize = authenticationTagSize(key.algorithm(), blockMode);
    if (!authenticationData.isEmpty()) {
        if (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("Authenticated encryption not supported for algorithms other than AES"));
        }
        if (tagSize == 0) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedBlockMode,
                                            QLatin1String("Authenticated encryption not supported for block modes other than GCM and CCM"));
        }
        if (!authenticationTag) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidAuthenticationTag,
                                            QLatin1String("Authenticated encryption failed, no authentication tag container provided"));
        }
    }

    const int expectedIvSize = initializationVectorSize(key.algorithm(), blockMode, key.size());
    if (!iv.isEmpty() && expectedIvSize < 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidInitializationVector,
                                        QStringLiteral("Initialization Vector should not be provided for this algorithm/mode/key configuration"));
    } else if (iv.size() != expectedIvSize) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidInitializationVector,
                                        QStringLiteral("Initialization Vector length should be %1 but was %2")
                                                .arg(expectedIvSize)
                                                .arg(iv.size()));
    }

    // encrypt plaintext
    if (!authenticationData.isEmpty()) {
        QPair<QByteArray, QByteArray> resultData = aes_auth_encrypt_plaintext(blockMode, data, key.secretKey(), iv, authenticationData, tagSize);
        const QByteArray &ciphertext = resultData.first;
        const QByteArray &authenticationTagData = resultData.second;
        if (authenticationTagData.isEmpty()) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginAuthenticationTagError,
                                            QLatin1String("OpenSSL crypto plugin failed to get the authentication tag"));
        }
        if (!ciphertext.isEmpty()) {
            *encrypted = ciphertext;
            *authenticationTag = authenticationTagData;
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
        }
    } else {
        const QByteArray &ciphertext = aes_encrypt_plaintext(blockMode, data, key.secretKey(), iv);
        if (!ciphertext.isEmpty()) {
            *encrypted = ciphertext;
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
        }
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                     QLatin1String("OpenSSL crypto plugin failed to encrypt the data"));
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        const QVariantMap & /* customParameters */,
        QByteArray *decrypted,
        bool *verified)
{
    if (key.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return this->decryptAes(data, iv, key, blockMode, padding, authenticationData, authenticationTag, decrypted, verified);
    } else if (key.algorithm() >= Sailfish::Crypto::CryptoManager::FirstAsymmetricAlgorithm
               && key.algorithm() <= Sailfish::Crypto::CryptoManager::LastAsymmetricAlgorithm) {
        return this->decryptAsymmetric(data, iv, key, blockMode, padding, decrypted);
    }

    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("Unsupported decryption algorithm specified."));
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::decryptAsymmetric(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        QByteArray *decrypted)
{
    if (key.privateKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptyPrivateKey,
                                        QLatin1String("Cannot decrypt if there is no private key to decrypt with."));
    }

    if (iv.size()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: initialization vectors are not yet supported with asymmetric encryption"));
    }

    if (key.algorithm() < Sailfish::Crypto::CryptoManager::FirstAsymmetricAlgorithm
           || key.algorithm() > Sailfish::Crypto::CryptoManager::LastAsymmetricAlgorithm) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("OpenSslCryptoPlugin::decryptAssymmetric only supports asymmetric algorithms"));
    }

    if (blockMode != Sailfish::Crypto::CryptoManager::BlockModeUnknown) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than Unknown"));
    }

    int opensslPadding = getOpenSslRsaPadding(padding);
    if (opensslPadding == 0 || (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmRsa && padding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("The given padding type is not supported for the given algorithm."));
    }

    QScopedPointer<BIO, LibCrypto_BIO_Deleter> bio(BIO_new(BIO_s_mem()));

    // Use BIO to write private key data
    int r = BIO_write(bio.data(), key.privateKey().data(), key.privateKey().length());
    if (r == 0 || r != key.privateKey().length()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDecryptionError,
                                        QLatin1String("Failed to read private key data."));
    }

    // Read the private key data into an EVP_PKEY, which SHOULD handle different formats transparently.
    EVP_PKEY *pkeyPtr = Q_NULLPTR;
    PEM_read_bio_PrivateKey(bio.data(), &pkeyPtr, Q_NULLPTR, Q_NULLPTR);
    if (pkeyPtr == Q_NULLPTR) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDecryptionError,
                                        QLatin1String("Failed to read private key from PEM format."));
    }

    QScopedPointer<EVP_PKEY, LibCrypto_EVP_PKEY_Deleter> pkey(pkeyPtr);

    uint8_t *decryptedBytes = Q_NULLPTR;
    size_t decryptedBytesLength = 0;

    r = OpenSslEvp::pkey_decrypt_ciphertext(pkeyPtr,
                                        opensslPadding,
                                        reinterpret_cast<const uint8_t*>(data.data()),
                                        data.length(),
                                        &decryptedBytes,
                                        &decryptedBytesLength);

    if (r != 1) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginEncryptionError,
                                        QLatin1String("Failed to encrypt."));
    }

    *decrypted = QByteArray(reinterpret_cast<char*>(decryptedBytes),
                            static_cast<int>(decryptedBytesLength));

    OPENSSL_free(decryptedBytes);

    // Return result indicating success
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::decryptAes(
        const QByteArray &data,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
        const QByteArray &authenticationData,
        const QByteArray &authenticationTag,
        QByteArray *decrypted,
        bool *verified)
{
    if (key.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot decrypt with empty secret key"));
    }

    if (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("OpenSslCryptoPlugin::decryptAes should only be used with AES"));
    }

    if (padding != Sailfish::Crypto::CryptoManager::EncryptionPaddingNone) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: encryption padding other than None"));
    }

    if (!authenticationData.isEmpty()) {
        if (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                            QLatin1String("Authenticated decryption not supported for algorithms other than AES"));
        }
        if (blockMode != Sailfish::Crypto::CryptoManager::BlockModeGcm
                && blockMode != Sailfish::Crypto::CryptoManager::BlockModeCcm) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedBlockMode,
                                            QLatin1String("Authenticated decryption not supported for block modes other than GCM and CCM"));
        }
        if (authenticationTag.size() != authenticationTagSize(key.algorithm(), blockMode)) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidAuthenticationTag,
                                            QStringLiteral("Authenticated decryption failed, authentication tag length should be %1 but was %2")
                                                    .arg(authenticationTagSize(key.algorithm(), blockMode))
                                                    .arg(authenticationTag.size()));
        }
    }

    const int expectedIvSize = initializationVectorSize(key.algorithm(), blockMode, key.size());
    if (!iv.isEmpty() && expectedIvSize < 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidInitializationVector,
                                        QStringLiteral("Initialization Vector should not be provided for this algorithm/mode/key configuration"));
    } else if (iv.size() != expectedIvSize) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidInitializationVector,
                                        QStringLiteral("Initialization Vector length should be %1 but was %2")
                                                .arg(expectedIvSize)
                                                .arg(iv.size()));
    }

    // decrypt ciphertext
    QByteArray plaintext;
    bool verifiedResult = false;
    if (!authenticationData.isEmpty()) {
        QPair<QByteArray, bool> authDecryptResult = aes_auth_decrypt_ciphertext(blockMode, data, key.secretKey(), iv, authenticationData, authenticationTag);
        plaintext = authDecryptResult.first;
        verifiedResult = authDecryptResult.second;
    } else {
        plaintext = aes_decrypt_ciphertext(blockMode, data, key.secretKey(), iv);
    }
    if (!plaintext.size() || (plaintext.size() == 1 && plaintext.at(0) == 0)) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginDecryptionError,
                                         QLatin1String("Failed to decrypt the secret"));
    }

    // return result
    *decrypted = plaintext;
    *verified = verifiedResult;
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Daemon::Plugins::OpenSslCryptoPlugin::initializeCipherSession(
        quint64 clientId,
        const QByteArray &iv,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::CryptoManager::Operation operation,
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
        Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
        const QVariantMap & /* customParameters */,
        quint32 *cipherSessionToken)
{
    if (key.secretKey().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::EmptySecretKey,
                                        QLatin1String("Cannot create a cipher session with empty secret key"));
    }

    if (key.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                        QLatin1String("TODO: algorithms other than Aes256"));
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

    if (operation == Sailfish::Crypto::CryptoManager::OperationEncrypt) {
        const int expectedIvSize = initializationVectorSize(key.algorithm(), blockMode, key.size());
        if (!iv.isEmpty() && expectedIvSize < 0) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidInitializationVector,
                                            QStringLiteral("Initialization Vector should not be provided for this algorithm/mode/key configuration"));
        } else if (iv.size() != expectedIvSize) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidInitializationVector,
                                            QStringLiteral("Initialization Vector length should be %1 but was %2")
                                                    .arg(expectedIvSize)
                                                    .arg(iv.size()));
        }
    }

    EVP_MD_CTX *evp_md_ctx = NULL;
    EVP_CIPHER_CTX *evp_cipher_ctx = NULL;
    if (operation == Sailfish::Crypto::CryptoManager::OperationEncrypt) {
        evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (evp_cipher_ctx == NULL) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Unable to initialize cipher context for encryption"));
        }
        if (key.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmAes) {
            const EVP_CIPHER *evp_cipher = getEvpCipher(blockMode, key.secretKey().size());
            // Initialize context
            if (evp_cipher == NULL) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Cannot create cipher for AES encryption, check key size and block mode"));
            }
            if (EVP_EncryptInit_ex(evp_cipher_ctx, evp_cipher, NULL, NULL, NULL) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialize encryption cipher context in AES 256 mode"));
            }
            // Set IV length
            if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm
                    && EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length(), NULL) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to set encryption initialization vector length"));
            }
            // Initialize key and IV
            if (EVP_EncryptInit_ex(evp_cipher_ctx, NULL, NULL,
                                   reinterpret_cast<const unsigned char*>(key.secretKey().constData()),
                                   reinterpret_cast<const unsigned char*>(iv.constData())) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialize encryption key and IV"));
            }
        }
    } else if (operation == Sailfish::Crypto::CryptoManager::OperationDecrypt) {
        evp_cipher_ctx = EVP_CIPHER_CTX_new();
        if (evp_cipher_ctx == NULL) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Unable to initialize cipher context for decryption"));
        }
        if (key.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmAes) {
            const EVP_CIPHER *evp_cipher = getEvpCipher(blockMode, key.secretKey().size());
            // Initialize context
            if (evp_cipher == NULL) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Cannot create cipher for AES deccryption, check key size and block mode"));
            }
            if (EVP_DecryptInit_ex(evp_cipher_ctx, evp_cipher, NULL, NULL, NULL) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialize decryption cipher context in AES 256 mode"));
            }
            // Set IV length
            if (blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm
                    && EVP_CIPHER_CTX_ctrl(evp_cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, iv.length(), NULL) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to set decryption initialization vector length"));

            }
            // Initialize key and IV
            if (EVP_DecryptInit_ex(evp_cipher_ctx, NULL, NULL,
                                   reinterpret_cast<const unsigned char *>(key.secretKey().constData()),
                                   reinterpret_cast<const unsigned char *>(iv.constData())) != 1) {
                EVP_CIPHER_CTX_free(evp_cipher_ctx);
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to initialize decryption cipher context in AES 256 mode"));
            }
        }
    } else {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                        QLatin1String("TODO: implement sign/verify data!"));
    }

    CipherSessionData *csd = new CipherSessionData;
    csd->iv = iv;
    csd->key = key;
    csd->operation = operation;
    csd->blockMode = blockMode;
    csd->encryptionPadding = encryptionPadding;
    csd->signaturePadding = signaturePadding;
    csd->digestFunction = digestFunction;
    csd->cipherSessionToken = sessionToken;
    csd->evp_cipher_ctx = evp_cipher_ctx;
    csd->evp_md_ctx = evp_md_ctx;
    QTimer *timeout = new QTimer;
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
Daemon::Plugins::OpenSslCryptoPlugin::updateCipherSessionAuthentication(
        quint64 clientId,
        const QByteArray &authenticationData,
        const QVariantMap & /* customParameters */,
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
                                        QLatin1String("Cipher context has not been initialized"));
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
Daemon::Plugins::OpenSslCryptoPlugin::updateCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap & /* customParameters */,
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
                                        QLatin1String("Cipher context has not been initialized"));
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
Daemon::Plugins::OpenSslCryptoPlugin::finalizeCipherSession(
        quint64 clientId,
        const QByteArray &data,
        const QVariantMap & /* customParameters */,
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
                                        QLatin1String("Cipher context has not been initialized"));
    }

    QScopedPointer<CipherSessionData,CipherSessionDataDeleter> csdd(m_cipherSessions[clientId].take(cipherSessionToken));
    m_cipherSessionTimeouts.remove(csd->timeout);
    int blockSizeForCipher = 16; // TODO: lookup for different algorithms, but AES is 128 bit blocks = 16 bytes
    QScopedArrayPointer<unsigned char> generatedDataBuf(new unsigned char[blockSizeForCipher*2]); // final 1 or 2 blocks.
    int generatedDataSize = 0;
    if (csd->operation == Sailfish::Crypto::CryptoManager::OperationEncrypt) {
        if (EVP_EncryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize) != 1) {
            return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                            QLatin1String("Failed to finalize encryption cipher"));
        }
        if (csd->blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
            // in GCM mode, the finalization above does not write extra ciphertext.
            // instead, we should retrieve the authenticationTag.
            if (generatedDataSize > 0) {
                // This should never happen.
                qWarning() << "INTERNAL ERROR: GCM finalization produced ciphertext data!";
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
            // in GCM mode, the finalization requires setting the provided authenticationTag data.
            if (data.size() != SAILFISH_CRYPTO_GCM_TAG_SIZE) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("GCM authenticationTag data is not the expected size"));
            }
            QByteArray authenticationTagData(data);
            if (!EVP_CIPHER_CTX_ctrl(csd->evp_cipher_ctx, EVP_CTRL_GCM_SET_TAG, data.size(),
                                     reinterpret_cast<void *>(authenticationTagData.data()))) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Unable to set the GCM authenticationTag to finalize the cipher"));
            }
            int evpRet = EVP_DecryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize);
            *verified = evpRet > 0;
        } else {
            if (EVP_DecryptFinal_ex(csd->evp_cipher_ctx, generatedDataBuf.data(), &generatedDataSize) != 1) {
                return Sailfish::Crypto::Result(Sailfish::Crypto::Result::CryptoPluginCipherSessionError,
                                                QLatin1String("Failed to finalize the decryption cipher"));
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
Daemon::Plugins::OpenSslCryptoPlugin::aes_encrypt_plaintext(
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const QByteArray &plaintext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray encryptedData;
    unsigned char *encrypted = NULL;
    int size = OpenSslEvp::aes_encrypt_plaintext(getEvpCipher(blockMode, key.size()),
                                             (const unsigned char *)init_vector.constData(),
                                             (const unsigned char *)key.constData(),
                                             key.size(),
                                             (const unsigned char *)plaintext.constData(),
                                             plaintext.size(),
                                             &encrypted);
    if (size <= 0) {
        return QByteArray();
    }

    encryptedData = QByteArray((const char *)encrypted, size);
    free(encrypted);
    return encryptedData;
}

QByteArray
Daemon::Plugins::OpenSslCryptoPlugin::aes_decrypt_ciphertext(
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const QByteArray &ciphertext,
        const QByteArray &key,
        const QByteArray &init_vector)
{
    QByteArray decryptedData;
    unsigned char *decrypted = NULL;
    int size = OpenSslEvp::aes_decrypt_ciphertext(getEvpCipher(blockMode, key.size()),
                                              (const unsigned char *)init_vector.constData(),
                                              (const unsigned char *)key.constData(),
                                              key.size(),
                                              (const unsigned char *)ciphertext.constData(),
                                              ciphertext.size(),
                                              &decrypted);
    if (size <= 0) {
        return QByteArray();
    }

    decryptedData = QByteArray((const char *)decrypted, size);
    free(decrypted);
    return decryptedData;
}

QPair<QByteArray, QByteArray>
Daemon::Plugins::OpenSslCryptoPlugin::aes_auth_encrypt_plaintext(
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const QByteArray &plaintext,
        const QByteArray &key,
        const QByteArray &init_vector,
        const QByteArray &auth,
        unsigned int authenticationTagLength)
{
    QByteArray encryptedData;
    QByteArray authenticationTagData;
    unsigned char *encrypted = NULL;
    unsigned char *authenticationTag = NULL;

    int encryptedSize = OpenSslEvp::aes_auth_encrypt_plaintext(getEvpCipher(blockMode, key.size()),
                                                           (const unsigned char *)init_vector.constData(),
                                                           init_vector.size(),
                                                           (const unsigned char *)key.constData(),
                                                           key.size(),
                                                           (const unsigned char *)auth.constData(),
                                                           auth.size(),
                                                           (const unsigned char *)plaintext.constData(),
                                                           plaintext.size(),
                                                           &encrypted,
                                                           &authenticationTag,
                                                           authenticationTagLength);
    if (encryptedSize <= 0) {
        return qMakePair(QByteArray(), QByteArray());
    }

    encryptedData = QByteArray((const char *)encrypted, encryptedSize);
    free(encrypted);
    authenticationTagData = QByteArray((const char *)authenticationTag, authenticationTagLength);
    free(authenticationTag);

    return qMakePair(encryptedData, authenticationTagData);
}

QPair<QByteArray, bool>
Daemon::Plugins::OpenSslCryptoPlugin::aes_auth_decrypt_ciphertext(
        Sailfish::Crypto::CryptoManager::BlockMode blockMode,
        const QByteArray &ciphertext,
        const QByteArray &key,
        const QByteArray &init_vector,
        const QByteArray &auth,
        const QByteArray &authenticationTag)
{
    QByteArray decryptedData;
    int verifyResult = -1;
    unsigned char *decrypted = NULL;
    unsigned char *authenticationTagData = (unsigned char *)authenticationTag.data();

    int size = OpenSslEvp::aes_auth_decrypt_ciphertext(getEvpCipher(blockMode, key.size()),
                                                   (const unsigned char *)init_vector.constData(),
                                                   init_vector.size(),
                                                   (const unsigned char *)key.constData(),
                                                   key.size(),
                                                   (const unsigned char *)auth.constData(),
                                                   auth.size(),
                                                   authenticationTagData,
                                                   authenticationTag.size(),
                                                   (const unsigned char *)ciphertext.constData(),
                                                   ciphertext.size(),
                                                   &decrypted,
                                                   &verifyResult);
    if (size <= 0) {
        return qMakePair(QByteArray(), false);
    }

    decryptedData = QByteArray((const char *)decrypted, size);
    free(decrypted);
    return qMakePair(decryptedData, (verifyResult > 0));
}

