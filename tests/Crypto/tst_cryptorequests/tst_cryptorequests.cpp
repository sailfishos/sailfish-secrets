/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

// This test requires linkage to both Crypto and Secrets APIs.

#include <QtTest>
#include <QSignalSpy>
#include <QObject>
#include <QElapsedTimer>
#include <QFile>
#include <QDateTime>
#include <QtCore/QCryptographicHash>

#include "Crypto/calculatedigestrequest.h"
#include "Crypto/cipherrequest.h"
#include "Crypto/decryptrequest.h"
#include "Crypto/deletestoredkeyrequest.h"
#include "Crypto/encryptrequest.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/generatestoredkeyrequest.h"
#include "Crypto/importkeyrequest.h"
#include "Crypto/importstoredkeyrequest.h"
#include "Crypto/lockcoderequest.h"
#include "Crypto/plugininforequest.h"
#include "Crypto/seedrandomdatageneratorrequest.h"
#include "Crypto/generateinitializationvectorrequest.h"
#include "Crypto/signrequest.h"
#include "Crypto/storedkeyidentifiersrequest.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/verifyrequest.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/key.h"
#include "Crypto/result.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/interactionparameters.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/createcollectionrequest.h"
#include "Secrets/deletecollectionrequest.h"
#include "Secrets/findsecretsrequest.h"
#include "Secrets/storesecretrequest.h"
#include "Secrets/deletesecretrequest.h"
#include "Secrets/storedsecretrequest.h"

// Needed for the calculateDigest tests
Q_DECLARE_METATYPE(QCryptographicHash::Algorithm);

using namespace Sailfish::Crypto;

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                         \
    do {                                                                    \
        int maxWait = 1000000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(100);                                              \
            maxWait -= 100;                                                 \
        }                                                                   \
    } while (0)
#define SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                   \
    do {                                                                    \
        int maxWait = 1000000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(1);                                                \
            maxWait -= 1;                                                   \
        }                                                                   \
    } while (0)
#define LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                    \
    do {                                                                    \
        int maxWait = 3000000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(100);                                              \
            maxWait -= 100;                                                 \
        }                                                                   \
    } while (0)

#define DEFAULT_TEST_CRYPTO_PLUGIN_NAME CryptoManager::DefaultCryptoPluginName + QLatin1String(".test")
#define DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")
#define DEFAULT_TEST_STORAGE_PLUGIN Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test")
#define DEFAULT_TEST_ENCRYPTION_PLUGIN Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName + QLatin1String(".test")
#define IN_APP_TEST_AUTHENTICATION_PLUGIN Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName + QLatin1String(".test")

class tst_cryptorequests : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void getPluginInfo();
    void randomData();
    void generateInitializationVectorRequest_data();
    void generateInitializationVectorRequest();
    void generateKeyEncryptDecrypt_data();
    void generateKeyEncryptDecrypt();
    void signVerify();
    void signVerify_data();
    void calculateDigest();
    void calculateDigest_data();
    void storedKeyRequests_data();
    void storedKeyRequests();
    void storedDerivedKeyRequests_data();
    void storedDerivedKeyRequests();
    void storedGeneratedKeyRequests();
    void cipherEncryptDecrypt_data();
    void cipherEncryptDecrypt();
    void cipherBenchmark_data();
    void cipherBenchmark();
    void cipherTimeout();
    void lockCode();
    void pluginThreading();
    void requestInterleaving();
    void importKey_data();
    void importKey();
    void importKeyAndStore_data();
    void importKeyAndStore();

private:
    QByteArray generateInitializationVector(Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                            Sailfish::Crypto::CryptoManager::BlockMode blockMode)
    {
        if (algorithm != Sailfish::Crypto::CryptoManager::AlgorithmAes
                || blockMode == Sailfish::Crypto::CryptoManager::BlockModeEcb) {
            return QByteArray();
        }

        QByteArray data = QString::number(QDateTime::currentDateTime().currentMSecsSinceEpoch()).toLatin1();
        data.resize(16);

        if (algorithm == Sailfish::Crypto::CryptoManager::AlgorithmAes
                && blockMode == Sailfish::Crypto::CryptoManager::BlockModeGcm) {
            data.resize(12);
        }

        return data;
    }

    void addCryptoTestData()
    {
        QTest::addColumn<CryptoManager::Algorithm>("algorithm");
        QTest::addColumn<CryptoManager::BlockMode>("blockMode");
        QTest::addColumn<CryptoManager::EncryptionPadding>("padding");
        QTest::addColumn<int>("keySize");

        QTest::newRow("AES ECB 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeEcb << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES ECB 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeEcb << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES ECB 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeEcb << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("AES CBC 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCbc << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES CBC 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCbc << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES CBC 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCbc << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("AES CFB-1 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb1 << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES CFB-1 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb1 << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES CFB-1 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb1 << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("AES CFB-8 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb8 << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES CFB-8 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb8 << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES CFB-8 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb8 << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("AES CFB-128 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb128 << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES CFB-128 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb128 << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES CFB-128 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCfb128 << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("AES OFB 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeOfb << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES OFB 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeOfb << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES OFB 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeOfb << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("AES CTR 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES CTR 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES CTR 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("CTR 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("CTR 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("CTR 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("GCM 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("GCM 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("GCM 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("RSA 512-bit (no padding)") << CryptoManager::AlgorithmRsa << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingNone << 512;
        QTest::newRow("RSA 512-bit (PKCS1 padding") << CryptoManager::AlgorithmRsa << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaPkcs1 << 512;
        QTest::newRow("RSA 512-bit (OAEP padding)") << CryptoManager::AlgorithmRsa << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaOaep << 512;

        QTest::newRow("RSA 1024-bit (no padding)") << CryptoManager::AlgorithmRsa << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingNone << 1024;
        QTest::newRow("RSA 1024-bit (PKCS1 padding") << CryptoManager::AlgorithmRsa << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaPkcs1 << 1024;
        QTest::newRow("RSA 1024-bit (OAEP padding)") << CryptoManager::AlgorithmRsa << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaOaep << 1024;
    }

    CryptoManager cm;
    Sailfish::Secrets::SecretManager sm;
    QStringList populatedCollections;
};

Q_DECLARE_METATYPE(Sailfish::Crypto::Result::ResultCode)
Q_DECLARE_METATYPE(Sailfish::Crypto::Result::ErrorCode)

static inline QByteArray createRandomTestData(int size) {
    QFile file("/dev/urandom");
    file.open(QIODevice::ReadOnly);
    QByteArray result = file.read(size);
    file.close();
    return result;
}

static inline KeyPairGenerationParameters getKeyPairGenerationParameters(CryptoManager::Algorithm algorithm, int keySize)
{
    switch (algorithm)
    {
    case CryptoManager::AlgorithmRsa: {
        RsaKeyPairGenerationParameters rsa;
        rsa.setModulusLength(keySize);
        return rsa;
    }
    case CryptoManager::AlgorithmEc: {
        return EcKeyPairGenerationParameters();
    }
    default: {
        KeyPairGenerationParameters unknown;
        unknown.setKeyPairType(KeyPairGenerationParameters::KeyPairUnknown);
        return unknown;
    }
    }
}

void tst_cryptorequests::init()
{
}

void tst_cryptorequests::cleanup()
{
    while (!populatedCollections.isEmpty()) {
        // clean up by deleting the collection in which the secret is stored.
        Sailfish::Secrets::DeleteCollectionRequest dcr;
        dcr.setManager(&sm);
        dcr.setCollectionName(populatedCollections.takeFirst());
        dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
        dcr.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
        QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
        QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
    }
}

void tst_cryptorequests::getPluginInfo()
{
    PluginInfoRequest r;
    r.setManager(&cm);
    QSignalSpy ss(&r, &PluginInfoRequest::statusChanged);
    QSignalSpy cs(&r, &PluginInfoRequest::cryptoPluginsChanged);
    QCOMPARE(r.status(), Request::Inactive);
    r.startRequest();
    QCOMPARE(ss.count(), 1);
    QCOMPARE(r.status(), Request::Active);
    QCOMPARE(r.result().code(), Result::Pending);
    r.waitForFinished();
    QCOMPARE(ss.count(), 2);
    QCOMPARE(r.status(), Request::Finished);
    QCOMPARE(r.result().code(), Result::Succeeded);
    QCOMPARE(cs.count(), 1);
    QVERIFY(r.cryptoPlugins().size());
    QStringList cryptoPluginNames;
    for (auto p : r.cryptoPlugins()) {
        cryptoPluginNames.append(p.name());
    }
    QVERIFY(cryptoPluginNames.contains(DEFAULT_TEST_CRYPTO_PLUGIN_NAME));
}

void tst_cryptorequests::randomData()
{
    // test generating random data
    GenerateRandomDataRequest grdr;
    grdr.setManager(&cm);
    QSignalSpy grdrss(&grdr, &GenerateRandomDataRequest::statusChanged);
    QSignalSpy grdrds(&grdr, &GenerateRandomDataRequest::generatedDataChanged);
    grdr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(grdr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    grdr.setCsprngEngineName(GenerateRandomDataRequest::DefaultCsprngEngineName);
    QCOMPARE(grdr.csprngEngineName(), GenerateRandomDataRequest::DefaultCsprngEngineName);
    grdr.setNumberBytes(2048);
    QCOMPARE(grdr.status(), Request::Inactive);
    grdr.startRequest();
    QCOMPARE(grdrss.count(), 1);
    QCOMPARE(grdr.status(), Request::Active);
    QCOMPARE(grdr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(grdr);
    QCOMPARE(grdrss.count(), 2);
    QCOMPARE(grdr.status(), Request::Finished);
    QCOMPARE(grdr.result().code(), Result::Succeeded);
    QCOMPARE(grdrds.count(), 1);
    QByteArray randomData = grdr.generatedData();
    QCOMPARE(randomData.size(), 2048);
    bool allNull = true;
    for (auto c : randomData) {
        if (c != '\0') {
            allNull = false;
            break;
        }
    }
    QVERIFY(!allNull);

    // test seeding the random number generator
    SeedRandomDataGeneratorRequest srdgr;
    srdgr.setManager(&cm);
    QSignalSpy srdgrss(&srdgr, &SeedRandomDataGeneratorRequest::statusChanged);
    srdgr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(srdgr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    srdgr.setCsprngEngineName(GenerateRandomDataRequest::DefaultCsprngEngineName);
    QCOMPARE(srdgr.csprngEngineName(), GenerateRandomDataRequest::DefaultCsprngEngineName);
    srdgr.setSeedData(QByteArray("seed"));
    QCOMPARE(srdgr.seedData(), QByteArray("seed"));
    srdgr.setEntropyEstimate(0.5);
    QCOMPARE(srdgr.entropyEstimate(), 0.5);
    QCOMPARE(srdgr.status(), Request::Inactive);
    srdgr.startRequest();
    QCOMPARE(srdgrss.count(), 1);
    QCOMPARE(srdgr.status(), Request::Active);
    QCOMPARE(srdgr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(srdgr);
    QCOMPARE(srdgrss.count(), 2);
    QCOMPARE(srdgr.status(), Request::Finished);
    QCOMPARE(srdgr.result().code(), Result::Succeeded);

    // ensure that we get different random data to the original set
    grdr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(grdr);
    QByteArray seededData = grdr.generatedData();
    QCOMPARE(seededData.size(), 2048);
    QVERIFY(randomData != seededData);

    // try a different engine (/dev/urandom)
    // and use the random data to generate a random number
    // in some range
    grdr.setCsprngEngineName(QStringLiteral("/dev/urandom"));
    grdr.setNumberBytes(8);
    grdr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(grdr);
    QByteArray randomBytes = grdr.generatedData();
    quint64 randomU64 = 0;
    memcpy(&randomU64, randomBytes.constData(), 8);
    double randomDouble = (randomU64 >> 11) * (1.0/9007199254740992.0); // 53 bits / 2**53
    QVERIFY(randomDouble >= 0.0);
    QVERIFY(randomDouble <= 1.0);
    int randomInRange = qRound((7777 - 30) * randomDouble) + 30;
    QVERIFY(randomInRange >= 30);
    QVERIFY(randomInRange <= 7777);
}

void tst_cryptorequests::generateInitializationVectorRequest_data()
{
    QTest::addColumn<CryptoManager::Algorithm>("algorithm");
    QTest::addColumn<CryptoManager::BlockMode>("blockMode");
    QTest::addColumn<int>("expectedIvSize");

    QTest::newRow("Unsupported") << CryptoManager::AlgorithmCustom << CryptoManager::BlockModeCustom << -1;
    QTest::newRow("AES ECB") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeEcb << 0;
    QTest::newRow("AES CBC") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCbc << 16;
    QTest::newRow("AES GCM") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << 12;
}

void tst_cryptorequests::generateInitializationVectorRequest()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, expectedIvSize);

    GenerateInitializationVectorRequest ivr;
    ivr.setManager(&cm);
    ivr.setAlgorithm(algorithm);
    ivr.setBlockMode(blockMode);
    ivr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(ivr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    QSignalSpy ivrss(&ivr, &GenerateInitializationVectorRequest::statusChanged);
    QSignalSpy ivrivs(&ivr, &GenerateInitializationVectorRequest::generatedInitializationVectorChanged);

    QCOMPARE(ivr.status(), Request::Inactive);
    ivr.startRequest();
    QCOMPARE(ivrss.count(), 1);
    QCOMPARE(ivr.status(), Request::Active);
    QCOMPARE(ivr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ivr);
    QCOMPARE(ivrss.count(), 2);
    QCOMPARE(ivr.status(), Request::Finished);
    QCOMPARE(ivr.result().code(), expectedIvSize >= 0 ? Result::Succeeded : Result::Failed);
    QCOMPARE(ivrivs.count(), 1);

    QByteArray iv = ivr.generatedInitializationVector();
    QCOMPARE(iv.size(), qMax(0, expectedIvSize));
}

void tst_cryptorequests::generateKeyEncryptDecrypt_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::generateKeyEncryptDecrypt()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(CryptoManager::EncryptionPadding, padding);
    QFETCH(int, keySize);

    bool isSymmetric = algorithm < CryptoManager::FirstAsymmetricAlgorithm || algorithm > CryptoManager::LastAsymmetricAlgorithm;

    // Create key template
    Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(algorithm);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    QSignalSpy gkrss(&gkr, &GenerateKeyRequest::statusChanged);
    QSignalSpy gkrks(&gkr, &GenerateKeyRequest::generatedKeyChanged);
    gkr.setKeyTemplate(keyTemplate);
    QCOMPARE(gkr.keyTemplate(), keyTemplate);

    if (!isSymmetric) {
        auto keyPairParams = getKeyPairGenerationParameters(algorithm, keySize);
        gkr.setKeyPairGenerationParameters(keyPairParams);
    }

    gkr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(gkr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(gkr.status(), Request::Inactive);
    gkr.startRequest();
    QCOMPARE(gkrss.count(), 1);
    QCOMPARE(gkr.status(), Request::Active);
    QCOMPARE(gkr.result().code(), Result::Pending);
    QCOMPARE(gkrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gkr);
    QCOMPARE(gkrss.count(), 2);
    QCOMPARE(gkr.status(), Request::Finished);
    QCOMPARE(gkr.result().code(), Result::Succeeded);
    QCOMPARE(gkrks.count(), 1);
    Key fullKey = gkr.generatedKey();
    if (isSymmetric) {
        QVERIFY(!fullKey.secretKey().isEmpty());
    } else {
        QVERIFY(!fullKey.privateKey().isEmpty());
        QVERIFY(!fullKey.publicKey().isEmpty());
    }
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());
    QCOMPARE(fullKey.size(), keySize);

    // test encrypting some plaintext with the generated key
    QByteArray plaintext = createRandomTestData(42);
    QByteArray initVector = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QByteArray authData("fedcba9876543210");
    QByteArray authenticationTag;

    if (algorithm == CryptoManager::AlgorithmRsa && padding == CryptoManager::EncryptionPaddingNone) {
        // Otherwise OpenSSL will complain about too small / too large data size.
        // See https://stackoverflow.com/questions/17746263/rsa-encryption-using-public-key-data-size-based-on-key
        plaintext = createRandomTestData(keySize / 8 - 1);
        plaintext.prepend('\0');
    }
    if (algorithm == CryptoManager::AlgorithmRsa && padding == CryptoManager::EncryptionPaddingRsaOaep) {
        // Otherwise OpenSSL will complain about too small / too large data size.
        plaintext = createRandomTestData(keySize / 32);
    }

    EncryptRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setInitialisationVector(initVector);
    QCOMPARE(er.initialisationVector(), initVector);
    er.setKey(fullKey);
    QCOMPARE(er.key(), fullKey);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setPadding(padding);
    QCOMPARE(er.padding(), padding);
    if (blockMode == CryptoManager::BlockModeGcm) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.status(), Request::Inactive);

    er.startRequest();
    QCOMPARE(er.result().errorMessage(), QString());
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(erss.count(), 1);
    QCOMPARE(ercs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().errorMessage(), QString());
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ercs.count(), 1);
    QByteArray ciphertext = er.ciphertext();
    QVERIFY(!ciphertext.isEmpty());
    QVERIFY(ciphertext != plaintext);
    authenticationTag = er.authenticationTag();
    QCOMPARE(authenticationTag.isEmpty(), blockMode != CryptoManager::BlockModeGcm);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    dr.setManager(&cm);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setInitialisationVector(initVector);
    QCOMPARE(dr.initialisationVector(), initVector);
    dr.setKey(fullKey);
    QCOMPARE(dr.key(), fullKey);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);
    dr.setPadding(padding);
    QCOMPARE(dr.padding(), padding);
    if (blockMode == CryptoManager::BlockModeGcm) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }
    dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.status(), Request::Inactive);

    dr.startRequest();
    QCOMPARE(drss.count(), 1);
    QCOMPARE(dr.status(), Request::Active);
    QCOMPARE(dr.result().code(), Result::Pending);
    QCOMPARE(drps.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(er.result().errorMessage(), QString());
    QCOMPARE(dr.result().code(), Result::Succeeded);
    QCOMPARE(drps.count(), 1);
    QByteArray decrypted = dr.plaintext();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(plaintext, decrypted);
    QCOMPARE(dr.verified(), !dr.authenticationData().isEmpty());
}

void tst_cryptorequests::signVerify_data()
{
    QTest::addColumn<CryptoManager::Algorithm>("algorithm");
    QTest::addColumn<CryptoManager::DigestFunction>("digestFunction");

    QTest::newRow("RSA + SHA256") << CryptoManager::AlgorithmRsa << CryptoManager::DigestSha256;
    QTest::newRow("RSA + SHA512") << CryptoManager::AlgorithmRsa << CryptoManager::DigestSha512;
    QTest::newRow("RSA + MD5") << CryptoManager::AlgorithmRsa << CryptoManager::DigestMd5;
    QTest::newRow("EC + SHA256") << CryptoManager::AlgorithmEc << CryptoManager::DigestSha256;
    QTest::newRow("EC + SHA512") << CryptoManager::AlgorithmEc << CryptoManager::DigestSha512;
}

void tst_cryptorequests::signVerify()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::DigestFunction, digestFunction);

    KeyPairGenerationParameters keyPairGenParams = getKeyPairGenerationParameters(algorithm, 2048);

    // Generate key for signing
    // ----------------------------

    // Create key template
    Key keyTemplate;
    keyTemplate.setAlgorithm(algorithm);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationSign);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // Key pair generation params, make sure it's valid
    QVERIFY2(keyPairGenParams.keyPairType() != KeyPairGenerationParameters::KeyPairUnknown, "Key pair type SHOULD NOT be unknown.");
    QVERIFY2(keyPairGenParams.isValid(), "Key pair generation params are invalid.");

    // Create generate key request, execute, make sure it's okay
    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    gkr.setKeyPairGenerationParameters(keyPairGenParams);
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    gkr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gkr);
    QCOMPARE(gkr.status(), Request::Finished);
    QCOMPARE(gkr.result().code(), Result::Succeeded);

    // Grab generated key, make sure it's sane
    Key fullKey = gkr.generatedKey();
    QVERIFY(!fullKey.privateKey().isEmpty());
    QVERIFY(!fullKey.publicKey().isEmpty());

    // Sign a test plaintext
    // ----------------------------

    QByteArray plaintext = "Test plaintext data";

    SignRequest sr;
    sr.setManager(&cm);
    QSignalSpy srss(&sr, &SignRequest::statusChanged);
    QSignalSpy srvs(&sr, &SignRequest::signatureChanged);

    sr.setKey(fullKey);
    QCOMPARE(sr.key(), fullKey);
    sr.setPadding(CryptoManager::SignaturePaddingNone);
    QCOMPARE(sr.padding(), CryptoManager::SignaturePaddingNone);
    sr.setDigestFunction(digestFunction);
    QCOMPARE(sr.digestFunction(), digestFunction);
    sr.setData(plaintext);
    QCOMPARE(sr.data(), plaintext);
    sr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(sr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(sr.status(), Request::Inactive);

    sr.startRequest();
    QCOMPARE(srss.count(), 1);
    QCOMPARE(sr.status(), Request::Active);
    QCOMPARE(sr.result().code(), Result::Pending);
    QCOMPARE(srvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(sr);
    QCOMPARE(srss.count(), 2);
    QCOMPARE(sr.status(), Request::Finished);

    QCOMPARE(sr.result().code(), Result::Succeeded);
    QCOMPARE(srvs.count(), 1);
    QByteArray signature = sr.signature();

    // Verify the test signature
    // ----------------------------

    VerifyRequest vr;
    vr.setManager(&cm);
    QSignalSpy vrss(&vr, &VerifyRequest::statusChanged);
    QSignalSpy vrvs(&vr, &VerifyRequest::verifiedChanged);
    QCOMPARE(vr.verified(), false);
    QCOMPARE(vr.status(), Request::Inactive);
    vr.setKey(fullKey);
    QCOMPARE(vr.key(), fullKey);
    vr.setData(plaintext);
    QCOMPARE(vr.data(), plaintext);
    vr.setSignature(signature);
    QCOMPARE(vr.signature(), signature);
    vr.setDigestFunction(digestFunction);
    QCOMPARE(vr.digestFunction(), digestFunction);
    vr.setPadding(CryptoManager::SignaturePaddingNone);
    QCOMPARE(vr.padding(), CryptoManager::SignaturePaddingNone);
    vr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(vr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    vr.startRequest();
    QCOMPARE(vrss.count(), 1);
    QCOMPARE(vr.status(), Request::Active);
    QCOMPARE(vr.result().code(), Result::Pending);
    QCOMPARE(vrvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(vr);
    QCOMPARE(vrss.count(), 2);
    QCOMPARE(vr.status(), Request::Finished);

    QCOMPARE(vr.result().code(), Result::Succeeded);
    QCOMPARE(vrvs.count(), 1);
    QCOMPARE(vr.verified(), true);
}

void tst_cryptorequests::calculateDigest_data()
{
    QTest::addColumn<CryptoManager::DigestFunction>("digestFunction");
    QTest::addColumn<QCryptographicHash::Algorithm>("cryptographicHashAlgorithm");

    QTest::newRow("SHA256") << CryptoManager::DigestSha256 << QCryptographicHash::Sha256;
    QTest::newRow("SHA512") << CryptoManager::DigestSha512 << QCryptographicHash::Sha512;
    QTest::newRow("MD5") << CryptoManager::DigestMd5 << QCryptographicHash::Md5;
}

void tst_cryptorequests::calculateDigest()
{
    QFETCH(CryptoManager::DigestFunction, digestFunction);
    QFETCH(QCryptographicHash::Algorithm, cryptographicHashAlgorithm);

    QByteArray plaintext = "Test plaintext data";

    CalculateDigestRequest cdr;
    cdr.setManager(&cm);
    QSignalSpy cdrss(&cdr, &CalculateDigestRequest::statusChanged);
    QSignalSpy cdrds(&cdr, &CalculateDigestRequest::digestChanged);
    QCOMPARE(cdr.status(), Request::Inactive);
    cdr.setData(plaintext);
    QCOMPARE(cdr.data(), plaintext);
    cdr.setDigestFunction(digestFunction);
    QCOMPARE(cdr.digestFunction(), digestFunction);
    cdr.setPadding(CryptoManager::SignaturePaddingNone);
    QCOMPARE(cdr.padding(), CryptoManager::SignaturePaddingNone);
    cdr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(cdr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    cdr.startRequest();
    QCOMPARE(cdrss.count(), 1);
    QCOMPARE(cdr.status(), Request::Active);
    QCOMPARE(cdr.result().code(), Result::Pending);
    QCOMPARE(cdrds.count(), 0);

    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(cdr);
    QCOMPARE(cdrss.count(), 2);
    QCOMPARE(cdr.status(), Request::Finished);

    QCOMPARE(cdr.result().code(), Result::Succeeded);
    QCOMPARE(cdrds.count(), 1);

    QByteArray digest = cdr.digest();
    QVERIFY2(digest.length() != 0, "Calculated digest should NOT be empty.");
    QCOMPARE(digest, QCryptographicHash::hash(plaintext, cryptographicHashAlgorithm));
}

void tst_cryptorequests::storedKeyRequests_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::storedKeyRequests()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(CryptoManager::EncryptionPadding, padding);
    QFETCH(int, keySize);

    if (algorithm != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    keyTemplate.setComponentConstraints(Sailfish::Crypto::Key::MetaData | Sailfish::Crypto::Key::PublicKeyData | Sailfish::Crypto::Key::PrivateKeyData);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().errorMessage(), QString());
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.status(), Request::Inactive);
    gskr.startRequest();
    QCOMPARE(gskrss.count(), 1);
    QCOMPARE(gskr.status(), Request::Active);
    QCOMPARE(gskr.result().code(), Result::Pending);
    QCOMPARE(gskrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(ccr.result().errorMessage(), QString());
    QCOMPARE(gskr.result().code(), Result::Succeeded);
    QCOMPARE(gskrks.count(), 1);
    Sailfish::Crypto::Key keyReference = gskr.generatedKeyReference();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());
    QCOMPARE(keyReference.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QByteArray authData("fedcba9876543210");
    QByteArray authenticationTag;

    EncryptRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setInitialisationVector(initVector);
    QCOMPARE(er.initialisationVector(), initVector);
    er.setKey(keyReference);
    QCOMPARE(er.key(), keyReference);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setPadding(padding);
    QCOMPARE(er.padding(), padding);
    if (blockMode == CryptoManager::BlockModeGcm) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.status(), Request::Inactive);

    er.startRequest();
    QCOMPARE(er.result().errorMessage(), QString());
    QCOMPARE(erss.count(), 1);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(ercs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.result().errorMessage(), QString());
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ercs.count(), 1);
    QByteArray ciphertext = er.ciphertext();
    QVERIFY(!ciphertext.isEmpty());
    QVERIFY(ciphertext != plaintext);
    authenticationTag = er.authenticationTag();
    QCOMPARE(authenticationTag.isEmpty(), blockMode != CryptoManager::BlockModeGcm);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    dr.setManager(&cm);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setInitialisationVector(initVector);
    QCOMPARE(dr.initialisationVector(), initVector);
    dr.setKey(keyReference);
    QCOMPARE(dr.key(), keyReference);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);   
    dr.setPadding(padding);
    QCOMPARE(dr.padding(), padding);
    if (blockMode == CryptoManager::BlockModeGcm) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }
    dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.status(), Request::Inactive);

    dr.startRequest();
    QCOMPARE(drss.count(), 1);
    QCOMPARE(dr.status(), Request::Active);
    QCOMPARE(dr.result().code(), Result::Pending);
    QCOMPARE(drps.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(dr.result().code(), Result::Succeeded);
    QCOMPARE(drps.count(), 1);
    QByteArray decrypted = dr.plaintext();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(plaintext, decrypted);
    QCOMPARE(dr.verified(), !dr.authenticationData().isEmpty());

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    Sailfish::Secrets::FindSecretsRequest fsr;
    fsr.setManager(&sm);
    fsr.setFilter(filter);
    fsr.setFilterOperator(Sailfish::Secrets::SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    fsr.setCollectionName(keyTemplate.identifier().collectionName());
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 1);
    QCOMPARE(fsr.identifiers().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(fsr.identifiers().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 0);

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&cm);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(Key::MetaData);
    QCOMPARE(skr.keyComponents(), Key::MetaData);
    QCOMPARE(skr.status(), Request::Inactive);
    skr.startRequest();
    QCOMPARE(skrss.count(), 1);
    QCOMPARE(skr.status(), Request::Active);
    QCOMPARE(skr.result().code(), Result::Pending);
    QCOMPARE(skrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skrss.count(), 2);
    QCOMPARE(skr.status(), Request::Finished);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skrks.count(), 1);
    QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
    QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
    QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched

    // and that we can get the public key data + custom parameters
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched

    // and that we can get the secret key data
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData | Key::SecretKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(!skr.storedKey().secretKey().isEmpty());

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(dr.result().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    gskr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskr.result().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = gskr.generatedKeyReference();

    er.setKey(keyReference);
    er.setData(plaintext);
    if (blockMode == CryptoManager::BlockModeGcm) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(er.result().code(), Sailfish::Crypto::Result::Succeeded);
    ciphertext = er.ciphertext();
    if (blockMode == CryptoManager::BlockModeGcm) {
        authenticationTag = er.authenticationTag();
    }

    dr.setKey(keyReference);
    dr.setData(ciphertext);
    if (blockMode == CryptoManager::BlockModeGcm) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Succeeded);
    decrypted = dr.plaintext();
    QCOMPARE(decrypted, plaintext);

    // delete the key via deleteStoredKey, and test that the deletion worked.
    DeleteStoredKeyRequest dskr;
    dskr.setManager(&cm);
    QSignalSpy dskrss(&dskr, &DeleteStoredKeyRequest::statusChanged);
    dskr.setIdentifier(keyTemplate.identifier());
    QCOMPARE(dskr.identifier(), keyTemplate.identifier());
    QCOMPARE(dskr.status(), Request::Inactive);
    dskr.startRequest();
    QCOMPARE(dskrss.count(), 1);
    QCOMPARE(dskr.status(), Request::Active);
    QCOMPARE(dskr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dskr);
    QCOMPARE(dskrss.count(), 2);
    QCOMPARE(dskr.status(), Request::Finished);
    QCOMPARE(dskr.result().code(), Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(dr.result().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    Sailfish::Secrets::StoredSecretRequest gsr;
    gsr.setManager(&sm);
    gsr.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                          keyReference.identifier().name(),
                          keyReference.identifier().collectionName()));
    gsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(gsr.result().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_cryptorequests::storedDerivedKeyRequests_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::storedDerivedKeyRequests()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(CryptoManager::EncryptionPadding, padding);
    QFETCH(int, keySize);

    if (algorithm != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    // test generating a symmetric cipher key via a key derivation function
    // and storing securely in the same plugin which produces the key.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    keyTemplate.setComponentConstraints(Sailfish::Crypto::Key::MetaData | Sailfish::Crypto::Key::PublicKeyData | Sailfish::Crypto::Key::PrivateKeyData);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    Sailfish::Crypto::KeyDerivationParameters skdf;
    skdf.setKeyDerivationFunction(Sailfish::Crypto::CryptoManager::KdfPkcs5Pbkdf2);
    skdf.setKeyDerivationMac(Sailfish::Crypto::CryptoManager::MacHmac);
    skdf.setKeyDerivationDigestFunction(Sailfish::Crypto::CryptoManager::DigestSha1);
    skdf.setIterations(16384);
    skdf.setSalt(QByteArray("0123456789abcdef"));
    //skdf.setInputData(QByteArray("example user passphrase")); // TODO: this is implemented, but not covered by the unit test if uiParams exists!
    skdf.setOutputKeySize(keySize);

    Sailfish::Crypto::InteractionParameters uiParams;
    uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    uiParams.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);
    uiParams.setPromptText(QLatin1String("Enter the passphrase for the unit test"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().errorMessage(), QString());
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setKeyDerivationParameters(skdf);
    QCOMPARE(gskr.keyDerivationParameters(), skdf);
    gskr.setInteractionParameters(uiParams);
    QCOMPARE(gskr.interactionParameters(), uiParams);
    QCOMPARE(gskr.status(), Request::Inactive);
    gskr.startRequest();
    QCOMPARE(gskrss.count(), 1);
    QCOMPARE(gskr.status(), Request::Active);
    QCOMPARE(gskr.result().code(), Result::Pending);
    QCOMPARE(gskrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(gskr.result().code(), Result::Succeeded);
    QCOMPARE(gskrks.count(), 1);
    Sailfish::Crypto::Key keyReference = gskr.generatedKeyReference();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());
    QCOMPARE(keyReference.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QByteArray authData("fedcba9876543210");
    QByteArray authenticationTag;

    EncryptRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setInitialisationVector(initVector);
    QCOMPARE(er.initialisationVector(), initVector);
    er.setKey(keyReference);
    QCOMPARE(er.key(), keyReference);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);    
    er.setPadding(padding);
    QCOMPARE(er.padding(), padding);
    if (blockMode == CryptoManager::BlockModeGcm) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.status(), Request::Inactive);

    er.startRequest();
    QCOMPARE(erss.count(), 1);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(ercs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ercs.count(), 1);
    QByteArray ciphertext = er.ciphertext();
    QVERIFY(!ciphertext.isEmpty());
    QVERIFY(ciphertext != plaintext);
    authenticationTag = er.authenticationTag();
    QCOMPARE(authenticationTag.isEmpty(), blockMode != CryptoManager::BlockModeGcm);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    dr.setManager(&cm);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setInitialisationVector(initVector);
    QCOMPARE(dr.initialisationVector(), initVector);
    dr.setKey(keyReference);
    QCOMPARE(dr.key(), keyReference);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);
    dr.setPadding(padding);
    QCOMPARE(dr.padding(), padding);
    if (blockMode == CryptoManager::BlockModeGcm) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }
    dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.status(), Request::Inactive);

    dr.startRequest();
    QCOMPARE(drss.count(), 1);
    QCOMPARE(dr.status(), Request::Active);
    QCOMPARE(dr.result().code(), Result::Pending);
    QCOMPARE(drps.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(dr.result().code(), Result::Succeeded);
    QCOMPARE(drps.count(), 1);
    QByteArray decrypted = dr.plaintext();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(plaintext, decrypted);
    QCOMPARE(dr.verified(), !dr.authenticationData().isEmpty());

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    Sailfish::Secrets::FindSecretsRequest fsr;
    fsr.setManager(&sm);
    fsr.setFilter(filter);
    fsr.setFilterOperator(Sailfish::Secrets::SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    fsr.setCollectionName(keyTemplate.identifier().collectionName());
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 1);
    QCOMPARE(fsr.identifiers().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(fsr.identifiers().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 0);

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&cm);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(Key::MetaData);
    QCOMPARE(skr.keyComponents(), Key::MetaData);
    QCOMPARE(skr.status(), Request::Inactive);
    skr.startRequest();
    QCOMPARE(skrss.count(), 1);
    QCOMPARE(skr.status(), Request::Active);
    QCOMPARE(skr.result().code(), Result::Pending);
    QCOMPARE(skrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skrss.count(), 2);
    QCOMPARE(skr.status(), Request::Finished);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skrks.count(), 1);
    QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
    QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
    QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched

    // and that we can get the public key data + custom parameters
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched

    // and that we can get the secret key data
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData | Key::SecretKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(!skr.storedKey().secretKey().isEmpty());

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(dr.result().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    gskr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskr.result().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = gskr.generatedKeyReference();

    er.setKey(keyReference);
    er.setData(plaintext);
    er.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(er.result().code(), Sailfish::Crypto::Result::Succeeded);
    ciphertext = er.ciphertext();

    dr.setKey(keyReference);
    dr.setData(ciphertext);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Succeeded);
    decrypted = dr.plaintext();
    QCOMPARE(decrypted, plaintext);

    // delete the key via deleteStoredKey, and test that the deletion worked.
    DeleteStoredKeyRequest dskr;
    dskr.setManager(&cm);
    QSignalSpy dskrss(&dskr, &DeleteStoredKeyRequest::statusChanged);
    dskr.setIdentifier(keyTemplate.identifier());
    QCOMPARE(dskr.identifier(), keyTemplate.identifier());
    QCOMPARE(dskr.status(), Request::Inactive);
    dskr.startRequest();
    QCOMPARE(dskrss.count(), 1);
    QCOMPARE(dskr.status(), Request::Active);
    QCOMPARE(dskr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dskr);
    QCOMPARE(dskrss.count(), 2);
    QCOMPARE(dskr.status(), Request::Finished);
    QCOMPARE(dskr.result().code(), Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(dr.result().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    Sailfish::Secrets::StoredSecretRequest gsr;
    gsr.setManager(&sm);
    gsr.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                          keyReference.identifier().name(),
                          keyReference.identifier().collectionName()));
    gsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(gsr.result().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_cryptorequests::storedGeneratedKeyRequests()
{
    // test generating an asymmetric cipher key pair
    // and storing securely in the same plugin which produces the key.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmRsa);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt
                             |Sailfish::Crypto::CryptoManager::OperationDecrypt
                             |Sailfish::Crypto::CryptoManager::OperationSign
                             |Sailfish::Crypto::CryptoManager::OperationVerify);
    keyTemplate.setComponentConstraints(Sailfish::Crypto::Key::MetaData | Sailfish::Crypto::Key::PublicKeyData | Sailfish::Crypto::Key::PrivateKeyData);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    Sailfish::Crypto::RsaKeyPairGenerationParameters rsakpg;
    rsakpg.setModulusLength(2048);
    rsakpg.setPublicExponent(65537);
    rsakpg.setNumberPrimes(2);

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().errorMessage(), QString());
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setKeyPairGenerationParameters(rsakpg);
    QCOMPARE(gskr.status(), Request::Inactive);
    gskr.startRequest();
    QCOMPARE(gskrss.count(), 1);
    QCOMPARE(gskr.status(), Request::Active);
    QCOMPARE(gskr.result().code(), Result::Pending);
    QCOMPARE(gskrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(gskr.result().code(), Result::Succeeded);
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskrks.count(), 1);
    Sailfish::Crypto::Key keyReference = gskr.generatedKeyReference();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());
    QCOMPARE(keyReference.filterData(), keyTemplate.filterData());

    // TODO: attempt encryption/decryption once implemented

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    Sailfish::Secrets::FindSecretsRequest fsr;
    fsr.setManager(&sm);
    fsr.setFilter(filter);
    fsr.setFilterOperator(Sailfish::Secrets::SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    fsr.setCollectionName(keyTemplate.identifier().collectionName());
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 1);
    QCOMPARE(fsr.identifiers().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(fsr.identifiers().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 0);

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&cm);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(Key::MetaData);
    QCOMPARE(skr.keyComponents(), Key::MetaData);
    QCOMPARE(skr.status(), Request::Inactive);
    skr.startRequest();
    QCOMPARE(skrss.count(), 1);
    QCOMPARE(skr.status(), Request::Active);
    QCOMPARE(skr.result().code(), Result::Pending);
    QCOMPARE(skrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skrss.count(), 2);
    QCOMPARE(skr.status(), Request::Finished);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skrks.count(), 1);
    QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
    QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
    QVERIFY(skr.storedKey().publicKey().isEmpty()); // public key data, not fetched
    QVERIFY(skr.storedKey().privateKey().isEmpty()); // secret key data, not fetched

    // and that we can get the public key data + custom parameters
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(!skr.storedKey().publicKey().isEmpty()); // public key data, fetched
    QVERIFY(skr.storedKey().privateKey().isEmpty()); // secret key data, not fetched

    // and that we can get the secret key data
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData | Key::SecretKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(!skr.storedKey().publicKey().isEmpty());  // public key data, fetched
    QVERIFY(!skr.storedKey().privateKey().isEmpty()); // private key data, fetched

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_cryptorequests::cipherEncryptDecrypt_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::cipherEncryptDecrypt()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(CryptoManager::EncryptionPadding, padding);
    QFETCH(int, keySize);

    if (algorithm != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    // then use that stored key to perform stream cipher encrypt/decrypt operations.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.status(), Request::Inactive);
    gskr.startRequest();
    QCOMPARE(gskrss.count(), 1);
    QCOMPARE(gskr.status(), Request::Active);
    QCOMPARE(gskr.result().code(), Result::Pending);
    QCOMPARE(gskrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(gskr.result().code(), Result::Succeeded);
    QCOMPARE(gskrks.count(), 1);
    Sailfish::Crypto::Key keyReference = gskr.generatedKeyReference();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());
    QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    Sailfish::Crypto::Key minimalKeyReference(keyReference.identifier().name(),
                                              keyReference.identifier().collectionName());

    // now perform encryption.
    QByteArray iv = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QByteArray ciphertext;
    QByteArray decrypted;
    QByteArray plaintext("This is a long plaintext"
                         " which contains multiple blocks of data"
                         " which will be encrypted over several updates"
                         " via a stream cipher operation.");
    QByteArray authData("fedcba9876543210");
    QByteArray authenticationTag;

    CipherRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er,  &CipherRequest::statusChanged);
    QSignalSpy ergds(&er, &CipherRequest::generatedDataChanged);
    er.setKey(minimalKeyReference);
    QCOMPARE(er.key(), minimalKeyReference);
    er.setOperation(Sailfish::Crypto::CryptoManager::OperationEncrypt);
    QCOMPARE(er.operation(), Sailfish::Crypto::CryptoManager::OperationEncrypt);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setEncryptionPadding(padding);
    QCOMPARE(er.encryptionPadding(), padding);
    er.setInitialisationVector(iv);
    QCOMPARE(er.initialisationVector(), iv);
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(er.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    er.setCipherMode(CipherRequest::InitialiseCipher);
    QCOMPARE(er.cipherMode(), CipherRequest::InitialiseCipher);
    QCOMPARE(er.status(), Request::Inactive);
    er.startRequest();
    QCOMPARE(erss.count(), 1);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(ergds.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().errorMessage(), QString());
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ergds.count(), 0);

    int gdsCount = 0, ssCount = 2, chunkStartPos = 0;

    if (blockMode == CryptoManager::BlockModeGcm) {
        er.setCipherMode(CipherRequest::UpdateCipherAuthentication);
        QCOMPARE(er.cipherMode(), CipherRequest::UpdateCipherAuthentication);
        er.setData(authData);
        QCOMPARE(er.data(), authData);
        ssCount = erss.count();
        er.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
        QCOMPARE(er.status(), Request::Finished);
        QCOMPARE(er.result().code(), Result::Succeeded);
        QCOMPARE(erss.count(), ssCount + 2);
        QCOMPARE(er.status(), Request::Finished);
        QCOMPARE(er.result().code(), Result::Succeeded);
    }

    while (chunkStartPos < plaintext.size()) {
        QByteArray chunk = plaintext.mid(chunkStartPos, 16);
        if (chunk.isEmpty()) break;
        chunkStartPos += 16;
        er.setCipherMode(CipherRequest::UpdateCipher);
        QCOMPARE(er.cipherMode(), CipherRequest::UpdateCipher);
        er.setData(chunk);
        QCOMPARE(er.data(), chunk);
        gdsCount = ergds.count();
        ssCount = erss.count();
        er.startRequest();
        QCOMPARE(erss.count(), ssCount + 1);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
        QCOMPARE(erss.count(), ssCount + 2);
        QCOMPARE(er.status(), Request::Finished);
        QCOMPARE(er.result().code(), Result::Succeeded);
        QCOMPARE(ergds.count(), gdsCount + 1);
        QByteArray ciphertextChunk = er.generatedData();
        if (chunk.size() >= 16) {
            QVERIFY(ciphertextChunk.size() >= chunk.size());
            // otherwise, it will be emitted during FinaliseCipher
        }
        ciphertext.append(ciphertextChunk);
        QVERIFY(!ciphertext.isEmpty());
    }

    er.setCipherMode(CipherRequest::FinaliseCipher);
    QCOMPARE(er.cipherMode(), CipherRequest::FinaliseCipher);
    er.setData(QByteArray());
    ssCount = erss.count();
    er.startRequest();
    QCOMPARE(erss.count(), ssCount + 1);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().errorMessage(), QString());
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(erss.count(), ssCount + 2);
    if (blockMode == CryptoManager::BlockModeGcm) {
        authenticationTag = er.generatedData();
    } else {
        ciphertext.append(er.generatedData()); // may or may not be empty.
    }
    QVERIFY(!ciphertext.isEmpty());

    // now perform decryption, and ensure the roundtrip matches.
    CipherRequest dr;
    dr.setManager(&cm);
    QSignalSpy drss(&dr,  &CipherRequest::statusChanged);
    QSignalSpy drgds(&dr, &CipherRequest::generatedDataChanged);
    dr.setKey(minimalKeyReference);
    QCOMPARE(dr.key(), minimalKeyReference);
    dr.setInitialisationVector(iv);
    QCOMPARE(dr.initialisationVector(), iv);
    dr.setOperation(Sailfish::Crypto::CryptoManager::OperationDecrypt);
    QCOMPARE(dr.operation(), Sailfish::Crypto::CryptoManager::OperationDecrypt);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);
    dr.setEncryptionPadding(padding);
    QCOMPARE(dr.encryptionPadding(), padding);
    dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(dr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    dr.setCipherMode(CipherRequest::InitialiseCipher);
    QCOMPARE(dr.cipherMode(), CipherRequest::InitialiseCipher);
    QCOMPARE(dr.status(), Request::Inactive);
    dr.startRequest();
    QCOMPARE(drss.count(), 1);
    QCOMPARE(dr.status(), Request::Active);
    QCOMPARE(dr.result().code(), Result::Pending);
    QCOMPARE(drgds.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(dr.result().code(), Result::Succeeded);
    QCOMPARE(drgds.count(), 0);

    if (blockMode == CryptoManager::BlockModeGcm) {
        dr.setCipherMode(CipherRequest::UpdateCipherAuthentication);
        QCOMPARE(dr.cipherMode(), CipherRequest::UpdateCipherAuthentication);
        dr.setData(authData);
        QCOMPARE(dr.data(), authData);
        ssCount = drss.count();
        dr.startRequest();
        QCOMPARE(drss.count(), ssCount + 1);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
        QCOMPARE(drss.count(), ssCount + 2);
        QCOMPARE(dr.status(), Request::Finished);
        QCOMPARE(dr.result().code(), Result::Succeeded);
    }

    gdsCount = 0; ssCount = 2; chunkStartPos = 0;
    while (chunkStartPos < ciphertext.size()) {
        QByteArray chunk = ciphertext.mid(chunkStartPos, 16);
        if (chunk.isEmpty()) break;
        chunkStartPos += 16;
        dr.setCipherMode(CipherRequest::UpdateCipher);
        QCOMPARE(dr.cipherMode(), CipherRequest::UpdateCipher);
        dr.setData(chunk);
        QCOMPARE(dr.data(), chunk);
        gdsCount = drgds.count();
        ssCount = drss.count();
        dr.startRequest();
        QCOMPARE(drss.count(), ssCount + 1);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
        QCOMPARE(drss.count(), ssCount + 2);
        QCOMPARE(dr.status(), Request::Finished);
        QCOMPARE(dr.result().code(), Result::Succeeded);
        QByteArray plaintextChunk = dr.generatedData();
        decrypted.append(plaintextChunk);
        if (blockMode != CryptoManager::BlockModeGcm
                && chunkStartPos >= 32) {
            // in CBC mode the first block will not be returned,
            // due to the cipher requiring it for the next update.
            QCOMPARE(drgds.count(), gdsCount + 1);
            QVERIFY(plaintextChunk.size() >= chunk.size());
            QVERIFY(!decrypted.isEmpty());
        }
    }

    dr.setCipherMode(CipherRequest::FinaliseCipher);
    QCOMPARE(dr.cipherMode(), CipherRequest::FinaliseCipher);
    dr.setData(blockMode == CryptoManager::BlockModeGcm ? authenticationTag : QByteArray());
    ssCount = drss.count();
    dr.startRequest();
    QCOMPARE(drss.count(), ssCount + 1);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), ssCount + 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(dr.result().errorMessage(), QString());
    QCOMPARE(dr.result().code(), Result::Succeeded);
    decrypted.append(dr.generatedData()); // may or may not be empty.
    QCOMPARE(plaintext, decrypted); // successful round trip!
    QCOMPARE(dr.verified(), blockMode == CryptoManager::BlockModeGcm);

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
}

#define CIPHER_BENCHMARK_CHUNK_SIZE 131072
#define BATCH_BENCHMARK_CHUNK_SIZE 32768
#define BENCHMARK_TEST_FILE QLatin1String("/tmp/sailfish.crypto.testfile")

void tst_cryptorequests::cipherBenchmark_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::cipherBenchmark()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(CryptoManager::EncryptionPadding, padding);
    QFETCH(int, keySize);

    if (algorithm != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    if (!QFile::exists(BENCHMARK_TEST_FILE)) {
        QSKIP("First generate test data via: head -c 33554432 </dev/urandom >/tmp/sailfish.crypto.testfile");
    }

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    // then use that stored key to perform stream cipher encrypt/decrypt operations.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.status(), Request::Inactive);
    gskr.startRequest();
    QCOMPARE(gskrss.count(), 1);
    QCOMPARE(gskr.status(), Request::Active);
    QCOMPARE(gskr.result().code(), Result::Pending);
    QCOMPARE(gskrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(gskr.result().code(), Result::Succeeded);
    QCOMPARE(gskrks.count(), 1);
    Sailfish::Crypto::Key keyReference = gskr.generatedKeyReference();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());
    QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    Sailfish::Crypto::Key minimalKeyReference(keyReference.identifier().name(),
                                              keyReference.identifier().collectionName());

    QByteArray iv = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QByteArray canonicalCiphertext;
    {
        // now perform encryption in non-batch mode.
        // that is, we wait for each update to complete before beginning the next.
        QByteArray ciphertext;
        QByteArray decrypted;
        QByteArray plaintext;

        // read the test file into the plaintext array.
        // we don't want the file I/O to be part of the benchmark.
        QFile testfile(BENCHMARK_TEST_FILE);
        QVERIFY(testfile.open(QIODevice::ReadOnly));
        plaintext = testfile.readAll();
        testfile.close();

        qDebug() << "Beginning non-batch benchmark:" << plaintext.size() << "bytes at:" << QDateTime::currentDateTime().toString(Qt::ISODate);
        qint64 encryptionTime = 0, decryptionTime = 0, totalTime = 0;
        QElapsedTimer et;
        et.start();

        CipherRequest er;
        er.setManager(&cm);
        er.setKey(minimalKeyReference);
        er.setOperation(Sailfish::Crypto::CryptoManager::OperationEncrypt);
        er.setBlockMode(blockMode);
        er.setEncryptionPadding(padding);
        er.setInitialisationVector(iv);
        QCOMPARE(er.initialisationVector(), iv);
        er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        er.setCipherMode(CipherRequest::InitialiseCipher);
        er.startRequest();
        SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);

        int chunkStartPos = 0;
        while (chunkStartPos < plaintext.size()) {
            QByteArray chunk = plaintext.mid(chunkStartPos, CIPHER_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += CIPHER_BENCHMARK_CHUNK_SIZE;
            er.setCipherMode(CipherRequest::UpdateCipher);
            er.setData(chunk);
            er.startRequest();
            SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
            QByteArray ciphertextChunk = er.generatedData();
            ciphertext.append(ciphertextChunk);
        }

        er.setCipherMode(CipherRequest::FinaliseCipher);
        er.setData(QByteArray());
        er.startRequest();
        SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
        ciphertext.append(er.generatedData()); // may or may not be empty.

        encryptionTime = et.elapsed();

        // now perform decryption, and ensure the roundtrip matches.
        CipherRequest dr;
        dr.setManager(&cm);
        dr.setKey(minimalKeyReference);
        dr.setInitialisationVector(iv);
        dr.setOperation(Sailfish::Crypto::CryptoManager::OperationDecrypt);
        dr.setBlockMode(blockMode);
        dr.setEncryptionPadding(padding);
        dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        dr.setCipherMode(CipherRequest::InitialiseCipher);
        dr.startRequest();
        SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);

        chunkStartPos = 0;
        while (chunkStartPos < ciphertext.size()) {
            QByteArray chunk = ciphertext.mid(chunkStartPos, CIPHER_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += CIPHER_BENCHMARK_CHUNK_SIZE;
            dr.setCipherMode(CipherRequest::UpdateCipher);
            dr.setData(chunk);
            dr.startRequest();
            SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
            QByteArray plaintextChunk = dr.generatedData();
            decrypted.append(plaintextChunk);
        }

        dr.setCipherMode(CipherRequest::FinaliseCipher);
        dr.setData(QByteArray());
        dr.startRequest();
        SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
        decrypted.append(dr.generatedData()); // may or may not be empty.

        totalTime = et.elapsed();
        decryptionTime = totalTime - encryptionTime;
        qWarning() << "Finished non-batch benchmark at:" << QDateTime::currentDateTime().toString(Qt::ISODate);
        qWarning() << "Encrypted in" << encryptionTime << ", Decrypted in" << decryptionTime << "(msecs)";
        QCOMPARE(plaintext, decrypted); // successful round trip!
        canonicalCiphertext = ciphertext;
    }

    {
        // now perform "batch" encryption where we don't wait for
        // the result of previous data updates prior to beginning the next.
        QByteArray ciphertext;
        QByteArray decrypted;
        QByteArray plaintext;

        // read the test file into the plaintext array.
        // we don't want the file I/O to be part of the benchmark.
        QFile testfile(BENCHMARK_TEST_FILE);
        QVERIFY(testfile.open(QIODevice::ReadOnly));
        plaintext = testfile.readAll();
        testfile.close();

        qWarning() << "Beginning batch benchmark:" << plaintext.size() << "bytes at:" << QDateTime::currentDateTime().toString(Qt::ISODate);
        qint64 encryptionTime = 0, decryptionTime = 0, totalTime = 0;
        QElapsedTimer et;
        et.start();

        CipherRequest er;
        QObject::connect(&er, &CipherRequest::generatedDataChanged,
                         [&er, &ciphertext] {
            ciphertext.append(er.generatedData());
        });
        er.setManager(&cm);
        er.setKey(minimalKeyReference);
        er.setInitialisationVector(iv);
        er.setOperation(Sailfish::Crypto::CryptoManager::OperationEncrypt);
        er.setBlockMode(blockMode);
        er.setEncryptionPadding(padding);
        er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        er.setCipherMode(CipherRequest::InitialiseCipher);
        er.startRequest();
        LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);

        int chunkStartPos = 0;
        while (chunkStartPos < plaintext.size()) {
            QByteArray chunk = plaintext.mid(chunkStartPos, BATCH_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += BATCH_BENCHMARK_CHUNK_SIZE;
            er.setCipherMode(CipherRequest::UpdateCipher);
            er.setData(chunk);
            er.startRequest();
        }
        LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er); // wait for the updates to finish.

        er.setCipherMode(CipherRequest::FinaliseCipher);
        er.setData(QByteArray());
        er.startRequest();
        LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);

        encryptionTime = et.elapsed();

        // now perform decryption, and ensure the roundtrip matches.
        CipherRequest dr;
        QObject::connect(&dr, &CipherRequest::generatedDataChanged,
                         [&dr, &decrypted] {
            decrypted.append(dr.generatedData());
        });
        dr.setManager(&cm);
        dr.setKey(minimalKeyReference);
        dr.setInitialisationVector(iv);
        dr.setOperation(Sailfish::Crypto::CryptoManager::OperationDecrypt);
        dr.setBlockMode(blockMode);
        dr.setEncryptionPadding(padding);
        dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        dr.setCipherMode(CipherRequest::InitialiseCipher);
        dr.startRequest();
        LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);

        chunkStartPos = 0;
        while (chunkStartPos < ciphertext.size()) {
            QByteArray chunk = ciphertext.mid(chunkStartPos, BATCH_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += BATCH_BENCHMARK_CHUNK_SIZE;
            dr.setCipherMode(CipherRequest::UpdateCipher);
            dr.setData(chunk);
            dr.startRequest();
        }
        LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr); // drain the queue of responses.

        dr.setCipherMode(CipherRequest::FinaliseCipher);
        dr.setData(QByteArray());
        dr.startRequest();
        LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);

        totalTime = et.elapsed();
        decryptionTime = totalTime - encryptionTime;
        qWarning() << "Finished batch benchmark at:" << QDateTime::currentDateTime().toString(Qt::ISODate);
        qWarning() << "Encrypted in" << encryptionTime << ", Decrypted in" << decryptionTime << "(msecs)";
        QCOMPARE(plaintext, decrypted); // successful round trip!
        QCOMPARE(ciphertext, canonicalCiphertext);
    }

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_cryptorequests::cipherTimeout()
{
    QSKIP("This test should only be run manually after changing CIPHER_SESSION_INACTIVITY_TIMEOUT to 10000");

    // this test ensures that cipher sessions time out after some period of time.
    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    // then use that stored key to perform stream cipher encrypt/decrypt operations.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setSize(256);
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.status(), Request::Inactive);
    gskr.startRequest();
    QCOMPARE(gskrss.count(), 1);
    QCOMPARE(gskr.status(), Request::Active);
    QCOMPARE(gskr.result().code(), Result::Pending);
    QCOMPARE(gskrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(gskr.result().code(), Result::Succeeded);
    QCOMPARE(gskrks.count(), 1);
    Sailfish::Crypto::Key keyReference = gskr.generatedKeyReference();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());
    QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    Sailfish::Crypto::Key minimalKeyReference(keyReference.identifier().name(),
                                              keyReference.identifier().collectionName());

    // now perform encryption.
    QByteArray iv = generateInitializationVector(keyTemplate.algorithm(), Sailfish::Crypto::CryptoManager::BlockModeCbc);
    QByteArray ciphertext;
    QByteArray decrypted;
    QByteArray plaintext("This is a long plaintext"
                         " which contains multiple blocks of data"
                         " which will be encrypted over several updates"
                         " via a stream cipher operation.");

    CipherRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er,  &CipherRequest::statusChanged);
    QSignalSpy ergds(&er, &CipherRequest::generatedDataChanged);
    er.setKey(minimalKeyReference);
    QCOMPARE(er.key(), minimalKeyReference);
    er.setOperation(Sailfish::Crypto::CryptoManager::OperationEncrypt);
    QCOMPARE(er.operation(), Sailfish::Crypto::CryptoManager::OperationEncrypt);
    er.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
    QCOMPARE(er.blockMode(), Sailfish::Crypto::CryptoManager::BlockModeCbc);
    er.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    QCOMPARE(er.encryptionPadding(), Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    er.setInitialisationVector(iv);
    QCOMPARE(er.initialisationVector(), iv);
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(er.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    er.setCipherMode(CipherRequest::InitialiseCipher);
    QCOMPARE(er.cipherMode(), CipherRequest::InitialiseCipher);
    QCOMPARE(er.status(), Request::Inactive);
    er.startRequest();
    QCOMPARE(erss.count(), 1);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(ergds.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ergds.count(), 0);

    // wait for 8 seconds, which is less than the 10 second timeout.
    // note that the "real" timeout is 60 seconds, and the value
    // needs to be modified in order to run this test.
    QTest::qWait(8000);

    // now update the cipher session with the first chunk of data.
    // since the timeout was not exceeded, this should succeed.
    QByteArray chunk = plaintext.mid(0, 16);
    er.setCipherMode(CipherRequest::UpdateCipher);
    er.setData(chunk);
    er.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);

    // wait for 12 seconds, which is greater than the 10 second timeout.
    QTest::qWait(12000);

    // now update the cipher session with the second chunk of data.
    // since the timeout was exceeded, this should not succeed.
    chunk = plaintext.mid(16, 32);
    er.setCipherMode(CipherRequest::UpdateCipher);
    er.setData(chunk);
    er.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Failed);
    QCOMPARE(er.result().errorMessage(), QLatin1String("Unknown cipher session token provided"));

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_cryptorequests::lockCode()
{
    Sailfish::Crypto::InteractionParameters uiParams;
    uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    uiParams.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);
    uiParams.setPromptText(QLatin1String("Modify the lock code for the crypto plugin"));

    Sailfish::Crypto::LockCodeRequest lcr;
    lcr.setManager(&cm);
    lcr.setLockCodeRequestType(Sailfish::Crypto::LockCodeRequest::ModifyLockCode);
    QCOMPARE(lcr.lockCodeRequestType(), Sailfish::Crypto::LockCodeRequest::ModifyLockCode);
    lcr.setLockCodeTargetType(Sailfish::Crypto::LockCodeRequest::ExtensionPlugin);
    QCOMPARE(lcr.lockCodeTargetType(), Sailfish::Crypto::LockCodeRequest::ExtensionPlugin);
    lcr.setLockCodeTarget(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(lcr.lockCodeTarget(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    lcr.setInteractionParameters(uiParams);
    QCOMPARE(lcr.interactionParameters(), uiParams);
    lcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(lcr);
    QCOMPARE(lcr.status(), Sailfish::Crypto::Request::Finished);
    QCOMPARE(lcr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(lcr.result().errorMessage(), QStringLiteral("Crypto plugin %1 does not support locking")
                                                    .arg(DEFAULT_TEST_CRYPTO_PLUGIN_NAME));

    uiParams.setPromptText(QLatin1String("Provide the lock code for the crypto plugin"));
    uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    lcr.setLockCodeRequestType(Sailfish::Crypto::LockCodeRequest::ProvideLockCode);
    lcr.setInteractionParameters(uiParams);
    lcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(lcr);
    QCOMPARE(lcr.status(), Sailfish::Crypto::Request::Finished);
    QCOMPARE(lcr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(lcr.result().errorMessage(), QStringLiteral("Crypto plugin %1 does not support locking")
                                                    .arg(DEFAULT_TEST_CRYPTO_PLUGIN_NAME));

    lcr.setLockCodeRequestType(Sailfish::Crypto::LockCodeRequest::ForgetLockCode);
    lcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(lcr);
    QCOMPARE(lcr.status(), Sailfish::Crypto::Request::Finished);
    QCOMPARE(lcr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(lcr.result().errorMessage(), QStringLiteral("Crypto plugin %1 does not support locking")
                                                    .arg(DEFAULT_TEST_CRYPTO_PLUGIN_NAME));
}

void tst_cryptorequests::pluginThreading()
{
    // This test is meant to be run manually and
    // concurrently with tst_secretsrequests::pluginThreading().
    // It performs a series of simple crypto requests which
    // will use the OpenSSL crypto plugin to encrypt and decrypt
    // data in the Crypto Plugins Thread.
    // The tst_secretsrequests::pluginThreading() will concurrently
    // be using the OpenSSL secrets encryption plugin to encrypt
    // and decrypt data in the Crypto Plugins Thread.
    // If the appropriate locking and multithreading has not been
    // implemented, we expect the daemon to crash, or to produce
    // incorrect data.

    Key keyTemplate;
    keyTemplate.setSize(256);
    keyTemplate.setAlgorithm(CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    gkr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gkr);
    QCOMPARE(gkr.status(), Request::Finished);
    QCOMPARE(gkr.result().code(), Result::Succeeded);
    Key fullKey = gkr.generatedKey();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    QElapsedTimer et;
    et.start();
    while (et.elapsed() < 15000) {
        // test encrypting some plaintext with the generated key
        QByteArray plaintext = "Test plaintext data";
        QByteArray initVector = "0123456789abcdef";
        EncryptRequest er;
        er.setManager(&cm);
        er.setData(plaintext);
        er.setInitialisationVector(initVector);
        er.setKey(fullKey);
        er.setBlockMode(CryptoManager::BlockModeCbc);
        er.setPadding(CryptoManager::EncryptionPaddingNone);
        er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
        er.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
        QCOMPARE(er.status(), Request::Finished);
        QCOMPARE(er.result().code(), Result::Succeeded);
        QByteArray ciphertext = er.ciphertext();
        QVERIFY(!ciphertext.isEmpty());
        QVERIFY(ciphertext != plaintext);

        // test decrypting the ciphertext, and ensure that the roundtrip works.
        DecryptRequest dr;
        dr.setManager(&cm);
        dr.setData(ciphertext);
        dr.setInitialisationVector(initVector);
        dr.setKey(fullKey);
        dr.setBlockMode(CryptoManager::BlockModeCbc);
        dr.setPadding(CryptoManager::EncryptionPaddingNone);
        dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
        dr.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
        QCOMPARE(dr.status(), Request::Finished);
        QCOMPARE(dr.result().code(), Result::Succeeded);
        QByteArray decrypted = dr.plaintext();
        QVERIFY(!decrypted.isEmpty());
        QCOMPARE(plaintext, decrypted);
    }
}

void tst_cryptorequests::requestInterleaving()
{
    // Repeatedly create and delete a collection, while performing
    // a long-running encryption operation on the Secrets Plugin Thread.
    // If the bookkeeping database is modified by the delete request
    // prior to the create request being completely finished, then
    // the requests have been interleaved incorrectly.

    QByteArray initVector = "0123456789abcdef";
    QByteArray plaintext = createRandomTestData(10 * 1024 * 1024);

    Key keyTemplate;
    keyTemplate.setSize(256);
    keyTemplate.setAlgorithm(CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gkr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gkr);
    QCOMPARE(gkr.status(), Request::Finished);
    QCOMPARE(gkr.result().code(), Result::Succeeded);
    Key fullKey = gkr.generatedKey();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    EncryptRequest er;
    er.setManager(&cm);
    er.setData(plaintext);
    er.setInitialisationVector(initVector);
    er.setKey(fullKey);
    er.setBlockMode(CryptoManager::BlockModeCbc);
    er.setPadding(CryptoManager::EncryptionPaddingNone);
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);

    Sailfish::Secrets::Secret testSecret(Sailfish::Secrets::Secret::Identifier("testsecretname"));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Sailfish::Secrets::Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

    Sailfish::Secrets::StoreSecretRequest ssr;
    ssr.setManager(&sm);
    ssr.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::StandaloneDeviceLockSecret);
    ssr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ssr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ssr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
    ssr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ssr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ssr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ssr.setSecret(testSecret);
    ssr.startRequest();

    Sailfish::Secrets::DeleteSecretRequest dsr;
    dsr.setManager(&sm);
    dsr.setIdentifier(testSecret.identifier());
    dsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    dsr.startRequest();

    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("testinterleavingcollection"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.startRequest();

    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(
                                  QLatin1String("storedkey"),
                                  QLatin1String("testinterleavingcollection")));
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    gskr.setKeyTemplate(keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.startRequest();

    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("testinterleavingcollection"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    dcr.startRequest();

    // if step == 0, we create and delete the collection
    // if step == 1, we create the collection
    // if step == 2, we generate the stored key only, so it will succeed.
    // if step == 3, we delete the collection.
    int generateStoredKeyStep = 0;
    bool gskrMustSucceed = false;

    QElapsedTimer et;
    et.start();
    while (et.elapsed() < 30000) {
        if (!er.status() == Request::Finished) {
            er.startRequest();
        }

        bool dcrWasFinished = dcr.status() == Sailfish::Secrets::Request::Finished;
        bool ccrWasFinished = ccr.status() == Sailfish::Secrets::Request::Finished;
        if (ccr.status() == Sailfish::Secrets::Request::Finished) {
            QCOMPARE(ccr.result().errorMessage(), QString());
            QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);
            if (dcr.status() == Sailfish::Secrets::Request::Finished) {
                // if the previous step was 3 (i.e. current step is 0)
                // or the previous step was 0 (i.e. current step is 1)
                // then we need to restart the request.
                if (generateStoredKeyStep == 3
                        || generateStoredKeyStep == 0) {
                    ccr.startRequest();
                }
            }
        }

        if (gskr.status() == Request::Finished && ccrWasFinished && dcrWasFinished) {
            generateStoredKeyStep++;
            if (generateStoredKeyStep == 4) {
                generateStoredKeyStep = 0;
            }
            if (generateStoredKeyStep == 3) {
                bool ensureSucceeded = true;
                if (!gskrMustSucceed) {
                    // the previous step was "2", which should have succeeded,
                    // but might have failed due to interleaving with the create
                    // collection request.  If it failed, decrement our step counter
                    // and restart the request; next time it must pass as there will
                    // be no possible conflicts.
                    if (gskr.result().errorMessage() == QStringLiteral("The identified collection is not stored by that plugin")
                            || gskr.result().errorMessage() == QStringLiteral("That collection is being modified and cannot currently be used")) {
                        ensureSucceeded = false;
                        gskrMustSucceed = true;
                        generateStoredKeyStep--;
                    }
                }

                if (ensureSucceeded) {
                    QCOMPARE(gskr.result().errorMessage(), QString());
                    QCOMPARE(gskr.result().code(), Result::Succeeded);
                    gskrMustSucceed = false;
                }

                if (generateStoredKeyStep != 3) {
                    // if the previous step was 2, and we succeeded,
                    // then the key will already exist at this point.
                    // restarting it now would result in a failure (duplicate key).
                    gskr.startRequest();
                }
            } else if (gskr.result().errorMessage() == QStringLiteral("The identified collection is not stored by that plugin")) {
                // Note that if this request was started (on the main thread)
                // while the delete collection request was ongoing (on the
                // secrets plugin thread), it might fail specifically at the
                // point where the secrets request processor attempts to
                // determine if the target collection is stored by the plugin,
                // since that check is performed via an asynchronous request.
                // This is OK, since no data will have been written to the
                // bookkeeping database (by setCollectionSecretMetadata())
                // at that point.
                gskr.startRequest();
            } else if (gskr.result().errorMessage() == QStringLiteral("That collection is being modified and cannot currently be used")) {
                // Note that if this request was started (on the main thread)
                // while the delete collection request was ongoing (on the
                // secrets plugin thread), it should fail with this error.
                // This is OK, since no data will have been written to the
                // bookkeeping database (by setCollectionSecretMetadata())
                // at that point, as we prevent that via the interleaving-lock.
                gskr.startRequest();
            } else {
                // other errors are potentially erroneous request interleaves.
                QCOMPARE(gskr.result().errorMessage(), QString());
            }
        }

        if (dcr.status() == Sailfish::Secrets::Request::Finished) {
            QCOMPARE(dcr.result().errorMessage(), QString());
            QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
            // if this step is 0 or 3, we need to restart the request.
            if (generateStoredKeyStep == 0
                    || generateStoredKeyStep == 3) {
                dcr.startRequest();
            }
        }

        if (ssr.status() == Sailfish::Secrets::Request::Finished) {
            QCOMPARE(ssr.result().errorMessage(), QString());
            QCOMPARE(ssr.result().code(), Sailfish::Secrets::Result::Succeeded);
            if (dsr.status() == Sailfish::Secrets::Request::Finished) {
                ssr.startRequest();
            }
        }

        if (dsr.status() == Sailfish::Secrets::Request::Finished) {
            QCOMPARE(dsr.result().errorMessage(), QString());
            QCOMPARE(dsr.result().code(), Sailfish::Secrets::Result::Succeeded);
            dsr.startRequest();
        }

        QTest::qWait(2); // allow asynchronous processing / DBus responses.
    }
}

static const auto test_key_rsa_1024_in = QByteArrayLiteral(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIICXQIBAAKBgQCiqCTjlgV2LMhFSnBOn/QDMUmxJXeMd9umc44nMnBYeI4C225t\n"
            "BQEqqUReAgxz+nuMJ8LUP4T2LQeYAFbOD99NEOLI4a1HCr+uxFWH3dfxr+BNZzsq\n"
            "iUQSSVeO1i4WQ9sBMLJrHGOCSLBfroKfdGFdncxvWBqk73AQSl2YzQ72owIDAQAB\n"
            "AoGAbNMAcz/hAZKunyVRhFkiAazNN/bwSAu86l1voyvs3FQz9xdmhwwNHsTG1/qY\n"
            "6FOSq0/C2wxwYd/4r6qyaQVXiP/TQS61Vy/LnAyGpQ17l4UWCTH2vNgzarnrDUxt\n"
            "nwZ46soZVsO1XfLZr+v/h5X9FqaZwsGGt/A5g1uGksN/snECQQDUzLf5y2htHatv\n"
            "RBIQyUnvejJEHQhpM3xQShqpIS91DFM/HmfM5ERUg9YO23eOXAmY6J6Chys3DN2a\n"
            "Fvu7Z2DpAkEAw617MhMfp9n1UbOA/5vh4aJUDPwCK+1T4Re77xlFTBz70rcXYgoP\n"
            "TxNREW5BpKkv9mJ8RJwOKf70JAMzYtqDqwJBANCqjh0cIKIe3eSVU0GyoBV8NZ4k\n"
            "+gJuwg/ZGpuONwMHuvnBzvdTPs3BGT4oZuvpxF90ezpzYSTyMLrQnrf9f0ECQC9y\n"
            "WkPrFSrrE6vq3aWdE6lVZhH77T7ffg4/Zgd01jO9d2ZBlP7lt46R/X8/f9VAXOve\n"
            "N4mfWWPfeS1eRVB78Z8CQQCM5gzW8QjXX/PyuF+CcQx2WkYr3I4btXnKJaU3g0ED\n"
            "tJSXNq/ZZfAXKa42id05ee2F1ek26dBlOPrXguXO7UlC\n"
            "-----END RSA PRIVATE KEY-----\n");
static const auto test_key_rsa_1024_sailfish_in = QByteArrayLiteral(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,1BFF649355F7612CC1E6A64DBC54D241\n"
            "\n"
            "/cG+zThmi43Grj2JLc0TqbYxt0sBG8deGfRxQkU09dPxk0PeB+z/Itgfo7ex276W\n"
            "GtoQNx+sbQ4gsKW637Fsmonk2oGniPycz4g2XLB0K6HSCn2XnV7UIwzzveFRsJI7\n"
            "0yBhNhyZDQmiL2Y+X+1Go9NHltgb0Vxq2zapSuYlgZGV6xIaxwLun58kJ46BYau1\n"
            "VCMP7QrrPbPp9/Jd70vg+bmO9juU8QI/iSvjQjKnCRV6HlbfEJ9jXuFvoJ3TcdjB\n"
            "LssLCRq5W31k9LEq9Lb5OZE0qq8Tdz0rPbimVR05V/Zsi/8B1XSyFD8Na70IHLj6\n"
            "gPvKJE/61kvDNc8Q7QGgEPGYEpjzrli9KjK/VIr/NxR2lvphUVi6g9LY+lwnKUHI\n"
            "DjI5FY62uL4EVu3RqCTWE+OYOLj5BRH9q7cYNEqOdFCwGuNtjmlgK19BLnk+7EXR\n"
            "E+Da3g4AeV9dVL+I15tGzeHfld+XOZuOWMGzDnDPNlqVxmXTkwGJ1ZIwtf8mNrgE\n"
            "20nrqT5ILlb+XU7/STXkN8FJUEkmbvbRsDAfikZU8VN4/BwLp4XiZichRtvwkGe4\n"
            "wBLstddVka3H5VqFUBa8qVMGxaKAgWkYNTONwbwSfb8rzBAl3akVSKhK1azumXzS\n"
            "4udmj21HXB/gUftjOhW4IuezCrESGqmR6QAHNxB0DM6DZW/oqNp3n0FC98IaRE1z\n"
            "7zjntkztt7PKQy+gI3pfq6U7IsXM+xqpR3xGwnOiHoqVMWRsuCGwyweA/wjwpCkd\n"
            "Y6r4YUlGATyVw+8KaSgRqBrOTo0+McUP3c2GFz2qntSM/+Eaai6dajTBlsAtLjwa\n"
            "-----END RSA PRIVATE KEY-----\n");
static const auto test_key_rsa_1024_pub = QByteArrayLiteral(
            "-----BEGIN PUBLIC KEY-----\n"
            "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiqCTjlgV2LMhFSnBOn/QDMUmx\n"
            "JXeMd9umc44nMnBYeI4C225tBQEqqUReAgxz+nuMJ8LUP4T2LQeYAFbOD99NEOLI\n"
            "4a1HCr+uxFWH3dfxr+BNZzsqiUQSSVeO1i4WQ9sBMLJrHGOCSLBfroKfdGFdncxv\n"
            "WBqk73AQSl2YzQ72owIDAQAB\n"
            "-----END PUBLIC KEY-----\n");
static const auto test_key_rsa_1024_out = QByteArrayLiteral(
            "-----BEGIN PRIVATE KEY-----\n"
            "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAKKoJOOWBXYsyEVK\n"
            "cE6f9AMxSbEld4x326ZzjicycFh4jgLbbm0FASqpRF4CDHP6e4wnwtQ/hPYtB5gA\n"
            "Vs4P300Q4sjhrUcKv67EVYfd1/Gv4E1nOyqJRBJJV47WLhZD2wEwsmscY4JIsF+u\n"
            "gp90YV2dzG9YGqTvcBBKXZjNDvajAgMBAAECgYBs0wBzP+EBkq6fJVGEWSIBrM03\n"
            "9vBIC7zqXW+jK+zcVDP3F2aHDA0exMbX+pjoU5KrT8LbDHBh3/ivqrJpBVeI/9NB\n"
            "LrVXL8ucDIalDXuXhRYJMfa82DNquesNTG2fBnjqyhlWw7Vd8tmv6/+Hlf0WppnC\n"
            "wYa38DmDW4aSw3+ycQJBANTMt/nLaG0dq29EEhDJSe96MkQdCGkzfFBKGqkhL3UM\n"
            "Uz8eZ8zkRFSD1g7bd45cCZjonoKHKzcM3ZoW+7tnYOkCQQDDrXsyEx+n2fVRs4D/\n"
            "m+HholQM/AIr7VPhF7vvGUVMHPvStxdiCg9PE1ERbkGkqS/2YnxEnA4p/vQkAzNi\n"
            "2oOrAkEA0KqOHRwgoh7d5JVTQbKgFXw1niT6Am7CD9kam443Awe6+cHO91M+zcEZ\n"
            "Pihm6+nEX3R7OnNhJPIwutCet/1/QQJAL3JaQ+sVKusTq+rdpZ0TqVVmEfvtPt9+\n"
            "Dj9mB3TWM713ZkGU/uW3jpH9fz9/1UBc6943iZ9ZY995LV5FUHvxnwJBAIzmDNbx\n"
            "CNdf8/K4X4JxDHZaRivcjhu1ecolpTeDQQO0lJc2r9ll8BcprjaJ3Tl57YXV6Tbp\n"
            "0GU4+teC5c7tSUI=\n"
            "-----END PRIVATE KEY-----\n");

static const auto test_key_rsa_2048_in = QByteArrayLiteral(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEAzydUP1CHBVQ+lbD4q0xxg92/NlQApCVMC3eQd9wCXh9ASkjw\n"
            "mSAEA/koY3G+3dJRE8/KCDbkA54UwMMr5kYDHk8AGe6I5MVAFmo7me2SJ7YnN182\n"
            "1hYHVq0ED++tYhyYz0EYw/HPc5Blp2SVZYPdrm85D58iixeyMXidDiIVCM+k/a9F\n"
            "U7Slab7jLIt9MRiN0Yma6G2bnrQjM+WKvjSKXOsfI9GfbxggKZHkyV7A3z013rdn\n"
            "pKdgxYSxFt7f96B0sygRuUko5CLTCJWoksDzpceTpD1ijmsxGPoPR69rCqAwJDL5\n"
            "K5hE1C8U80TUcxr5dMhac/5Rg8hSUQPurE7Y2QIDAQABAoIBAHernLvG5XlqpY0M\n"
            "Y1tyGdG39JKKDKTG9xtYwxi6/JMrMpS3dma/XBJ/iZmJSF4U9cmgLHJ6Y1bDp/GD\n"
            "zoSExaBouwJADs06Nj+8txnBaMGQNS+DzcX3i93CraoXJ+6Z3p08WfY4Z0O3k0IU\n"
            "lUnD1/jBQBGKOQZpdgOmTfSwM76WSqcmj7Vc0nomWMsZaXHGTj7QkbrTRUbbM2HT\n"
            "cMOXmaurZKzwn9yLuU9vohxc66rMg3ffsf73fouR2ZIF5orMSWZqTdfoe4ePnmKo\n"
            "1sTzeAF2K7kzM04QFs4VrVlJ2I2mqeXN/jW7SsqN3ozuWYdl86Tb9Hw4Hjyv9Uld\n"
            "R4kWgxECgYEA/s9wp7LBv2cDH/mWdzGimE2+tIuHCIYbT/Lg2v7aE+EBLD/ISZfF\n"
            "tci1+n+8/3nyy7r0e/irNGIKIHWh6GYoRSETUk6j/GtPYdjR07r5JnWwX1d74Dbe\n"
            "mA8qkRv2v1kz+pJNDtOabZi3mbijBza/cD6FcufoXOhrSsikAsTb6KMCgYEA0B7t\n"
            "gmuAFcFvtqOzgwqv3ddSX+qQ8Wvz4Ju3BFtphPx2DMyvpFnFwi272qCfIbZEqlHU\n"
            "AG0JXLNtVM19mwkiJd6ZW4RZ59p4r61Es2aS1kT0yt/z+bgOm2BwWGSiPHqoZFS+\n"
            "3AK6rfIxH+Y9QFYHWFiWM0ApJGuqJ3dfL2W+pFMCgYEApQQeRtxDEPtbULfIM8TX\n"
            "MZ8Xo8DAYErJIUt/RxPIkxsiMU/VG6PIjGNBRsq20RReooWekzKFXVUojcDga6rM\n"
            "5Yf4BVOca3nrXMiXinEJrViGMhhrxtaB7SPVQ0hC0cSpHtrkQHfVCKjgLhMesStJ\n"
            "ax1yOuno11JFOZcacBig+dUCgYBbm3Fx+b2MVfPFUbMfWCHnJPMWUxpvmdPkJsZd\n"
            "PZtptPKFWcdqMTWx7g2FAzRoU2FQEuqdMWFwk23paPYDuvZz8tJQDSbBvlFnCn51\n"
            "9Q1nET0q2375iUGstLtevRUIR/k9CGxmTTE8haGH6AFIA1YCViPu9Svm4xknfAzC\n"
            "wSc0DwKBgQDNSd4EHd/qKoR1XC3TBFmPnDR1dTq6sEYzNFdw1A2oX59PV8u6z6U+\n"
            "HlCnsHW3FUFdKm6NzQBsdcjmZVKb00ps86luvyF9tuteoUWlAEtrQVNaEOqe3jLm\n"
            "1PPLPcdXQ+zGOY55NxBlxHeer5uV8xh2++dgjt4iJFa2sSOeR8Ac7Q==\n"
            "-----END RSA PRIVATE KEY-----\n");
static const auto test_key_rsa_2048_sailfish_in = QByteArrayLiteral(
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,BA57C602A92FCAF7C707F6DB07726E02\n"
            "\n"
            "VJ3x3rpboyS3MMFlF8chau/jUvwLqhaxIVQ6aXFtLmjhz4Jq2v21o1Skle4xL41u\n"
            "cfzHtrIBw4iZBgDIEOgyRya31mG2xbxG797i1aA/EFRcekGni1wj8n+trXv6Awy9\n"
            "KVqjcSJdzYuGmfRiaWYSZV7qOiENVlin6/U+z+Oqd/yh6/4uNHNnzE3ENt7AZB7U\n"
            "I+L2zlMp6Kbg/ikNkFxHEoH2WKW9ja+4/FnqZi51d1/5Im9a2VcTJOGM3amGH42n\n"
            "4gyqjwI/fl2b/v+LyAAKoiW6KOAF9KVaghvQwFBMWWNNzylofGQQq9/DE8N62gpG\n"
            "c/paSfq7MW8v4lW0uaz3vjNz3fmHfB/nceVwNji26LMdHQprsngSg8jNlMorbHmW\n"
            "7NdqWLYp2gRk+6SxMcoW3c2gK1dLAgug+KqnQtYvRteQStF4qxlWhc71XvtytOJA\n"
            "BKgC/bZk0ETxTjE6vHhd0P+7LjeTdNzQcevP9lcC/uRMUXACJcBfi07J7qcTavS7\n"
            "+8YvDYH5EeTr1Zf5sxj0mzZnaw+Ys/sUwDwnOpRjDewOCeZvGw6oatr6v3IU3Dmw\n"
            "IiRGUS4pmz756O9/Ak4l1RQlbC0lz3qiUgsFb2M/PCcUbarqx07EY0R1NkXNiS3M\n"
            "rXxkf2wjmdrAkJ/yn/itLwOW4qBPHiAOQZGGpoEA/T9R0P6An4h8vlqmRwwR2V9s\n"
            "y8NkurCd8P4NGQeZWm1bZNuFNY0t1myBxmNfpubcGGKbyW3NXSrlH/7x17Fghn9u\n"
            "P5prIlfj1YaC8YPpKjEXj3t7HuZmcakOaXpFzjqo9bdX8Z9V0TOqLWWFUATrl82a\n"
            "6d+wvZyNTVnOPO2CQFiuu952h2uxnpb4wjMtMCKplXWTqBIDxnpuCFE/ZmP7qu3h\n"
            "lFiV06LyUmrAnFSXXDHOiNyMPMYYCX6q1kZn4DOCDdPxOd3ydFhfIfO3nPdvaIuL\n"
            "dhzPC/+pNkC+m6EsrvHSmv5SypI7wBWdssBW+kRTVccP8BR87K4peYh7WnYli+Ea\n"
            "a522UMFQObUBTpB+MN1uNNCHX/v8daOCtnGn64A4ww5248qXt8d37ZVJQKStaiks\n"
            "1mzz8LlJH/XbVD2jJnwtJSYTFcjNzs+26Uo52a6OpoDI5aGlHHRIQ4z7oyZ30+es\n"
            "I3DC/vwrIKYJFjAGAPqsMJz7dGGmwrwM/mekAbiEOsmHWpipNSKbBGV/XdcTMnln\n"
            "1u7oWBGRgWZeVBF06nV182g6Ej5PhPh7uhwd4PB615TxYXkp5hMKewqR04lBz1Sm\n"
            "YjyInhhJm1u/ERiOS+J4w59/RkJ7XGfj+b80Orw9sgcDPYbWOV3JwT3Pzk8/bI+A\n"
            "P+hmhF8FNR/YtJCqyn5WBHobGZORCZU1FRdw3GEBXOm28Z0bYGRXr1LQt0axt6If\n"
            "SeKnmY89yoXAtPbonKBIjS7hYvFBJpAuNmsrokPuir1NzWSHipQOVLX0VlrOCV3T\n"
            "qlQpZMViqfKicxR+1w8g+O9EuPmFrqhBkLFCfLUUBueYHAzjPC6jYNtexI8LgR5X\n"
            "Gsy65FMTeUh12TywtqbwWpU+ECrUpt3Gy6VK3nCdt1yQcr4/tR4xG3YZadcnV6Jf\n"
            "-----END RSA PRIVATE KEY-----\n");
static const auto test_key_rsa_2048_pub = QByteArrayLiteral(
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzydUP1CHBVQ+lbD4q0xx\n"
            "g92/NlQApCVMC3eQd9wCXh9ASkjwmSAEA/koY3G+3dJRE8/KCDbkA54UwMMr5kYD\n"
            "Hk8AGe6I5MVAFmo7me2SJ7YnN1821hYHVq0ED++tYhyYz0EYw/HPc5Blp2SVZYPd\n"
            "rm85D58iixeyMXidDiIVCM+k/a9FU7Slab7jLIt9MRiN0Yma6G2bnrQjM+WKvjSK\n"
            "XOsfI9GfbxggKZHkyV7A3z013rdnpKdgxYSxFt7f96B0sygRuUko5CLTCJWoksDz\n"
            "pceTpD1ijmsxGPoPR69rCqAwJDL5K5hE1C8U80TUcxr5dMhac/5Rg8hSUQPurE7Y\n"
            "2QIDAQAB\n"
            "-----END PUBLIC KEY-----\n");
static const auto test_key_rsa_2048_out = QByteArrayLiteral(
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPJ1Q/UIcFVD6V\n"
            "sPirTHGD3b82VACkJUwLd5B33AJeH0BKSPCZIAQD+Shjcb7d0lETz8oINuQDnhTA\n"
            "wyvmRgMeTwAZ7ojkxUAWajuZ7ZIntic3XzbWFgdWrQQP761iHJjPQRjD8c9zkGWn\n"
            "ZJVlg92ubzkPnyKLF7IxeJ0OIhUIz6T9r0VTtKVpvuMsi30xGI3RiZrobZuetCMz\n"
            "5Yq+NIpc6x8j0Z9vGCApkeTJXsDfPTXet2ekp2DFhLEW3t/3oHSzKBG5SSjkItMI\n"
            "laiSwPOlx5OkPWKOazEY+g9Hr2sKoDAkMvkrmETULxTzRNRzGvl0yFpz/lGDyFJR\n"
            "A+6sTtjZAgMBAAECggEAd6ucu8bleWqljQxjW3IZ0bf0kooMpMb3G1jDGLr8kysy\n"
            "lLd2Zr9cEn+JmYlIXhT1yaAscnpjVsOn8YPOhITFoGi7AkAOzTo2P7y3GcFowZA1\n"
            "L4PNxfeL3cKtqhcn7pnenTxZ9jhnQ7eTQhSVScPX+MFAEYo5Bml2A6ZN9LAzvpZK\n"
            "pyaPtVzSeiZYyxlpccZOPtCRutNFRtszYdNww5eZq6tkrPCf3Iu5T2+iHFzrqsyD\n"
            "d9+x/vd+i5HZkgXmisxJZmpN1+h7h4+eYqjWxPN4AXYruTMzThAWzhWtWUnYjaap\n"
            "5c3+NbtKyo3ejO5Zh2XzpNv0fDgePK/1SV1HiRaDEQKBgQD+z3CnssG/ZwMf+ZZ3\n"
            "MaKYTb60i4cIhhtP8uDa/toT4QEsP8hJl8W1yLX6f7z/efLLuvR7+Ks0YgogdaHo\n"
            "ZihFIRNSTqP8a09h2NHTuvkmdbBfV3vgNt6YDyqRG/a/WTP6kk0O05ptmLeZuKMH\n"
            "Nr9wPoVy5+hc6GtKyKQCxNvoowKBgQDQHu2Ca4AVwW+2o7ODCq/d11Jf6pDxa/Pg\n"
            "m7cEW2mE/HYMzK+kWcXCLbvaoJ8htkSqUdQAbQlcs21UzX2bCSIl3plbhFnn2niv\n"
            "rUSzZpLWRPTK3/P5uA6bYHBYZKI8eqhkVL7cArqt8jEf5j1AVgdYWJYzQCkka6on\n"
            "d18vZb6kUwKBgQClBB5G3EMQ+1tQt8gzxNcxnxejwMBgSskhS39HE8iTGyIxT9Ub\n"
            "o8iMY0FGyrbRFF6ihZ6TMoVdVSiNwOBrqszlh/gFU5xreetcyJeKcQmtWIYyGGvG\n"
            "1oHtI9VDSELRxKke2uRAd9UIqOAuEx6xK0lrHXI66ejXUkU5lxpwGKD51QKBgFub\n"
            "cXH5vYxV88VRsx9YIeck8xZTGm+Z0+Qmxl09m2m08oVZx2oxNbHuDYUDNGhTYVAS\n"
            "6p0xYXCTbelo9gO69nPy0lANJsG+UWcKfnX1DWcRPSrbfvmJQay0u169FQhH+T0I\n"
            "bGZNMTyFoYfoAUgDVgJWI+71K+bjGSd8DMLBJzQPAoGBAM1J3gQd3+oqhHVcLdME\n"
            "WY+cNHV1OrqwRjM0V3DUDahfn09Xy7rPpT4eUKewdbcVQV0qbo3NAGx1yOZlUpvT\n"
            "SmzzqW6/IX22616hRaUAS2tBU1oQ6p7eMubU88s9x1dD7MY5jnk3EGXEd56vm5Xz\n"
            "GHb752CO3iIkVraxI55HwBzt\n"
            "-----END PRIVATE KEY-----\n");

static const auto test_key_dsa_1024_in = QByteArrayLiteral(
            "-----BEGIN DSA PRIVATE KEY-----\n"
            "MIIBuwIBAAKBgQCp5QVAxr8z+n6eVSmYCE7KB624x0rBRJltGyGaJwrhw4tZnS9O\n"
            "QpifSJ7OJ2gQR5exWTRVVDzEiSxpfjOo879A9+T7rcEYGTwMap1JVmwZwKfnChKu\n"
            "/609f6E1UE/4H8W7n98oeJZwd0TOzqJRAceeKtFuD/+0ruVgPZPiK0jEYwIVAKu1\n"
            "si92K0PnJBOk7kNCv4oyanFPAoGAWvMUZDOSZuTQwvYX9x0Fp+ZOfND9gpEHI6PH\n"
            "N0vKHrxcr7cT4cbffWmrLLxWVfZottCX1MeJzC9z2AfvZf5s2uha8cWh0Sgw/ipf\n"
            "huIXstnT9/I9VaN4Vm5O8gu9MmHWyEZxAW2wx3+5ncgdOWzP+dBsE4QN85+RwKY1\n"
            "9kX/eu0CgYAKKPbq+hfqs9g19SGfIw4O2n0eWAJan4SPD7CnjYw8rYEYS3+wjdUL\n"
            "/ImsZJRYTq5pMgnaNCi3Dz0gGGPAoVjzyS7xhbA70FjUGH8dO2EUu4Y3ArdDDn5L\n"
            "09C5XnS203lHkZTmM6uKIg5Y48rK3Q3bIn3cKRMOE61Cnp9CTDJ+LAIVAInCx5tA\n"
            "O6Ux513Bm8bg+QwLlWKN\n"
            "-----END DSA PRIVATE KEY-----\n");
static const auto test_key_dsa_1024_sailfish_in = QByteArrayLiteral(
            "-----BEGIN DSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,E07E817AAA64D534D917B5DCACB9E5CF\n"
            "\n"
            "p4Q416kw07T7jnT2IQ7HMbpag3MmfAB6ZwPrVCG+r9NennCGs5d37Snh1+6sCL2C\n"
            "jjPFpfS6f7QRUrttyPsjrL2PATEIijtFrEBGk5Tty237NOZ0+ZbBuwrT+BA68VzQ\n"
            "3dUgNhVPh4t+/Si5VeIRAsWf4QUljMUVDwzhafAVgwYL5jWAJFvu3JeSjW3jKB3V\n"
            "QwLT3TPzjXtiCAdAbqND5JHzTf33bMASCBWqC3g4Jup/LSx8SOK5IcSRMh4fNf4K\n"
            "H3wBD2lC9/2pPs70aPpM6up06KSFg6028btXUeEyLxZsiKpwx9oqMzOwxPmwXZTs\n"
            "sFAYKeOkmvWdimGroOhJtzxPhdiMxcGwAnmsmxgXuNz8mwlhREg+KGYmTDrL3qAM\n"
            "HrjXzm/HARzDaIRz2Lyz6NWhgPmDrrH1+ZsAsv0ND3R/BQ7ETJNKjLDxFaR5y3JQ\n"
            "VJBSFam/PEfdoqUd/JK5k2D2o6AS1tYOziH7IJejE+UFt4v5cZx7MMcD2xYIwn7/\n"
            "VF8bRZXA96a/pJ6kmFEpSN0qqfLu86JOCHqqQTNAkIfe0oZSIVy0MvoKi90q6CdN\n"
            "FbWAZ6eVb3eYly755IeiKA==\n"
            "-----END DSA PRIVATE KEY-----\n");
static const auto test_key_dsa_1024_pub = QByteArrayLiteral(
            "-----BEGIN PUBLIC KEY-----\n"
            "MIIBtjCCASsGByqGSM44BAEwggEeAoGBAKnlBUDGvzP6fp5VKZgITsoHrbjHSsFE\n"
            "mW0bIZonCuHDi1mdL05CmJ9Ins4naBBHl7FZNFVUPMSJLGl+M6jzv0D35PutwRgZ\n"
            "PAxqnUlWbBnAp+cKEq7/rT1/oTVQT/gfxbuf3yh4lnB3RM7OolEBx54q0W4P/7Su\n"
            "5WA9k+IrSMRjAhUAq7WyL3YrQ+ckE6TuQ0K/ijJqcU8CgYBa8xRkM5Jm5NDC9hf3\n"
            "HQWn5k580P2CkQcjo8c3S8oevFyvtxPhxt99aassvFZV9mi20JfUx4nML3PYB+9l\n"
            "/mza6FrxxaHRKDD+Kl+G4hey2dP38j1Vo3hWbk7yC70yYdbIRnEBbbDHf7mdyB05\n"
            "bM/50GwThA3zn5HApjX2Rf967QOBhAACgYAKKPbq+hfqs9g19SGfIw4O2n0eWAJa\n"
            "n4SPD7CnjYw8rYEYS3+wjdUL/ImsZJRYTq5pMgnaNCi3Dz0gGGPAoVjzyS7xhbA7\n"
            "0FjUGH8dO2EUu4Y3ArdDDn5L09C5XnS203lHkZTmM6uKIg5Y48rK3Q3bIn3cKRMO\n"
            "E61Cnp9CTDJ+LA==\n"
            "-----END PUBLIC KEY-----\n");
static const auto test_key_dsa_1024_out = QByteArrayLiteral(
            "-----BEGIN PRIVATE KEY-----\n"
            "MIIBSwIBADCCASsGByqGSM44BAEwggEeAoGBAKnlBUDGvzP6fp5VKZgITsoHrbjH\n"
            "SsFEmW0bIZonCuHDi1mdL05CmJ9Ins4naBBHl7FZNFVUPMSJLGl+M6jzv0D35Put\n"
            "wRgZPAxqnUlWbBnAp+cKEq7/rT1/oTVQT/gfxbuf3yh4lnB3RM7OolEBx54q0W4P\n"
            "/7Su5WA9k+IrSMRjAhUAq7WyL3YrQ+ckE6TuQ0K/ijJqcU8CgYBa8xRkM5Jm5NDC\n"
            "9hf3HQWn5k580P2CkQcjo8c3S8oevFyvtxPhxt99aassvFZV9mi20JfUx4nML3PY\n"
            "B+9l/mza6FrxxaHRKDD+Kl+G4hey2dP38j1Vo3hWbk7yC70yYdbIRnEBbbDHf7md\n"
            "yB05bM/50GwThA3zn5HApjX2Rf967QQXAhUAicLHm0A7pTHnXcGbxuD5DAuVYo0=\n"
            "-----END PRIVATE KEY-----\n");

static Key createPublicKey(
        const Key::Identifier &identifier, const QByteArray &data, Key::Component constraints = Key::PublicKeyData)
{
    Key key;
    key.setIdentifier(identifier);
    key.setPublicKey(data);
    key.setComponentConstraints(constraints);

    return key;
}

static Key createPrivateKey(
        const Key::Identifier &identifier, const QByteArray &data, Key::Component constraints = Key::PrivateKeyData)
{
    Key key;
    key.setIdentifier(identifier);
    key.setPrivateKey(data);
    key.setComponentConstraints(constraints);

    return key;
}

static Key createSecretKey(
        const Key::Identifier &identifier, const QByteArray &data, Key::Component constraints = Key::SecretKeyData)
{
    Key key;
    key.setIdentifier(identifier);
    key.setSecretKey(data);
    key.setComponentConstraints(constraints);

    return key;
}

void tst_cryptorequests::importKey_data()
{
    QTest::addColumn<Sailfish::Crypto::Key>("key");
    QTest::addColumn<Sailfish::Crypto::InteractionParameters>("interactionParameters");
    QTest::addColumn<Sailfish::Crypto::Result::ResultCode>("resultCode");
    QTest::addColumn<Sailfish::Crypto::Result::ErrorCode>("errorCode");
    QTest::addColumn<QByteArray>("privateKey");
    QTest::addColumn<QByteArray>("publicKey");
    QTest::addColumn<int>("size");
    QTest::addColumn<Sailfish::Crypto::Key::Origin>("origin");
    QTest::addColumn<Sailfish::Crypto::CryptoManager::Algorithm>("algorithm");

    InteractionParameters promptForSailfishPassphrase;
    promptForSailfishPassphrase.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    promptForSailfishPassphrase.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
    promptForSailfishPassphrase.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);
    promptForSailfishPassphrase.setPromptText(QLatin1String("Enter the passphrase 'Sailfish'"));

    InteractionParameters promptToCancel;
    promptToCancel.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    promptToCancel.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
    promptToCancel.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);
    promptToCancel.setPromptText(QLatin1String("Cancel input"));

    Sailfish::Crypto::InteractionParameters noUserInteraction;

    Key::Identifier keyIdentifier(QStringLiteral("storedkey"), QStringLiteral("tstcryptorequestsimportKey"));

    QTest::newRow("Private RSA 2048 - no passphrase")
            << createPrivateKey(keyIdentifier, test_key_rsa_2048_in)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << test_key_rsa_2048_out
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;
    QTest::newRow("Private RSA 2048 - passphrase")
            << createPrivateKey(keyIdentifier, test_key_rsa_2048_sailfish_in)
            << promptForSailfishPassphrase
            << Result::Succeeded
            << Result::NoError
            << test_key_rsa_2048_out
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;
    QTest::newRow("Public RSA 2048")
            << createPublicKey(keyIdentifier, test_key_rsa_2048_pub)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << QByteArray()
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;

    QTest::newRow("Private RSA 1024 - no passphrase")
            << createPrivateKey(keyIdentifier, test_key_rsa_1024_in)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << test_key_rsa_1024_out
            << test_key_rsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;
    QTest::newRow("Private RSA 1024 - passphrase")
            << createPrivateKey(keyIdentifier, test_key_rsa_1024_sailfish_in)
            << promptForSailfishPassphrase
            << Result::Succeeded
            << Result::NoError
            << test_key_rsa_1024_out
            << test_key_rsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;
    QTest::newRow("Public RSA 1024")
            << createPublicKey(keyIdentifier, test_key_rsa_1024_pub)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << QByteArray()
            << test_key_rsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;

    QTest::newRow("Private DSA 1024 - no passphrase")
            << createPrivateKey(keyIdentifier, test_key_dsa_1024_in)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << test_key_dsa_1024_out
            << test_key_dsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmDsa;
    QTest::newRow("Private DSA 1024 - passphrase")
            << createPrivateKey(keyIdentifier, test_key_dsa_1024_sailfish_in)
            << promptForSailfishPassphrase
            << Result::Succeeded
            << Result::NoError
            << test_key_dsa_1024_out
            << test_key_dsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmDsa;
    QTest::newRow("Public DSA 1024")
            << createPublicKey(keyIdentifier, test_key_dsa_1024_pub)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << QByteArray()
            << test_key_dsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmDsa;

    QTest::newRow("Private RSA 2048 - secret")
            << createSecretKey(keyIdentifier, test_key_rsa_2048_in)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << test_key_rsa_2048_out
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;

    QTest::newRow("Private RSA 2048 - passphrase, no user interaction")
            << createPrivateKey(keyIdentifier, test_key_rsa_2048_sailfish_in)
            << noUserInteraction
            << Result::Failed
            << Result::CryptoPluginIncorrectPassphrase
            << QByteArray()
            << QByteArray()
            << 0
            << Key::OriginUnknown
            << CryptoManager::AlgorithmUnknown;
    QTest::newRow("Private RSA 2048 - passphrase, canceled")
            << createPrivateKey(keyIdentifier, test_key_rsa_2048_sailfish_in)
            << promptToCancel
            << Result::Failed
            << Result::CryptoPluginKeyImportError
            << QByteArray()
            << QByteArray()
            << 0
            << Key::OriginUnknown
            << CryptoManager::AlgorithmUnknown;
    QTest::newRow("Private RSA 2048 - public constraint")
            << createPrivateKey(keyIdentifier, test_key_rsa_2048_in, Key::PublicKeyData)
            << noUserInteraction
            << Result::Succeeded
            << Result::NoError
            << QByteArray()
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa;
}

void tst_cryptorequests::importKey()
{
    QFETCH(Sailfish::Crypto::Key, key);
    QFETCH(Sailfish::Crypto::InteractionParameters, interactionParameters);
    QFETCH(Sailfish::Crypto::Result::ResultCode, resultCode);
    QFETCH(Sailfish::Crypto::Result::ErrorCode, errorCode);
    QFETCH(QByteArray, privateKey);
    QFETCH(QByteArray, publicKey);
    QFETCH(int, size);
    QFETCH(Sailfish::Crypto::Key::Origin, origin);
    QFETCH(Sailfish::Crypto::CryptoManager::Algorithm, algorithm);

    Sailfish::Crypto::ImportKeyRequest request;
    request.setManager(&cm);

    request.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(request.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);

    request.setKey(key);
    QCOMPARE(request.key(), key);

    if (interactionParameters.isValid()) {
        QSKIP("Invalid interaction service address for in-app authentication");
    }

    request.startRequest();

    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request);

    const Sailfish::Crypto::Result result = request.result();
    const Sailfish::Crypto::Key importedKey = request.importedKey();

    QCOMPARE(result.code(), resultCode);
    QCOMPARE(result.errorCode(), errorCode);

    QCOMPARE(importedKey.publicKey(), publicKey);
    QCOMPARE(importedKey.privateKey(), privateKey);
    QCOMPARE(importedKey.size(), size);
    QCOMPARE(importedKey.origin(), origin);
    QCOMPARE(importedKey.algorithm(), algorithm);
}

void tst_cryptorequests::importKeyAndStore_data()
{
    importKey_data();

    QTest::newRow("Private RSA 2048 - no identifier")
            << createPrivateKey(Key::Identifier(), test_key_rsa_2048_in)
            << InteractionParameters()
            << Result::Failed
            << Result::InvalidKeyIdentifier
            << QByteArray()
            << QByteArray()
            << 0
            << Key::OriginUnknown
            << CryptoManager::AlgorithmUnknown;
}

void tst_cryptorequests::importKeyAndStore()
{
    QFETCH(Sailfish::Crypto::Key, key);
    QFETCH(Sailfish::Crypto::InteractionParameters, interactionParameters);
    QFETCH(Sailfish::Crypto::Result::ResultCode, resultCode);
    QFETCH(Sailfish::Crypto::Result::ErrorCode, errorCode);
    QFETCH(QByteArray, privateKey);
    QFETCH(QByteArray, publicKey);
    QFETCH(int, size);
    QFETCH(Sailfish::Crypto::Key::Origin, origin);
    QFETCH(Sailfish::Crypto::CryptoManager::Algorithm, algorithm);

    if (interactionParameters.isValid()) {
        QSKIP("Invalid interaction service address for in-app authentication");
    }

    if (!key.collectionName().isEmpty()) {
        populatedCollections.append(key.collectionName());

        // first, create the collection via the Secrets API.
        Sailfish::Secrets::CreateCollectionRequest ccr;
        ccr.setManager(&sm);
        ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
        ccr.setCollectionName(key.collectionName());
        ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
        ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
        ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
        ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
        ccr.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
        QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);

        if (ccr.result().code() == Sailfish::Secrets::Result::Failed) {
            qDebug() << ccr.result().errorMessage();
        }

        QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);
    }

    Sailfish::Crypto::ImportStoredKeyRequest request;
    request.setManager(&cm);

    request.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(request.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);

    request.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(request.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);

    request.setKey(key);
    QCOMPARE(request.key(), key);

    request.startRequest();

    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request);

    const Sailfish::Crypto::Result result = request.result();

    QCOMPARE(result.code(), resultCode);
    QCOMPARE(result.errorCode(), errorCode);

    const Sailfish::Crypto::Key importedKey = request.importedKeyReference();

    QCOMPARE(importedKey.publicKey(), publicKey);
    QCOMPARE(importedKey.privateKey(), QByteArray());
    QCOMPARE(importedKey.size(), size);
    QCOMPARE(importedKey.origin(), origin);
    QCOMPARE(importedKey.algorithm(), algorithm);
}

#include "tst_cryptorequests.moc"
QTEST_MAIN(tst_cryptorequests)
