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

#include "Crypto/calculatedigestrequest.h"
#include "Crypto/cipherrequest.h"
#include "Crypto/decryptrequest.h"
#include "Crypto/deletestoredkeyrequest.h"
#include "Crypto/encryptrequest.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/generatestoredkeyrequest.h"
#include "Crypto/plugininforequest.h"
#include "Crypto/seedrandomdatageneratorrequest.h"
#include "Crypto/signrequest.h"
#include "Crypto/storedkeyidentifiersrequest.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/validatecertificatechainrequest.h"
#include "Crypto/verifyrequest.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/key.h"
#include "Crypto/result.h"
#include "Crypto/x509certificate.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/interactionparameters.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/createcollectionrequest.h"
#include "Secrets/deletecollectionrequest.h"
#include "Secrets/findsecretsrequest.h"
#include "Secrets/storedsecretrequest.h"

using namespace Sailfish::Crypto;

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                         \
    do {                                                                    \
        int maxWait = 10000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(100);                                              \
            maxWait -= 100;                                                 \
        }                                                                   \
    } while (0)
#define SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                   \
    do {                                                                    \
        int maxWait = 10000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(1);                                                \
            maxWait -= 1;                                                   \
        }                                                                   \
    } while (0)
#define LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                    \
    do {                                                                    \
        int maxWait = 30000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(100);                                              \
            maxWait -= 100;                                                 \
        }                                                                   \
    } while (0)

#define DEFAULT_TEST_CRYPTO_PLUGIN_NAME CryptoManager::DefaultCryptoPluginName + QLatin1String(".test")
#define DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")
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
    void generateKeyEncryptDecrypt_data();
    void generateKeyEncryptDecrypt();
    void validateCertificateChain();
    void signVerify();
    void calculateDigest();
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

private:
    void addCryptoTestData()
    {
        QTest::addColumn<CryptoManager::BlockMode>("blockMode");
        QTest::addColumn<int>("keySize");

        QTest::newRow("ECB 128-bit") << CryptoManager::BlockModeEcb << 128;
        QTest::newRow("ECB 192-bit") << CryptoManager::BlockModeEcb << 192;
        QTest::newRow("ECB 256-bit") << CryptoManager::BlockModeEcb << 256;

        QTest::newRow("CBC 128-bit") << CryptoManager::BlockModeCbc << 128;
        QTest::newRow("CBC 192-bit") << CryptoManager::BlockModeCbc << 192;
        QTest::newRow("CBC 256-bit") << CryptoManager::BlockModeCbc << 256;

        QTest::newRow("CFB-1 128-bit") << CryptoManager::BlockModeCfb1 << 128;
        QTest::newRow("CFB-1 192-bit") << CryptoManager::BlockModeCfb1 << 192;
        QTest::newRow("CFB-1 256-bit") << CryptoManager::BlockModeCfb1 << 256;

        QTest::newRow("CFB-8 128-bit") << CryptoManager::BlockModeCfb8 << 128;
        QTest::newRow("CFB-8 192-bit") << CryptoManager::BlockModeCfb8 << 192;
        QTest::newRow("CFB-8 256-bit") << CryptoManager::BlockModeCfb8 << 256;

        QTest::newRow("CFB-128 128-bit") << CryptoManager::BlockModeCfb128 << 128;
        QTest::newRow("CFB-128 192-bit") << CryptoManager::BlockModeCfb128 << 192;
        QTest::newRow("CFB-128 256-bit") << CryptoManager::BlockModeCfb128 << 256;

        QTest::newRow("OFB 128-bit") << CryptoManager::BlockModeOfb << 128;
        QTest::newRow("OFB 192-bit") << CryptoManager::BlockModeOfb << 192;
        QTest::newRow("OFB 256-bit") << CryptoManager::BlockModeOfb << 256;
    }

    CryptoManager cm;
    Sailfish::Secrets::SecretManager sm;
};

void tst_cryptorequests::init()
{
}

void tst_cryptorequests::cleanup()
{
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

void tst_cryptorequests::generateKeyEncryptDecrypt_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::generateKeyEncryptDecrypt()
{
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

    // test generating a symmetric cipher key
    Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    QSignalSpy gkrss(&gkr, &GenerateKeyRequest::statusChanged);
    QSignalSpy gkrks(&gkr, &GenerateKeyRequest::generatedKeyChanged);
    gkr.setKeyTemplate(keyTemplate);
    QCOMPARE(gkr.keyTemplate(), keyTemplate);
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
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the generated key
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = "0123456789abcdef";
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
    er.setPadding(CryptoManager::EncryptionPaddingNone);
    QCOMPARE(er.padding(), CryptoManager::EncryptionPaddingNone);
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
    dr.setPadding(CryptoManager::EncryptionPaddingNone);
    QCOMPARE(dr.padding(), CryptoManager::EncryptionPaddingNone);
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
}

void tst_cryptorequests::validateCertificateChain()
{
    // TODO: do this test properly, this currently just tests datatype copy semantics
    QVector<Certificate> chain;
    X509Certificate cert;
    cert.setSignatureValue(QByteArray("testing"));
    chain << cert;

    ValidateCertificateChainRequest vcr;
    vcr.setManager(&cm);
    QSignalSpy vcrss(&vcr, &ValidateCertificateChainRequest::statusChanged);
    QSignalSpy vcrvs(&vcr, &ValidateCertificateChainRequest::validatedChanged);
    vcr.setCertificateChain(chain);
    QCOMPARE(vcr.certificateChain(), chain);
    vcr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(vcr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(vcr.status(), Request::Inactive);
    vcr.startRequest();
    QCOMPARE(vcrss.count(), 1);
    QCOMPARE(vcr.status(), Request::Active);
    QCOMPARE(vcr.result().code(), Result::Pending);
    QCOMPARE(vcrvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(vcr);
    QCOMPARE(vcrss.count(), 2);
    QCOMPARE(vcr.status(), Request::Finished);
    QSKIP("TODO - certificate validation not yet implemented!");
}

void tst_cryptorequests::signVerify()
{
    // Generate RSA key for signing
    // ----------------------------

    // Create key template
    Key keyTemplate;
    keyTemplate.setSize(1024);
    keyTemplate.setAlgorithm(CryptoManager::AlgorithmRsa);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationSign);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // Create key pair generation params, make sure it's valid
    RsaKeyPairGenerationParameters keyPairGenParams;
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
    sr.setDigestFunction(CryptoManager::DigestSha256);
    QCOMPARE(sr.digestFunction(), CryptoManager::DigestSha256);
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
    vr.setDigestFunction(CryptoManager::DigestSha256);
    QCOMPARE(vr.digestFunction(), CryptoManager::DigestSha256);
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

void tst_cryptorequests::calculateDigest()
{
    QByteArray plaintext = "Test plaintext data";

    CalculateDigestRequest cdr;
    cdr.setManager(&cm);
    QSignalSpy cdrss(&cdr, &CalculateDigestRequest::statusChanged);
    QSignalSpy cdrds(&cdr, &CalculateDigestRequest::digestChanged);
    QCOMPARE(cdr.status(), Request::Inactive);
    cdr.setData(plaintext);
    QCOMPARE(cdr.data(), plaintext);
    cdr.setDigestFunction(CryptoManager::DigestSha256);
    QCOMPARE(cdr.digestFunction(), CryptoManager::DigestSha256);
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
}

void tst_cryptorequests::storedKeyRequests_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::storedKeyRequests()
{
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

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

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = "0123456789abcdef";
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
    er.setPadding(CryptoManager::EncryptionPaddingNone);
    QCOMPARE(er.padding(), CryptoManager::EncryptionPaddingNone);
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
    dr.setPadding(CryptoManager::EncryptionPaddingNone);
    QCOMPARE(dr.padding(), CryptoManager::EncryptionPaddingNone);
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

void tst_cryptorequests::storedDerivedKeyRequests_data()
{
    addCryptoTestData();
}

void tst_cryptorequests::storedDerivedKeyRequests()
{
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

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
    QByteArray initVector = "0123456789abcdef";
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
    er.setPadding(CryptoManager::EncryptionPaddingNone);
    QCOMPARE(er.padding(), CryptoManager::EncryptionPaddingNone);
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
    dr.setPadding(CryptoManager::EncryptionPaddingNone);
    QCOMPARE(dr.padding(), CryptoManager::EncryptionPaddingNone);
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
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(gskr.result().code(), Result::Succeeded);
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
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

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
    QByteArray iv;
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
    QSignalSpy erivs(&er, &CipherRequest::generatedInitialisationVectorChanged);
    er.setKey(minimalKeyReference);
    QCOMPARE(er.key(), minimalKeyReference);
    er.setOperation(Sailfish::Crypto::CryptoManager::OperationEncrypt);
    QCOMPARE(er.operation(), Sailfish::Crypto::CryptoManager::OperationEncrypt);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    QCOMPARE(er.encryptionPadding(), Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
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
    QCOMPARE(erivs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ergds.count(), 0);
    QCOMPARE(erivs.count(), 1);
    iv = er.generatedInitialisationVector();
    QCOMPARE(iv.size(), 16);

    int gdsCount = 0, ssCount = 2, chunkStartPos = 0;
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
    QCOMPARE(erss.count(), ssCount + 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    ciphertext.append(er.generatedData()); // may or may not be empty.
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
    dr.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    QCOMPARE(dr.encryptionPadding(), Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
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
        if (chunkStartPos >= 32) {
            // in CBC mode the first block will not be returned,
            // due to the cipher requiring it for the next update.
            QCOMPARE(drgds.count(), gdsCount + 1);
            QVERIFY(plaintextChunk.size() >= chunk.size());
            QVERIFY(!decrypted.isEmpty());
        }
    }

    dr.setCipherMode(CipherRequest::FinaliseCipher);
    QCOMPARE(dr.cipherMode(), CipherRequest::FinaliseCipher);
    dr.setData(QByteArray());
    ssCount = drss.count();
    dr.startRequest();
    QCOMPARE(drss.count(), ssCount + 1);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), ssCount + 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(dr.result().code(), Result::Succeeded);
    decrypted.append(dr.generatedData()); // may or may not be empty.
    QCOMPARE(plaintext, decrypted); // successful round trip!

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
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

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

    QByteArray iv;
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
        er.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
        er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        er.setCipherMode(CipherRequest::InitialiseCipher);
        er.startRequest();
        SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
        iv = er.generatedInitialisationVector();

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
        dr.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
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
        er.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
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
        dr.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
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
    QByteArray iv;
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
    QSignalSpy erivs(&er, &CipherRequest::generatedInitialisationVectorChanged);
    er.setKey(minimalKeyReference);
    QCOMPARE(er.key(), minimalKeyReference);
    er.setOperation(Sailfish::Crypto::CryptoManager::OperationEncrypt);
    QCOMPARE(er.operation(), Sailfish::Crypto::CryptoManager::OperationEncrypt);
    er.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
    QCOMPARE(er.blockMode(), Sailfish::Crypto::CryptoManager::BlockModeCbc);
    er.setEncryptionPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    QCOMPARE(er.encryptionPadding(), Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
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
    QCOMPARE(erivs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ergds.count(), 0);
    QCOMPARE(erivs.count(), 1);
    iv = er.generatedInitialisationVector();
    QCOMPARE(iv.size(), 16);

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

#include "tst_cryptorequests.moc"
QTEST_MAIN(tst_cryptorequests)
