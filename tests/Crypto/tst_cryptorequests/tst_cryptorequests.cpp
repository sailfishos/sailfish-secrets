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
#include "Secrets/collectionnamesrequest.h"
#include "Secrets/deletecollectionrequest.h"
#include "Secrets/findsecretsrequest.h"
#include "Secrets/storesecretrequest.h"
#include "Secrets/deletesecretrequest.h"
#include "Secrets/storedsecretrequest.h"

#include "../cryptotest.h"

// Needed for the calculateDigest tests
Q_DECLARE_METATYPE(QCryptographicHash::Algorithm);

using namespace Sailfish::Crypto;

namespace {

inline KeyPairGenerationParameters getKeyPairGenerationParameters(CryptoManager::Algorithm algorithm, int keySize)
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

}

class tst_cryptorequests : public CryptoTest
{
    Q_OBJECT

private:
    Sailfish::Secrets::CreateCollectionRequest *newCreateCollectionRequest(
            const QString &collectionName,
            const TestPluginMap &plugins,
            bool autoDeleteCollection,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode);
    Sailfish::Secrets::CreateCollectionRequest *newCreateCollectionRequestWithDeviceLock(
            const QString &collectionName,
            const TestPluginMap &plugins,
            bool autoDeleteCollection = true,
            Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic deviceLockSemantic = Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode = Sailfish::Secrets::SecretManager::OwnerOnlyMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = Sailfish::Secrets::SecretManager::ApplicationInteraction);
    Sailfish::Secrets::CreateCollectionRequest *newCreateCollectionRequestWithCustomLock(
            const QString &collectionName,
            const TestPluginMap &plugins,
            bool autoDeleteCollection = true,
            Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic customLockSemantic = Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode = Sailfish::Secrets::SecretManager::OwnerOnlyMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode = Sailfish::Secrets::SecretManager::ApplicationInteraction);

    Key::Identifier createTestKeyIdentifier(const TestPluginMap &plugins,
                                            const QString &collectionName = QStringLiteral("tstcryptosecretsgcsked"))
    {
        Q_ASSERT(plugins.contains(CryptoTest::StoragePlugin));
        return Key::Identifier(QStringLiteral("storedkey"), collectionName, plugins.value(CryptoTest::StoragePlugin));
    }

private slots:
    void init() { qtest_init(); }
    void cleanup() { qtest_cleanup(); }

    void getPluginInfo_data();
    void getPluginInfo();
    void randomData_data();
    void randomData();
    void randomData_dev_urandom();
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
    void storedKeyIdentifiersRequests_data();
    void storedKeyIdentifiersRequests();
    void storedDerivedKeyRequests_data();
    void storedDerivedKeyRequests();
    void storedGeneratedKeyRequests_data();
    void storedGeneratedKeyRequests();
    void cipherSignVerify_data();
    void cipherSignVerify();
    void cipherEncryptDecrypt_data();
    void cipherEncryptDecrypt();
    void cipherBenchmark_data();
    void cipherBenchmark();
    void cipherTimeout_data();
    void cipherTimeout();
    void lockCode_data();
    void lockCode();
    void pluginThreading();
    void requestInterleaving();
    void importKey_data();
    void importKey();
    void importKeyAndStore_data();
    void importKeyAndStore();
    void exampleUsbTokenPlugin();
};

Sailfish::Secrets::CreateCollectionRequest *tst_cryptorequests::newCreateCollectionRequest(
        const QString &collectionName,
        const TestPluginMap &plugins,
        bool autoDeleteCollection,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    Q_ASSERT(plugins.contains(CryptoTest::StoragePlugin));
    Q_ASSERT(plugins.contains(CryptoTest::EncryptionPlugin));
    Q_ASSERT(plugins.contains(CryptoTest::AuthenticationPlugin));

    Sailfish::Secrets::CreateCollectionRequest *ccr = new Sailfish::Secrets::CreateCollectionRequest(this);
    ccr->setManager(&m_sm);
    ccr->setCollectionName(collectionName);
    ccr->setStoragePluginName(plugins.value(CryptoTest::StoragePlugin));
    ccr->setEncryptionPluginName(plugins.value(CryptoTest::EncryptionPlugin));
    ccr->setAuthenticationPluginName(plugins.value(CryptoTest::AuthenticationPlugin));
    ccr->setAccessControlMode(accessControlMode);
    ccr->setUserInteractionMode(userInteractionMode);

    if (autoDeleteCollection) {
        // ensure the collection is deleted when the test finishes
        TestCollection collection = {
            ccr->collectionName(),
            ccr->storagePluginName(),
            ccr->userInteractionMode()
        };
        m_populatedCollections.append(collection);
    }

    return ccr;
}

Sailfish::Secrets::CreateCollectionRequest *tst_cryptorequests::newCreateCollectionRequestWithDeviceLock(
        const QString &collectionName,
        const TestPluginMap &plugins,
        bool autoDeleteCollection,
        Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic deviceLockSemantic,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    Sailfish::Secrets::CreateCollectionRequest *ccr =
            newCreateCollectionRequest(collectionName, plugins, autoDeleteCollection, accessControlMode, userInteractionMode);
    ccr->setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr->setDeviceLockUnlockSemantic(deviceLockSemantic);
    return ccr;
}

Sailfish::Secrets::CreateCollectionRequest *tst_cryptorequests::newCreateCollectionRequestWithCustomLock(
        const QString &collectionName,
        const TestPluginMap &plugins,
        bool autoDeleteCollection,
        Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic customLockSemantic,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    Sailfish::Secrets::CreateCollectionRequest *ccr =
            newCreateCollectionRequest(collectionName, plugins, autoDeleteCollection, accessControlMode, userInteractionMode);
    ccr->setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::CustomLock);
    ccr->setCustomLockUnlockSemantic(customLockSemantic);
    return ccr;
}

void tst_cryptorequests::getPluginInfo_data()
{
    QTest::addColumn<QString>("pluginName");
    QTest::addColumn<QString>("pluginDisplayName");
    QTest::addColumn<CryptoTest::PluginType>("pluginType");
    QTest::addColumn<PluginInfo::StatusFlags>("pluginStatus");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    QTest::newRow("DefaultCryptoPlugin")
            << DEFAULT_TEST_CRYPTO_PLUGIN_NAME << QStringLiteral("OpenSSL Crypto") << CryptoTest::CryptoPlugin
            << (PluginInfo::Available | PluginInfo::MasterUnlocked | PluginInfo::PluginUnlocked) << CryptoTest::TestRequests();
    QTest::newRow("DefaultEncryptedStoragePlugin crypto")
            << DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME << QStringLiteral("SQLCipher") << CryptoTest::CryptoPlugin
            << (PluginInfo::Available | PluginInfo::MasterUnlocked | PluginInfo::PluginUnlocked) << CryptoTest::TestRequests();
    QTest::newRow("DefaultEncryptedStoragePlugin storage")
            << DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME << QStringLiteral("SQLCipher") << CryptoTest::StoragePlugin
            << (PluginInfo::Available | PluginInfo::MasterUnlocked | PluginInfo::PluginUnlocked) << CryptoTest::TestRequests();
    QTest::newRow("DefaultUsbTokenPlugin")
            << TEST_USB_TOKEN_PLUGIN_NAME << QStringLiteral("example_usb_token-display_name") << CryptoTest::CryptoPlugin
            << (PluginInfo::Available | PluginInfo::MasterUnlocked | PluginInfo::PluginSupportsLocking) << CryptoTest::TestRequests();
}

void tst_cryptorequests::getPluginInfo()
{
    QFETCH(QString, pluginName);
    QFETCH(QString, pluginDisplayName);
    QFETCH(CryptoTest::PluginType, pluginType);
    QFETCH(PluginInfo::StatusFlags, pluginStatus);
    QFETCH(CryptoTest::TestRequests, testRequests);

    PluginInfoRequest r;
    r.setManager(&m_cm);
    r.setCustomParameters(testRequests.value("PluginInfoRequest").customerParameters);
    QSignalSpy ss(&r, &PluginInfoRequest::statusChanged);
    QSignalSpy cryptoPluginsChangedSpy(&r, &PluginInfoRequest::cryptoPluginsChanged);
    QSignalSpy storagePluginsChangedSpy(&r, &PluginInfoRequest::storagePluginsChanged);

    START_AND_WAIT_FOR_REQUEST_RESULT(r, ss, testRequests, "PluginInfoRequest");

    if (pluginType == CryptoTest::CryptoPlugin) {
        QCOMPARE(cryptoPluginsChangedSpy.count(), 1);
        bool foundPlugin = false;
        for (auto p : r.cryptoPlugins()) {
            if (p.name() == pluginName
                    || p.name() == PluginNameMapping::mappedPluginName(pluginName)) {
                foundPlugin = true;
                QCOMPARE(p.displayName(), pluginDisplayName);
                QCOMPARE(p.statusFlags(), pluginStatus);
                break;
            }
        }
if (!foundPlugin) { qWarning() << "XXXXXXXXXXXX didn't find:" << pluginName << "in:"; for (auto p : r.cryptoPlugins()) qWarning() << p.name(); }
        QVERIFY(foundPlugin);
    }

    if (pluginType == CryptoTest::StoragePlugin) {
        QCOMPARE(storagePluginsChangedSpy.count(), 1);
        bool foundPlugin = false;
        for (auto p : r.storagePlugins()) {
            if (p.name() == pluginName
                    || p.name() == PluginNameMapping::mappedPluginName(pluginName)) {
                foundPlugin = true;
                QCOMPARE(p.displayName(), pluginDisplayName);
                QCOMPARE(p.statusFlags(), pluginStatus);
                break;
            }
        }
if (!foundPlugin) { qWarning() << "XXXXXXXXXXXX didn't find:" << pluginName << "in:"; for (auto p : r.storagePlugins()) qWarning() << p.name(); }
        QVERIFY(foundPlugin);
    }
}

void tst_cryptorequests::randomData_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<QString>("csprngEngineName");
    QTest::addColumn<int>("generateRandomDataSize");
    QTest::addColumn<double>("seedRandomDataEntropyEstimate");
    QTest::addColumn<QByteArray>("seedData");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    QTest::newRow("DefaultCryptoPlugin")
            << plugins << GenerateRandomDataRequest::DefaultCsprngEngineName
            << 2048
            << 0.5 << QByteArray("seed")
            << CryptoTest::TestRequests();
}

void tst_cryptorequests::randomData()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(QString, csprngEngineName);
    QFETCH(int, generateRandomDataSize);
    QFETCH(double, seedRandomDataEntropyEstimate);
    QFETCH(QByteArray, seedData);
    QFETCH(CryptoTest::TestRequests, testRequests);

    QByteArray randomData;

    GenerateRandomDataRequest grdr;

    // test generating random data
    grdr.setManager(&m_cm);
    grdr.setCustomParameters(testRequests.value("GenerateRandomDataRequest").customerParameters);
    QSignalSpy grdrss(&grdr, &GenerateRandomDataRequest::statusChanged);
    QSignalSpy grdrds(&grdr, &GenerateRandomDataRequest::generatedDataChanged);
    grdr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(grdr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));
    grdr.setCsprngEngineName(csprngEngineName);
    QCOMPARE(grdr.csprngEngineName(), csprngEngineName);
    grdr.setNumberBytes(generateRandomDataSize);

    START_AND_WAIT_FOR_REQUEST_RESULT(grdr, grdrss, testRequests, "GenerateRandomDataRequest");
    if (testRequests.value("GenerateRandomDataRequest").resultCode == Result::Succeeded) {
        QCOMPARE(grdrds.count(), 1);
        randomData = grdr.generatedData();
        QCOMPARE(randomData.size(), generateRandomDataSize);
        QVERIFY(!allCharactersAreNull(randomData));
    }

    // test seeding the random number generator
    SeedRandomDataGeneratorRequest srdgr;
    srdgr.setManager(&m_cm);
    srdgr.setCustomParameters(testRequests.value("SeedRandomDataGeneratorRequest").customerParameters);
    QSignalSpy srdgrss(&srdgr, &SeedRandomDataGeneratorRequest::statusChanged);
    srdgr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(srdgr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));
    srdgr.setCsprngEngineName(csprngEngineName);
    QCOMPARE(srdgr.csprngEngineName(), csprngEngineName);
    srdgr.setSeedData(seedData);
    QCOMPARE(srdgr.seedData(), seedData);
    srdgr.setEntropyEstimate(seedRandomDataEntropyEstimate);
    QCOMPARE(srdgr.entropyEstimate(), seedRandomDataEntropyEstimate);

    START_AND_WAIT_FOR_REQUEST_RESULT(srdgr, srdgrss, testRequests, "SeedRandomDataGeneratorRequest");

    // ensure that we get different random data to the original set
    grdr.startRequest();
    WAIT_FOR_REQUEST_RESULT(grdr, testRequests, "GenerateRandomDataRequest");
    QByteArray seededData = grdr.generatedData();
    if (testRequests.value("GenerateRandomDataRequest").resultCode == Result::Succeeded) {
        QCOMPARE(seededData.size(), generateRandomDataSize);
        QVERIFY(randomData != seededData);
    }
}

void tst_cryptorequests::randomData_dev_urandom()
{
    // try a different engine (/dev/urandom)
    // and use the random data to generate a random number
    // in some range
    GenerateRandomDataRequest grdr;
    grdr.setManager(&m_cm);
    grdr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    grdr.setCsprngEngineName(QStringLiteral("/dev/urandom"));
    grdr.setNumberBytes(8);
    grdr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(grdr);
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
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<CryptoManager::Algorithm>("algorithm");
    QTest::addColumn<CryptoManager::BlockMode>("blockMode");
    QTest::addColumn<int>("expectedIvSize");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    QTest::newRow("Unsupported") << plugins << CryptoManager::AlgorithmCustom << CryptoManager::BlockModeCustom << -1
                                 << TestRequests{ {"GenerateInitializationVectorRequest", TestRequest::fail(Result::OperationNotSupportedError)} };
    QTest::newRow("AES ECB") << plugins << CryptoManager::AlgorithmAes << CryptoManager::BlockModeEcb << 0 << CryptoTest::TestRequests();
    QTest::newRow("AES CBC") << plugins << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCbc << 16 << CryptoTest::TestRequests();
    QTest::newRow("AES GCM") << plugins << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << 12 << CryptoTest::TestRequests();
    QTest::newRow("AES CCM") << plugins << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCcm << 7 << CryptoTest::TestRequests();
}

void tst_cryptorequests::generateInitializationVectorRequest()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, expectedIvSize);
    QFETCH(CryptoTest::TestRequests, testRequests);

    GenerateInitializationVectorRequest ivr;
    ivr.setManager(&m_cm);
    ivr.setCustomParameters(testRequests.value("GenerateInitializationVectorRequest").customerParameters);
    ivr.setAlgorithm(algorithm);
    ivr.setBlockMode(blockMode);
    ivr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(ivr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QSignalSpy ivrss(&ivr, &GenerateInitializationVectorRequest::statusChanged);
    QSignalSpy ivrivs(&ivr, &GenerateInitializationVectorRequest::generatedInitializationVectorChanged);

    START_AND_WAIT_FOR_REQUEST_RESULT(ivr, ivrss, testRequests, "GenerateInitializationVectorRequest");
    if (testRequests.value("GenerateInitializationVectorRequest").resultCode == Result::Succeeded) {
        QCOMPARE(ivrivs.count(), 1);
        QByteArray iv = ivr.generatedInitializationVector();
        QCOMPARE(iv.size(), qMax(0, expectedIvSize));
    }
}

void tst_cryptorequests::generateKeyEncryptDecrypt_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    addCryptoTestData(plugins, Key::OriginDevice, CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
}

void tst_cryptorequests::generateKeyEncryptDecrypt()
{
    FETCH_CRYPTO_TEST_DATA;

    bool isSymmetric = keyTemplate.algorithm() < CryptoManager::FirstAsymmetricAlgorithm
            || keyTemplate.algorithm() > CryptoManager::LastAsymmetricAlgorithm;

    GenerateKeyRequest gkr;
    gkr.setManager(&m_cm);
    gkr.setCustomParameters(testRequests.value("GenerateKeyRequest").customerParameters);
    QSignalSpy gkrss(&gkr, &GenerateKeyRequest::statusChanged);
    QSignalSpy gkrks(&gkr, &GenerateKeyRequest::generatedKeyChanged);
    gkr.setKeyTemplate(keyTemplate);
    QCOMPARE(gkr.keyTemplate(), keyTemplate);

    if (!isSymmetric) {
        auto keyPairParams = getKeyPairGenerationParameters(keyTemplate.algorithm(), keyTemplate.size());
        gkr.setKeyPairGenerationParameters(keyPairParams);
    }

    gkr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(gkr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(gkrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gkr, gkrss, testRequests, "GenerateKeyRequest");
    Key fullKey = gkr.generatedKey();

    if (testRequests.value("GenerateKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gkrks.count(), 1);
        if (isSymmetric) {
            QVERIFY(!fullKey.secretKey().isEmpty());
        } else {
            QVERIFY(!fullKey.privateKey().isEmpty());
            QVERIFY(!fullKey.publicKey().isEmpty());
        }
        QCOMPARE(fullKey.filterData(), keyTemplate.filterData());
        QCOMPARE(fullKey.size(), keyTemplate.size());
    }

    QByteArray authenticationTag;
    QByteArray ciphertext;

    // test encrypting some plaintext with the generated key
    EncryptRequest er;
    er.setManager(&m_cm);
    er.setCustomParameters(testRequests.value("EncryptRequest").customerParameters);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setInitializationVector(initVector);
    QCOMPARE(er.initializationVector(), initVector);
    er.setKey(fullKey);
    QCOMPARE(er.key(), fullKey);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setPadding(padding);
    QCOMPARE(er.padding(), padding);
    if (!authData.isEmpty()) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(er.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(ercs.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "EncryptRequest");
    if (testRequests.value("EncryptRequest").resultCode == Result::Succeeded) {
        QCOMPARE(ercs.count(), 1);
        ciphertext = er.ciphertext();
        QVERIFY(!ciphertext.isEmpty());
        QVERIFY(ciphertext != plaintext);
        authenticationTag = er.authenticationTag();
        QCOMPARE(authenticationTag.isEmpty(), authData.isEmpty());
    }

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    dr.setManager(&m_cm);
    dr.setCustomParameters(testRequests.value("DecryptRequest").customerParameters);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setInitializationVector(initVector);
    QCOMPARE(dr.initializationVector(), initVector);
    dr.setKey(fullKey);
    QCOMPARE(dr.key(), fullKey);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);
    dr.setPadding(padding);
    QCOMPARE(dr.padding(), padding);
    if (!authData.isEmpty()) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }
    dr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(dr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(drps.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(dr, drss, testRequests, "DecryptRequest");
    if (testRequests.value("DecryptRequest").resultCode == Result::Succeeded) {
        QCOMPARE(drps.count(), 1);
        QByteArray decrypted = dr.plaintext();
        QVERIFY(!decrypted.isEmpty());
        QCOMPARE(plaintext, decrypted);
        QCOMPARE(dr.verificationStatus() == CryptoManager::VerificationSucceeded, !dr.authenticationData().isEmpty());
    }
}

void tst_cryptorequests::signVerify_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<Key>("keyTemplate");
    QTest::addColumn<KeyPairGenerationParameters>("keyPairGenParams");
    QTest::addColumn<CryptoManager::DigestFunction>("digestFunction");
    QTest::addColumn<QByteArray>("plaintext");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    Key keyTemplateRsa = createTestKey(0, CryptoManager::AlgorithmRsa, Key::OriginDevice, CryptoManager::OperationSign);
    Key keyTemplateEc = createTestKey(0, CryptoManager::AlgorithmEc, Key::OriginDevice, CryptoManager::OperationSign);

    KeyPairGenerationParameters keyPairGenParamsRsa = getKeyPairGenerationParameters(CryptoManager::AlgorithmRsa, 2048);
    KeyPairGenerationParameters keyPairGenParamsEc = getKeyPairGenerationParameters(CryptoManager::AlgorithmEc, 2048);

    QByteArray plaintext = "Test plaintext data";

    QTest::newRow("RSA + SHA256")
            << plugins
            << keyTemplateRsa << keyPairGenParamsRsa
            << CryptoManager::DigestSha256
            << plaintext
            << CryptoTest::TestRequests();
    QTest::newRow("RSA + SHA512")
            << plugins
            << keyTemplateRsa << keyPairGenParamsRsa
            << CryptoManager::DigestSha512
            << plaintext
            << CryptoTest::TestRequests();
    QTest::newRow("RSA + MD5")
            << plugins
            << keyTemplateRsa << keyPairGenParamsRsa
            << CryptoManager::DigestMd5
            << plaintext
            << CryptoTest::TestRequests();
    QTest::newRow("EC + SHA256")
            << plugins
            << keyTemplateEc << keyPairGenParamsEc
            << CryptoManager::DigestSha256
            << plaintext
            << CryptoTest::TestRequests();
    QTest::newRow("EC + SHA512")
            << plugins
            << keyTemplateEc << keyPairGenParamsEc
            << CryptoManager::DigestSha512
            << plaintext
            << CryptoTest::TestRequests();
}

void tst_cryptorequests::signVerify()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(Key, keyTemplate);
    QFETCH(KeyPairGenerationParameters, keyPairGenParams);
    QFETCH(CryptoManager::DigestFunction, digestFunction);
    QFETCH(QByteArray, plaintext);
    QFETCH(CryptoTest::TestRequests, testRequests);

    // Generate key for signing
    // ----------------------------

    // Key pair generation params, make sure it's valid
    QVERIFY2(keyPairGenParams.keyPairType() != KeyPairGenerationParameters::KeyPairUnknown, "Key pair type SHOULD NOT be unknown.");
    QVERIFY2(keyPairGenParams.isValid(), "Key pair generation params are invalid.");

    // Create generate key request, execute, make sure it's okay
    GenerateKeyRequest gkr;
    gkr.setManager(&m_cm);
    gkr.setCustomParameters(testRequests.value("GenerateKeyRequest").customerParameters);
    gkr.setKeyPairGenerationParameters(keyPairGenParams);
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    gkr.startRequest();
    WAIT_FOR_REQUEST_RESULT(gkr, testRequests, "GenerateKeyRequest");

    // Grab generated key, make sure it's sane
    Key fullKey = gkr.generatedKey();
    if (testRequests.value("GenerateKeyRequest").resultCode == Result::Succeeded) {
        QVERIFY(!fullKey.privateKey().isEmpty());
        QVERIFY(!fullKey.publicKey().isEmpty());
    }

    // Sign a test plaintext
    // ----------------------------

    SignRequest sr;
    sr.setManager(&m_cm);
    sr.setCustomParameters(testRequests.value("SignRequest").customerParameters);
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
    sr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(sr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(srvs.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(sr, srss, testRequests, "SignRequest");
    QByteArray signature = sr.signature();
    if (testRequests.value("SignRequest").resultCode == Result::Succeeded) {
        QCOMPARE(srvs.count(), 1);
    }

    // Verify the test signature
    // ----------------------------

    VerifyRequest vr;
    vr.setManager(&m_cm);
    vr.setCustomParameters(testRequests.value("VerifyRequest").customerParameters);
    QSignalSpy vrss(&vr, &VerifyRequest::statusChanged);
    QSignalSpy vrvs(&vr, &VerifyRequest::verificationStatusChanged);
    QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationStatusUnknown);
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
    vr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(vr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    START_AND_WAIT_FOR_REQUEST_RESULT(vr, vrss, testRequests, "VerifyRequest");
    if (testRequests.value("VerifyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(vrvs.count(), 1);
        QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationSucceeded);
    }
}

void tst_cryptorequests::calculateDigest_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<CryptoManager::DigestFunction>("digestFunction");
    QTest::addColumn<QCryptographicHash::Algorithm>("cryptographicHashAlgorithm");
    QTest::addColumn<CryptoManager::SignaturePadding>("signaturePadding");
    QTest::addColumn<QByteArray>("plaintext");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    QByteArray plaintext = "Test plaintext data";

    QTest::newRow("SHA256")
            << plugins
            << CryptoManager::DigestSha256 << QCryptographicHash::Sha256 << CryptoManager::SignaturePaddingNone
            << plaintext
            << CryptoTest::TestRequests();
    QTest::newRow("SHA512")
            << plugins
            << CryptoManager::DigestSha512 << QCryptographicHash::Sha512 << CryptoManager::SignaturePaddingNone
            << plaintext
            << CryptoTest::TestRequests();
    QTest::newRow("MD5")
            << plugins
            << CryptoManager::DigestMd5 << QCryptographicHash::Md5 << CryptoManager::SignaturePaddingNone
            << plaintext
            << CryptoTest::TestRequests();
}

void tst_cryptorequests::calculateDigest()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(CryptoManager::DigestFunction, digestFunction);
    QFETCH(QCryptographicHash::Algorithm, cryptographicHashAlgorithm);
    QFETCH(CryptoManager::SignaturePadding, signaturePadding);
    QFETCH(QByteArray, plaintext);
    QFETCH(CryptoTest::TestRequests, testRequests);

    CalculateDigestRequest cdr;
    cdr.setManager(&m_cm);
    cdr.setCustomParameters(testRequests.value("CalculateDigestRequest").customerParameters);
    QSignalSpy cdrss(&cdr, &CalculateDigestRequest::statusChanged);
    QSignalSpy cdrds(&cdr, &CalculateDigestRequest::digestChanged);
    QCOMPARE(cdr.status(), Request::Inactive);
    cdr.setData(plaintext);
    QCOMPARE(cdr.data(), plaintext);
    cdr.setDigestFunction(digestFunction);
    QCOMPARE(cdr.digestFunction(), digestFunction);
    cdr.setPadding(signaturePadding);
    QCOMPARE(cdr.padding(), signaturePadding);
    cdr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(cdr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(cdrds.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(cdr, cdrss, testRequests, "CalculateDigestRequest");
    if (testRequests.value("CalculateDigestRequest").resultCode == Result::Succeeded) {
        QCOMPARE(cdrds.count(), 1);
        QByteArray digest = cdr.digest();
        QVERIFY2(digest.length() != 0, "Calculated digest should NOT be empty.");
        QCOMPARE(digest, QCryptographicHash::hash(plaintext, cryptographicHashAlgorithm));
    }
}

void tst_cryptorequests::storedKeyRequests_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    addCryptoTestData(plugins, Key::OriginDevice, CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt, createTestKeyIdentifier(plugins));
}

void tst_cryptorequests::storedKeyRequests()
{
    FETCH_CRYPTO_TEST_DATA;
    if (keyTemplate.algorithm() != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    keyTemplate.setComponentConstraints(Key::MetaData | Key::PublicKeyData | Key::PrivateKeyData);
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    QCOMPARE(gskrks.count(), 1);
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
        QVERIFY(!keyReference.identifier().name().isEmpty());
        QVERIFY(!keyReference.identifier().collectionName().isEmpty());
        QVERIFY(!keyReference.identifier().storagePluginName().isEmpty());
    }

    QByteArray authenticationTag;
    QByteArray ciphertext;

    // test encrypting some plaintext with the stored key.
    EncryptRequest er;
    er.setManager(&m_cm);
    er.setCustomParameters(testRequests.value("EncryptRequest").customerParameters);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setInitializationVector(initVector);
    QCOMPARE(er.initializationVector(), initVector);
    er.setKey(keyReference);
    QCOMPARE(er.key(), keyReference);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setPadding(padding);
    QCOMPARE(er.padding(), padding);
    if (!authData.isEmpty()) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(er.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(ercs.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "EncryptRequest");
    if (testRequests.value("EncryptRequest").resultCode == Result::Succeeded) {
        QCOMPARE(ercs.count(), 1);
        ciphertext = er.ciphertext();
        authenticationTag = er.authenticationTag();
        QVERIFY(!ciphertext.isEmpty());
        QVERIFY(ciphertext != plaintext);
        QCOMPARE(authenticationTag.isEmpty(), authData.isEmpty());
    }

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    QByteArray decrypted;
    dr.setManager(&m_cm);
    dr.setCustomParameters(testRequests.value("DecryptRequest").customerParameters);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setInitializationVector(initVector);
    QCOMPARE(dr.initializationVector(), initVector);
    dr.setKey(keyReference);
    QCOMPARE(dr.key(), keyReference);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);
    dr.setPadding(padding);
    QCOMPARE(dr.padding(), padding);
    if (!authData.isEmpty()) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }
    dr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(dr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(drps.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(dr, drss, testRequests, "DecryptRequest");
    if (testRequests.value("DecryptRequest").resultCode == Result::Succeeded) {
        QCOMPARE(drps.count(), 1);
        decrypted = dr.plaintext();
        QVERIFY(!decrypted.isEmpty());
        QCOMPARE(plaintext, decrypted);
        QCOMPARE(dr.verificationStatus() == CryptoManager::VerificationSucceeded, !dr.authenticationData().isEmpty());
    }

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    Sailfish::Secrets::FindSecretsRequest fsr;
    fsr.setManager(&m_sm);
    fsr.setFilter(filter);
    fsr.setFilterOperator(Sailfish::Secrets::SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    fsr.setCollectionName(keyTemplate.identifier().collectionName());
    fsr.setStoragePluginName(plugins.value(CryptoTest::StoragePlugin));
    fsr.startRequest();
    WAIT_FOR_REQUEST_RESULT(fsr, testRequests, "FindSecretsRequest");
    if (testRequests.value("FindSecretsRequest").resultCode == Result::Succeeded) {
        QCOMPARE(fsr.identifiers().size(), 1);
        QCOMPARE(fsr.identifiers().at(0).name(), keyTemplate.identifier().name());
        QCOMPARE(fsr.identifiers().at(0).collectionName(), keyTemplate.identifier().collectionName());
    }

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_REQUEST_RESULT(fsr, testRequests, "FindSecretsRequest");
    if (testRequests.value("FindSecretsRequest").resultCode == Result::Succeeded) {
        QCOMPARE(fsr.identifiers().size(), 0);
    }

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&m_cm);
    skr.setCustomParameters(testRequests.value("StoredKeyRequest").customerParameters);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(Key::MetaData);
    QCOMPARE(skr.keyComponents(), Key::MetaData);

    QCOMPARE(skrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(skr, skrss, testRequests, "StoredKeyRequest");
    QCOMPARE(skrks.count(), 1);
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
        QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
        QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched
    }

    // and that we can get the public key data + custom parameters
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData);
    skr.startRequest();
    WAIT_FOR_REQUEST_RESULT(skr, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
        QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched
    }

    // and that we can get the secret key data
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData | Key::SecretKeyData);
    skr.startRequest();
    WAIT_FOR_REQUEST_RESULT(skr, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
        QVERIFY(!skr.storedKey().secretKey().isEmpty());
    }

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&m_sm);
    dcr.setCollectionName(keyTemplate.identifier().collectionName());
    dcr.setStoragePluginName(plugins.value(CryptoTest::StoragePlugin));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(dcr);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_REQUEST_FAILED(dr, Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    delete ccr;
    ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins, false);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    gskr.startRequest();
    WAIT_FOR_REQUEST_RESULT(gskr, testRequests, "GenerateKeyRequest");
    keyReference = gskr.generatedKeyReference();

    er.setKey(keyReference);
    er.setData(plaintext);
    if (!authData.isEmpty()) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.startRequest();
    WAIT_FOR_REQUEST_RESULT(er, testRequests, "EncryptRequest");
    ciphertext = er.ciphertext();
    if (!authData.isEmpty()) {
        authenticationTag = er.authenticationTag();
    }

    dr.setKey(keyReference);
    dr.setData(ciphertext);
    if (!authData.isEmpty()) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }

    if (testRequests.value("DecryptRequest").resultCode == Result::Succeeded) {
        dr.startRequest();
        WAIT_FOR_REQUEST_RESULT(dr, testRequests, "DecryptRequest");
        decrypted = dr.plaintext();
        QCOMPARE(decrypted, plaintext);
    }

    // delete the key via deleteStoredKey, and test that the deletion worked.
    DeleteStoredKeyRequest dskr;
    dskr.setManager(&m_cm);
    dskr.setCustomParameters(testRequests.value("DeleteStoredKeyRequest").customerParameters);
    QSignalSpy dskrss(&dskr, &DeleteStoredKeyRequest::statusChanged);
    dskr.setIdentifier(keyTemplate.identifier());
    QCOMPARE(dskr.identifier(), keyTemplate.identifier());

    START_AND_WAIT_FOR_REQUEST_RESULT(dskr, dskrss, testRequests, "DeleteStoredKeyRequest");
    if (testRequests.value("DeleteStoredKeyRequest").resultCode == Result::Succeeded) {
        // ensure that the deletion was cascaded to the keyEntries internal database table.
        dr.setKey(keyReference);
        dr.startRequest();
        WAIT_FOR_REQUEST_FAILED(dr, Result::InvalidKeyIdentifier);

        // ensure that the deletion was cascaded to the Secrets internal database table.
        Sailfish::Secrets::StoredSecretRequest gsr;
        gsr.setManager(&m_sm);
        gsr.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                              keyReference.identifier().name(),
                              keyReference.identifier().collectionName(),
                              keyReference.identifier().storagePluginName()));
        gsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
        gsr.startRequest();
        WAIT_FOR_REQUEST_FAILED(gsr, Sailfish::Secrets::Result::InvalidSecretError);
    }
}

void tst_cryptorequests::storedKeyIdentifiersRequests_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<Key>("keyTemplate");
    QTest::addColumn<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>("unlockSemantic");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, PASSWORD_AGENT_TEST_AUTH_PLUGIN);

    // Create a secret key and store it into the collection.
    Key keyTemplate = createTestKey(128, CryptoManager::AlgorithmAes, Key::OriginDevice,
                                    CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
                                    Key::Identifier(QStringLiteral("testkeyname"),
                                                                      QStringLiteral("tstcryptorequestsskir"),
                                                                      plugins.value(CryptoTest::StoragePlugin)));

    QTest::newRow("sqlcipher customlock keepunlocked")
            << plugins
            << keyTemplate
            << Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked
            << CryptoTest::TestRequests();

    QTest::newRow("sqlcipher customlock accessrelock")
            << plugins
            << keyTemplate
            << Sailfish::Secrets::SecretManager::CustomLockAccessRelock
            << CryptoTest::TestRequests();
}

void tst_cryptorequests::storedKeyIdentifiersRequests()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(Key, keyTemplate);
    QFETCH(Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic, unlockSemantic);
    QFETCH(CryptoTest::TestRequests, testRequests);

    if (keyTemplate.algorithm() != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    keyTemplate.setComponentConstraints(Key::MetaData | Key::PublicKeyData | Key::PrivateKeyData);
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithCustomLock(keyTemplate.identifier().collectionName(), plugins, true, unlockSemantic);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gskrks.count(), 1);
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
        QVERIFY(!keyReference.identifier().name().isEmpty());
        QVERIFY(!keyReference.identifier().collectionName().isEmpty());
        QVERIFY(!keyReference.identifier().storagePluginName().isEmpty());
    }

    // if the unlock semantic is CustomLockRelock then requesting all
    // stored key identifiers may not return the newly added key,
    // since that collection should be locked.
    StoredKeyIdentifiersRequest skir;
    skir.setManager(&m_cm);
    skir.setCustomParameters(testRequests.value("StoredKeyIdentifiersRequest").customerParameters);
    skir.setStoragePluginName(plugins.value(CryptoTest::StoragePlugin));
    skir.setCollectionName(QString()); // clear.
    skir.startRequest();
    WAIT_FOR_REQUEST_RESULT(skir, testRequests, "StoredKeyIdentifiersRequest");
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded
            && unlockSemantic == Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked) {
        bool keyFound = false;
        for (const Key::Identifier &ident : skir.identifiers()) {
            if (ident == keyReference.identifier()) {
                keyFound = true;
            }
        }
        QCOMPARE(keyFound, true);
    }

    // in either case, requesting stored key identifiers from the
    // specific collection should work (after an unlock flow completes).
    skir.setCollectionName(keyTemplate.identifier().collectionName());
    skir.startRequest();
    WAIT_FOR_REQUEST_RESULT(skir, testRequests, "StoredKeyIdentifiersRequest");
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        bool keyFound = false;
        for (const Key::Identifier &ident : skir.identifiers()) {
            if (ident == keyReference.identifier()) {
                keyFound = true;
            }
        }
        QCOMPARE(keyFound, true);
    }
}

void tst_cryptorequests::storedDerivedKeyRequests_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, PASSWORD_AGENT_TEST_AUTH_PLUGIN);
    plugins.insert(CryptoTest::InAppAuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    addCryptoTestData(plugins, Key::OriginDevice, CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt, createTestKeyIdentifier(plugins));
}

void tst_cryptorequests::storedDerivedKeyRequests()
{
    FETCH_CRYPTO_TEST_DATA;
    if (keyTemplate.algorithm() != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    // test generating a symmetric cipher key via a key derivation function
    // and storing securely in the same plugin which produces the key.
    keyTemplate.setComponentConstraints(Key::MetaData | Key::PublicKeyData | Key::PrivateKeyData);
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    KeyDerivationParameters skdf;
    skdf.setKeyDerivationFunction(CryptoManager::KdfPkcs5Pbkdf2);
    skdf.setKeyDerivationMac(CryptoManager::MacHmac);
    skdf.setKeyDerivationDigestFunction(CryptoManager::DigestSha1);
    skdf.setIterations(16384);
    skdf.setSalt(QByteArray("0123456789abcdef"));
    //skdf.setInputData(QByteArray("example user passphrase")); // TODO: this is implemented, but not covered by the unit test if uiParams exists!
    skdf.setOutputKeySize(keyTemplate.size());

    InteractionParameters uiParams;
    uiParams.setAuthenticationPluginName(plugins.value(CryptoTest::InAppAuthenticationPlugin));
    uiParams.setInputType(InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(InteractionParameters::NormalEcho);
    uiParams.setPromptText(QLatin1String("Enter the lock code for the unit test"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));
    gskr.setKeyDerivationParameters(skdf);
    QCOMPARE(gskr.keyDerivationParameters(), skdf);
    gskr.setInteractionParameters(uiParams);
    QCOMPARE(gskr.interactionParameters(), uiParams);

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gskrks.count(), 1);
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    }

    // test encrypting some plaintext with the stored key.
    QByteArray authenticationTag;
    QByteArray ciphertext;
    QByteArray decrypted;

    EncryptRequest er;
    er.setManager(&m_cm);
    er.setCustomParameters(testRequests.value("EncryptRequest").customerParameters);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setInitializationVector(initVector);
    QCOMPARE(er.initializationVector(), initVector);
    er.setKey(keyReference);
    QCOMPARE(er.key(), keyReference);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setPadding(padding);
    QCOMPARE(er.padding(), padding);
    if (!authData.isEmpty()) {
        er.setAuthenticationData(authData);
        QCOMPARE(er.authenticationData(), authData);
    }
    er.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(er.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(ercs.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "EncryptRequest");
    ciphertext = er.ciphertext();
    if (testRequests.value("EncryptRequest").resultCode == Result::Succeeded) {
        QCOMPARE(ercs.count(), 1);
        QVERIFY(!ciphertext.isEmpty());
        QVERIFY(ciphertext != plaintext);
        authenticationTag = er.authenticationTag();
        QCOMPARE(authenticationTag.isEmpty(), authData.isEmpty());
    }

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    dr.setManager(&m_cm);
    dr.setCustomParameters(testRequests.value("DecryptRequest").customerParameters);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setInitializationVector(initVector);
    QCOMPARE(dr.initializationVector(), initVector);
    dr.setKey(keyReference);
    QCOMPARE(dr.key(), keyReference);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);
    dr.setPadding(padding);
    QCOMPARE(dr.padding(), padding);
    if (!authData.isEmpty()) {
        dr.setAuthenticationData(authData);
        QCOMPARE(dr.authenticationData(), authData);
        dr.setAuthenticationTag(authenticationTag);
        QCOMPARE(dr.authenticationTag(), authenticationTag);
    }
    dr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(dr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(drps.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(dr, drss, testRequests, "DecryptRequest");
    if (testRequests.value("DecryptRequest").resultCode == Result::Succeeded) {
        QCOMPARE(drps.count(), 1);
        decrypted = dr.plaintext();
        QVERIFY(!decrypted.isEmpty());
        QCOMPARE(plaintext, decrypted);
        QCOMPARE(dr.verificationStatus() == CryptoManager::VerificationSucceeded, !dr.authenticationData().isEmpty());
    }

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    Sailfish::Secrets::FindSecretsRequest fsr;
    fsr.setManager(&m_sm);
    fsr.setFilter(filter);
    fsr.setFilterOperator(Sailfish::Secrets::SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    fsr.setCollectionName(keyTemplate.identifier().collectionName());
    fsr.setStoragePluginName(plugins.value(CryptoTest::StoragePlugin));
    fsr.startRequest();
    WAIT_FOR_REQUEST_RESULT(fsr, testRequests, "FindSecretsRequest");
    if (testRequests.value("FindSecretsRequest").resultCode == Result::Succeeded) {
        QCOMPARE(fsr.identifiers().size(), 1);
        QCOMPARE(fsr.identifiers().at(0).name(), keyTemplate.identifier().name());
        QCOMPARE(fsr.identifiers().at(0).collectionName(), keyTemplate.identifier().collectionName());
    }

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_REQUEST_RESULT(fsr, testRequests, "FindSecretsRequest");
    if (testRequests.value("FindSecretsRequest").resultCode == Result::Succeeded) {
        QCOMPARE(fsr.identifiers().size(), 0);
    }

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&m_cm);
    skr.setCustomParameters(testRequests.value("StoredKeyRequest").customerParameters);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(Key::MetaData);
    QCOMPARE(skr.keyComponents(), Key::MetaData);

    QCOMPARE(skrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(skr, skrss, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skrks.count(), 1);
        QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
        QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
        QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched
    }

    // and that we can get the public key data + custom parameters
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData);
    skr.startRequest();
    WAIT_FOR_REQUEST_RESULT(skr, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
        QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched
    }

    // and that we can get the secret key data
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData | Key::SecretKeyData);
    skr.startRequest();
    WAIT_FOR_REQUEST_RESULT(skr, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
        QVERIFY(!skr.storedKey().secretKey().isEmpty());
    }

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&m_sm);
    dcr.setCollectionName(keyTemplate.identifier().collectionName());
    dcr.setStoragePluginName(plugins.value(CryptoTest::StoragePlugin));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(dcr);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_REQUEST_FAILED(dr, Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    delete ccr;
    ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins, false);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    gskr.startRequest();
    WAIT_FOR_REQUEST_RESULT(gskr, testRequests, "GenerateKeyRequest");
    keyReference = gskr.generatedKeyReference();

    er.setKey(keyReference);
    er.setData(plaintext);
    er.startRequest();
    WAIT_FOR_REQUEST_RESULT(er, testRequests, "EncryptRequest");
    ciphertext = er.ciphertext();

    dr.setKey(keyReference);
    dr.setData(ciphertext);
    dr.startRequest();
    WAIT_FOR_REQUEST_RESULT(dr, testRequests, "DecryptRequest");
    decrypted = dr.plaintext();
    if (testRequests.value("DecryptRequest").resultCode == Result::Succeeded) {
        QCOMPARE(decrypted, plaintext);
    }

    // delete the key via deleteStoredKey, and test that the deletion worked.
    DeleteStoredKeyRequest dskr;
    dskr.setManager(&m_cm);
    dskr.setCustomParameters(testRequests.value("DeleteStoredKeyRequest").customerParameters);
    QSignalSpy dskrss(&dskr, &DeleteStoredKeyRequest::statusChanged);
    dskr.setIdentifier(keyTemplate.identifier());
    QCOMPARE(dskr.identifier(), keyTemplate.identifier());

    START_AND_WAIT_FOR_REQUEST_RESULT(dskr, dskrss, testRequests, "DecryptRequest");
    if (testRequests.value("DeleteStoredKeyRequest").resultCode == Result::Succeeded) {
        // ensure that the deletion was cascaded to the keyEntries internal database table.
        dr.setKey(keyReference);
        dr.startRequest();
        WAIT_FOR_REQUEST_FAILED(dr, Result::InvalidKeyIdentifier);

        // ensure that the deletion was cascaded to the Secrets internal database table.
        Sailfish::Secrets::StoredSecretRequest gsr;
        gsr.setManager(&m_sm);
        gsr.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                              keyReference.identifier().name(),
                              keyReference.identifier().collectionName(),
                              keyReference.identifier().storagePluginName()));
        gsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
        gsr.startRequest();
        WAIT_FOR_REQUEST_FAILED(gsr, Sailfish::Secrets::Result::InvalidSecretError);
    }
}

void tst_cryptorequests::storedGeneratedKeyRequests_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<Key>("keyTemplate");
    QTest::addColumn<RsaKeyPairGenerationParameters>("rsaKeyPairGenerationParams");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    Key keyTemplate = createTestKey(0, CryptoManager::AlgorithmRsa, Key::OriginDevice,
                                    CryptoManager::OperationEncrypt
                                    | CryptoManager::OperationDecrypt
                                    | CryptoManager::OperationSign
                                    | CryptoManager::OperationVerify);
    keyTemplate.setComponentConstraints(Key::MetaData | Key::PublicKeyData | Key::PrivateKeyData);
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    // request that the secret key be generated and stored into the collection.
    keyTemplate.setIdentifier(createTestKeyIdentifier(plugins));

    RsaKeyPairGenerationParameters rsakpg;
    rsakpg.setModulusLength(2048);
    rsakpg.setPublicExponent(65537);
    rsakpg.setNumberPrimes(2);

    QTest::newRow("DefaultCryptoStoragePlugin") << plugins << keyTemplate << rsakpg << CryptoTest::TestRequests();
}

void tst_cryptorequests::storedGeneratedKeyRequests()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(Key, keyTemplate);
    QFETCH(RsaKeyPairGenerationParameters, rsaKeyPairGenerationParams);
    QFETCH(CryptoTest::TestRequests, testRequests);

    // test generating an asymmetric cipher key pair
    // and storing securely in the same plugin which produces the key.

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));
    gskr.setKeyPairGenerationParameters(rsaKeyPairGenerationParams);

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gskrks.count(), 1);
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    }

    // TODO: attempt encryption/decryption once implemented

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    Sailfish::Secrets::FindSecretsRequest fsr;
    fsr.setManager(&m_sm);
    fsr.setFilter(filter);
    fsr.setFilterOperator(Sailfish::Secrets::SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    fsr.setCollectionName(keyTemplate.identifier().collectionName());
    fsr.setStoragePluginName(plugins.value(CryptoTest::StoragePlugin));
    fsr.startRequest();
    WAIT_FOR_REQUEST_RESULT(fsr, testRequests, "FindSecretsRequest");
    if (testRequests.value("FindSecretsRequest").resultCode == Result::Succeeded) {
        QCOMPARE(fsr.identifiers().size(), 1);
        QCOMPARE(fsr.identifiers().at(0).name(), keyTemplate.identifier().name());
        QCOMPARE(fsr.identifiers().at(0).collectionName(), keyTemplate.identifier().collectionName());
    }

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_REQUEST_RESULT(fsr, testRequests, "FindSecretsRequest");
    if (testRequests.value("FindSecretsRequest").resultCode == Result::Succeeded) {
        QCOMPARE(fsr.identifiers().size(), 0);
    }

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&m_cm);
    skr.setCustomParameters(testRequests.value("StoredKeyRequest").customerParameters);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(Key::MetaData);
    QCOMPARE(skr.keyComponents(), Key::MetaData);

    QCOMPARE(skrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(skr, skrss, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skrks.count(), 1);
        QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
        QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
        QVERIFY(skr.storedKey().publicKey().isEmpty()); // public key data, not fetched
        QVERIFY(skr.storedKey().privateKey().isEmpty()); // secret key data, not fetched
    }

    // and that we can get the public key data + custom parameters
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData);
    skr.startRequest();
    WAIT_FOR_REQUEST_RESULT(skr, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
        QVERIFY(!skr.storedKey().publicKey().isEmpty()); // public key data, fetched
        QVERIFY(skr.storedKey().privateKey().isEmpty()); // secret key data, not fetched
    }

    // and that we can get the secret key data
    skr.setKeyComponents(Key::MetaData | Key::PublicKeyData | Key::SecretKeyData);
    skr.startRequest();
    WAIT_FOR_REQUEST_RESULT(skr, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
        QVERIFY(!skr.storedKey().publicKey().isEmpty());  // public key data, fetched
        QVERIFY(!skr.storedKey().privateKey().isEmpty()); // private key data, fetched
    }
}

void tst_cryptorequests::cipherSignVerify_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<Key>("keyTemplate");
    QTest::addColumn<RsaKeyPairGenerationParameters>("rsaKeyPairGenerationParams");
    QTest::addColumn<CryptoManager::SignaturePadding>("signaturePadding");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    Key keyTemplate = createTestKey(0, CryptoManager::AlgorithmRsa, Key::OriginDevice,
                                    CryptoManager::OperationEncrypt
                                    | CryptoManager::OperationDecrypt
                                    | CryptoManager::OperationSign
                                    | CryptoManager::OperationVerify);
    keyTemplate.setComponentConstraints(Key::MetaData | Key::PublicKeyData | Key::PrivateKeyData);
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    keyTemplate.setIdentifier(Key::Identifier(
                                  QLatin1String("storedkey"),
                                  QLatin1String("tstcryptosecretscsv"),
                                  plugins.value(CryptoTest::StoragePlugin)));

    RsaKeyPairGenerationParameters rsakpg;
    rsakpg.setModulusLength(2048);
    rsakpg.setPublicExponent(65537);
    rsakpg.setNumberPrimes(2);

    QTest::newRow("DefaultCryptoStoragePlugin") << plugins << keyTemplate << rsakpg << CryptoManager::SignaturePaddingNone << CryptoTest::TestRequests();
}

void tst_cryptorequests::cipherSignVerify()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(Key, keyTemplate);
    QFETCH(RsaKeyPairGenerationParameters, rsaKeyPairGenerationParams);
    QFETCH(CryptoManager::SignaturePadding, signaturePadding);
    QFETCH(CryptoTest::TestRequests, testRequests);

    // test generating an asymmetric cipher key pair
    // and storing securely in the same plugin which produces the key.

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));
    gskr.setKeyPairGenerationParameters(rsaKeyPairGenerationParams);

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gskrks.count(), 1);
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    }

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&m_cm);
    skr.setCustomParameters(testRequests.value("StoredKeyRequest").customerParameters);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(Key::MetaData);
    QCOMPARE(skr.keyComponents(), Key::MetaData);

    QCOMPARE(skrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(skr, skrss, testRequests, "StoredKeyRequest");
    if (testRequests.value("StoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(skrks.count(), 1);
        QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
        QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
        QVERIFY(skr.storedKey().publicKey().isEmpty()); // public key data, not fetched
        QVERIFY(skr.storedKey().privateKey().isEmpty()); // secret key data, not fetched
    }

    // now perform a cipher request to sign/verify data.
    QByteArray signature;
    const QByteArray dataToSign = QByteArrayLiteral(
                "This is a large block of data which we will split up into "
                "chunks and sign via a cipher request rather than sending "
                "all of the data in a single chunk, in order to test the "
                "cipher session semantics with sign / verify operations");

    int chunkStartPos = 0;

    CipherRequest sr;
    sr.setManager(&m_cm);
    sr.setCustomParameters(testRequests.value("CipherRequest-OperationSign").customerParameters);
    sr.setKey(keyReference);
    sr.setOperation(CryptoManager::OperationSign);
    sr.setSignaturePadding(signaturePadding);
    sr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    sr.setCipherMode(CipherRequest::InitializeCipher);
    sr.startRequest();
    WAIT_FOR_REQUEST_RESULT(sr, testRequests, "CipherRequest-OperationSign");

    while (chunkStartPos < dataToSign.size()) {
        QByteArray chunk = dataToSign.mid(chunkStartPos, 16);
        if (chunk.isEmpty()) break;
        chunkStartPos += 16;
        sr.setCipherMode(CipherRequest::UpdateCipher);
        QCOMPARE(sr.cipherMode(), CipherRequest::UpdateCipher);
        sr.setData(chunk);
        QCOMPARE(sr.data(), chunk);
        sr.startRequest();
        WAIT_FOR_REQUEST_RESULT(sr, testRequests, "CipherRequest-OperationSign");
        QByteArray signatureChunk = sr.generatedData();
        signature.append(signatureChunk);
    }

    sr.setCipherMode(CipherRequest::FinalizeCipher);
    QCOMPARE(sr.cipherMode(), CipherRequest::FinalizeCipher);
    sr.setData(QByteArray());
    sr.startRequest();
    WAIT_FOR_REQUEST_RESULT(sr, testRequests, "CipherRequest-OperationSign");
    signature.append(sr.generatedData()); // may or may not be empty.
    if (testRequests.value("CipherRequest-OperationSign-FinalizeCipher").resultCode == Result::Succeeded) {
        QVERIFY(!signature.isEmpty());
    }

    // now verify the signature and ensure it verifies successfully.
    CipherRequest vr;
    vr.setManager(&m_cm);
    vr.setCustomParameters(testRequests.value("CipherRequest-OperationVerify").customerParameters);
    vr.setKey(keyReference);
    vr.setOperation(CryptoManager::OperationVerify);
    vr.setSignaturePadding(signaturePadding);
    vr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    vr.setCipherMode(CipherRequest::InitializeCipher);
    vr.startRequest();
    WAIT_FOR_REQUEST_RESULT(vr, testRequests, "CipherRequest-OperationVerify");

    chunkStartPos = 0;
    while (chunkStartPos < dataToSign.size()) {
        QByteArray chunk = dataToSign.mid(chunkStartPos, 16);
        if (chunk.isEmpty()) break;
        chunkStartPos += 16;
        vr.setCipherMode(CipherRequest::UpdateCipher);
        QCOMPARE(vr.cipherMode(), CipherRequest::UpdateCipher);
        vr.setData(chunk);
        QCOMPARE(vr.data(), chunk);
        vr.startRequest();
        WAIT_FOR_REQUEST_RESULT(vr, testRequests, "CipherRequest-OperationVerify");
    }

    vr.setCipherMode(CipherRequest::FinalizeCipher);
    QCOMPARE(vr.cipherMode(), CipherRequest::FinalizeCipher);
    vr.setData(signature);
    vr.startRequest();
    WAIT_FOR_REQUEST_RESULT(vr, testRequests, "CipherRequest-OperationVerify");
    if (testRequests.value("CipherRequest-OperationVerify").resultCode == Result::Succeeded) {
        QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationSucceeded);
    }
}

void tst_cryptorequests::cipherEncryptDecrypt_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    QByteArray plaintext("This is a long plaintext"
                         " which contains multiple blocks of data"
                         " which will be encrypted over several updates"
                         " via a stream cipher operation.");

    addCryptoTestData(plugins, Key::OriginDevice, CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt, createTestKeyIdentifier(plugins), plaintext);
}

void tst_cryptorequests::cipherEncryptDecrypt()
{
    FETCH_CRYPTO_TEST_DATA;
    if (keyTemplate.algorithm() != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }
    if (blockMode == CryptoManager::BlockModeCcm) {
        QSKIP("CCM is not supported by CipherRequest");
    }

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    // then use that stored key to perform stream cipher encrypt/decrypt operations.

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gskrks.count(), 1);
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    }
    Key minimalKeyReference(keyReference.identifier().name(),
                                              keyReference.identifier().collectionName(),
                                              keyReference.identifier().storagePluginName());

    // now perform encryption.
    QByteArray ciphertext;
    QByteArray decrypted;
    QByteArray authenticationTag;

    int gdsCount = 0, chunkStartPos = 0;

    CipherRequest er;
    er.setManager(&m_cm);
    er.setCustomParameters(testRequests.value("CipherRequest-OperationEncrypt").customerParameters);
    QSignalSpy erss(&er,  &CipherRequest::statusChanged);
    QSignalSpy ergds(&er, &CipherRequest::generatedDataChanged);
    er.setKey(minimalKeyReference);
    QCOMPARE(er.key(), minimalKeyReference);
    er.setOperation(CryptoManager::OperationEncrypt);
    QCOMPARE(er.operation(), CryptoManager::OperationEncrypt);
    er.setBlockMode(blockMode);
    QCOMPARE(er.blockMode(), blockMode);
    er.setEncryptionPadding(padding);
    QCOMPARE(er.encryptionPadding(), padding);
    er.setInitializationVector(initVector);
    QCOMPARE(er.initializationVector(), initVector);
    er.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(er.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));
    er.setCipherMode(CipherRequest::InitializeCipher);
    QCOMPARE(er.cipherMode(), CipherRequest::InitializeCipher);

    QCOMPARE(ergds.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "CipherRequest-OperationEncrypt");
    QCOMPARE(ergds.count(), 0);

    if (!authData.isEmpty()) {
        er.setCipherMode(CipherRequest::UpdateCipherAuthentication);
        QCOMPARE(er.cipherMode(), CipherRequest::UpdateCipherAuthentication);
        er.setData(authData);
        QCOMPARE(er.data(), authData);
        START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "CipherRequest-OperationEncrypt");
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
        START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "CipherRequest-OperationEncrypt");
        if (testRequests.value("CipherRequest-OperationEncrypt").resultCode == Result::Succeeded) {
            QCOMPARE(ergds.count(), gdsCount + 1);
            QByteArray ciphertextChunk = er.generatedData();
            if (chunk.size() >= 16) {
                QVERIFY(ciphertextChunk.size() >= chunk.size());
                // otherwise, it will be emitted during FinalizeCipher
            }
            ciphertext.append(ciphertextChunk);
            QVERIFY(!ciphertext.isEmpty());
        }
    }

    er.setCipherMode(CipherRequest::FinalizeCipher);
    QCOMPARE(er.cipherMode(), CipherRequest::FinalizeCipher);
    er.setData(QByteArray());

    START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "CipherRequest-OperationEncrypt");
    if (testRequests.value("CipherRequest-OperationEncrypt").resultCode == Result::Succeeded) {
        if (!authData.isEmpty()) {
            authenticationTag = er.generatedData();
        } else {
            ciphertext.append(er.generatedData()); // may or may not be empty.
        }
        QVERIFY(!ciphertext.isEmpty());
    }

    // now perform decryption, and ensure the roundtrip matches.
    CipherRequest dr;
    dr.setManager(&m_cm);
    dr.setCustomParameters(testRequests.value("CipherRequest-OperationDecrypt").customerParameters);
    QSignalSpy drss(&dr,  &CipherRequest::statusChanged);
    QSignalSpy drgds(&dr, &CipherRequest::generatedDataChanged);
    dr.setKey(minimalKeyReference);
    QCOMPARE(dr.key(), minimalKeyReference);
    dr.setInitializationVector(initVector);
    QCOMPARE(dr.initializationVector(), initVector);
    dr.setOperation(CryptoManager::OperationDecrypt);
    QCOMPARE(dr.operation(), CryptoManager::OperationDecrypt);
    dr.setBlockMode(blockMode);
    QCOMPARE(dr.blockMode(), blockMode);
    dr.setEncryptionPadding(padding);
    QCOMPARE(dr.encryptionPadding(), padding);
    dr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(dr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));
    dr.setCipherMode(CipherRequest::InitializeCipher);
    QCOMPARE(dr.cipherMode(), CipherRequest::InitializeCipher);

    QCOMPARE(drgds.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(dr, drss, testRequests, "CipherRequest-OperationDecrypt");
    QCOMPARE(drgds.count(), 0);

    if (!authData.isEmpty()) {
        dr.setCipherMode(CipherRequest::UpdateCipherAuthentication);
        QCOMPARE(dr.cipherMode(), CipherRequest::UpdateCipherAuthentication);
        dr.setData(authData);
        QCOMPARE(dr.data(), authData);
        START_AND_WAIT_FOR_REQUEST_RESULT(dr, drss, testRequests, "CipherRequest-OperationDecrypt");
    }

    gdsCount = 0; chunkStartPos = 0;
    while (chunkStartPos < ciphertext.size()) {
        QByteArray chunk = ciphertext.mid(chunkStartPos, 16);
        if (chunk.isEmpty()) break;
        chunkStartPos += 16;
        dr.setCipherMode(CipherRequest::UpdateCipher);
        QCOMPARE(dr.cipherMode(), CipherRequest::UpdateCipher);
        dr.setData(chunk);
        QCOMPARE(dr.data(), chunk);
        gdsCount = drgds.count();

        START_AND_WAIT_FOR_REQUEST_RESULT(dr, drss, testRequests, "CipherRequest-OperationDecrypt");
        if (testRequests.value("CipherRequest-OperationDecrypt").resultCode == Result::Succeeded) {
            QByteArray plaintextChunk = dr.generatedData();
            decrypted.append(plaintextChunk);
            if (authData.isEmpty()
                    && chunkStartPos >= 32) {
                // in CBC mode the first block will not be returned,
                // due to the cipher requiring it for the next update.
                QCOMPARE(drgds.count(), gdsCount + 1);
                QVERIFY(plaintextChunk.size() >= chunk.size());
                QVERIFY(!decrypted.isEmpty());
            }
        }
    }

    dr.setCipherMode(CipherRequest::FinalizeCipher);
    QCOMPARE(dr.cipherMode(), CipherRequest::FinalizeCipher);
    dr.setData(!authData.isEmpty() ? authenticationTag : QByteArray());

    START_AND_WAIT_FOR_REQUEST_RESULT(dr, drss, testRequests, "CipherRequest-OperationDecrypt");
    if (testRequests.value("CipherRequest-OperationDecrypt").resultCode == Result::Succeeded) {
        decrypted.append(dr.generatedData()); // may or may not be empty.
        QCOMPARE(plaintext, decrypted); // successful round trip!
        QCOMPARE(dr.verificationStatus() == CryptoManager::VerificationSucceeded, !authData.isEmpty());
    }
}

#define CIPHER_BENCHMARK_CHUNK_SIZE 131072
#define BATCH_BENCHMARK_CHUNK_SIZE 32768
#define BENCHMARK_TEST_FILE QLatin1String("/tmp/sailfish.crypto.testfile")

void tst_cryptorequests::cipherBenchmark_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    addCryptoTestData(plugins, Key::OriginDevice, CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt, createTestKeyIdentifier(plugins));
}

void tst_cryptorequests::cipherBenchmark()
{
    FETCH_CRYPTO_TEST_DATA;
    if (keyTemplate.algorithm() != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }
    if (!QFile::exists(BENCHMARK_TEST_FILE)) {
        QSKIP("First generate test data via: head -c 33554432 </dev/urandom >/tmp/sailfish.crypto.testfile");
    }

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    // then use that stored key to perform stream cipher encrypt/decrypt operations.

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gskrks.count(), 1);
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    }
    Key minimalKeyReference(keyReference.identifier().name(),
                                              keyReference.identifier().collectionName(),
                                              keyReference.identifier().storagePluginName());

    int chunkStartPos = 0;

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
        er.setManager(&m_cm);
        er.setCustomParameters(testRequests.value("CipherRequest-OperationEncrypt").customerParameters);
        er.setKey(minimalKeyReference);
        er.setOperation(CryptoManager::OperationEncrypt);
        er.setBlockMode(blockMode);
        er.setEncryptionPadding(padding);
        er.setInitializationVector(initVector);
        QCOMPARE(er.initializationVector(), initVector);
        er.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
        er.setCipherMode(CipherRequest::InitializeCipher);
        er.startRequest();
        WAIT_FOR_REQUEST_RESULT(er, testRequests, "CipherRequest-OperationEncrypt");

        while (chunkStartPos < plaintext.size()) {
            QByteArray chunk = plaintext.mid(chunkStartPos, CIPHER_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += CIPHER_BENCHMARK_CHUNK_SIZE;
            er.setCipherMode(CipherRequest::UpdateCipher);
            er.setData(chunk);
            er.startRequest();
            WAIT_FOR_REQUEST_RESULT(er, testRequests, "CipherRequest-OperationEncrypt");
            QByteArray ciphertextChunk = er.generatedData();
            ciphertext.append(ciphertextChunk);
        }

        er.setCipherMode(CipherRequest::FinalizeCipher);
        er.setData(QByteArray());
        er.startRequest();
        WAIT_FOR_REQUEST_RESULT(er, testRequests, "CipherRequest-OperationEncrypt");
        ciphertext.append(er.generatedData()); // may or may not be empty.

        encryptionTime = et.elapsed();

        // now perform decryption, and ensure the roundtrip matches.
        CipherRequest dr;
        dr.setManager(&m_cm);
        dr.setCustomParameters(testRequests.value("CipherRequest-OperationDecrypt").customerParameters);
        dr.setKey(minimalKeyReference);
        dr.setInitializationVector(initVector);
        dr.setOperation(CryptoManager::OperationDecrypt);
        dr.setBlockMode(blockMode);
        dr.setEncryptionPadding(padding);
        dr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
        dr.setCipherMode(CipherRequest::InitializeCipher);
        dr.startRequest();
        WAIT_FOR_REQUEST_RESULT(dr, testRequests, "CipherRequest-OperationDecrypt");

        chunkStartPos = 0;
        while (chunkStartPos < ciphertext.size()) {
            QByteArray chunk = ciphertext.mid(chunkStartPos, CIPHER_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += CIPHER_BENCHMARK_CHUNK_SIZE;
            dr.setCipherMode(CipherRequest::UpdateCipher);
            dr.setData(chunk);
            dr.startRequest();
            WAIT_FOR_REQUEST_RESULT(dr, testRequests, "CipherRequest-OperationDecrypt");
            QByteArray plaintextChunk = dr.generatedData();
            decrypted.append(plaintextChunk);
        }

        dr.setCipherMode(CipherRequest::FinalizeCipher);
        dr.setData(QByteArray());
        dr.startRequest();
        WAIT_FOR_REQUEST_RESULT(dr, testRequests, "CipherRequest-OperationDecrypt");
        decrypted.append(dr.generatedData()); // may or may not be empty.

        totalTime = et.elapsed();
        decryptionTime = totalTime - encryptionTime;
        qWarning() << "Finished non-batch benchmark at:" << QDateTime::currentDateTime().toString(Qt::ISODate);
        qWarning() << "Encrypted in" << encryptionTime << ", Decrypted in" << decryptionTime << "(msecs)";

        if (testRequests.value("CipherRequest-OperationEncrypt").resultCode == Result::Succeeded
                && testRequests.value("CipherRequest-OperationDecrypt").resultCode == Result::Succeeded) {
            QCOMPARE(plaintext, decrypted); // successful round trip!
        }
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
        er.setManager(&m_cm);
        er.setCustomParameters(testRequests.value("CipherRequest-OperationEncrypt").customerParameters);
        er.setKey(minimalKeyReference);
        er.setInitializationVector(initVector);
        er.setOperation(CryptoManager::OperationEncrypt);
        er.setBlockMode(blockMode);
        er.setEncryptionPadding(padding);
        er.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
        er.setCipherMode(CipherRequest::InitializeCipher);
        er.startRequest();
        WAIT_LONG_FOR_REQUEST_RESULT(er, testRequests, "CipherRequest-OperationEncrypt");

        int chunkStartPos = 0;
        while (chunkStartPos < plaintext.size()) {
            QByteArray chunk = plaintext.mid(chunkStartPos, BATCH_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += BATCH_BENCHMARK_CHUNK_SIZE;
            er.setCipherMode(CipherRequest::UpdateCipher);
            er.setData(chunk);
            er.startRequest();
        }
        WAIT_LONG_FOR_REQUEST_RESULT(er, testRequests, "CipherRequest-OperationEncrypt"); // wait for the updates to finish.

        er.setCipherMode(CipherRequest::FinalizeCipher);
        er.setData(QByteArray());
        er.startRequest();
        WAIT_LONG_FOR_REQUEST_RESULT(er, testRequests, "CipherRequest-OperationEncrypt");

        encryptionTime = et.elapsed();

        // now perform decryption, and ensure the roundtrip matches.
        CipherRequest dr;
        QObject::connect(&dr, &CipherRequest::generatedDataChanged,
                         [&dr, &decrypted] {
            decrypted.append(dr.generatedData());
        });
        dr.setManager(&m_cm);
        dr.setCustomParameters(testRequests.value("CipherRequest-OperationDecrypt").customerParameters);
        dr.setKey(minimalKeyReference);
        dr.setInitializationVector(initVector);
        dr.setOperation(CryptoManager::OperationDecrypt);
        dr.setBlockMode(blockMode);
        dr.setEncryptionPadding(padding);
        dr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
        dr.setCipherMode(CipherRequest::InitializeCipher);
        dr.startRequest();
        WAIT_LONG_FOR_REQUEST_RESULT(dr, testRequests, "CipherRequest-OperationDecrypt");

        chunkStartPos = 0;
        while (chunkStartPos < ciphertext.size()) {
            QByteArray chunk = ciphertext.mid(chunkStartPos, BATCH_BENCHMARK_CHUNK_SIZE);
            if (chunk.isEmpty()) break;
            chunkStartPos += BATCH_BENCHMARK_CHUNK_SIZE;
            dr.setCipherMode(CipherRequest::UpdateCipher);
            dr.setData(chunk);
            dr.startRequest();
        }
        WAIT_LONG_FOR_REQUEST_RESULT(dr, testRequests, "CipherRequest-OperationDecrypt"); // drain the queue of responses.

        dr.setCipherMode(CipherRequest::FinalizeCipher);
        dr.setData(QByteArray());
        dr.startRequest();
        WAIT_LONG_FOR_REQUEST_RESULT(dr, testRequests, "CipherRequest-OperationDecrypt");

        totalTime = et.elapsed();
        decryptionTime = totalTime - encryptionTime;
        qWarning() << "Finished batch benchmark at:" << QDateTime::currentDateTime().toString(Qt::ISODate);
        qWarning() << "Encrypted in" << encryptionTime << ", Decrypted in" << decryptionTime << "(msecs)";

        if (testRequests.value("CipherRequest-OperationEncrypt").resultCode == Result::Succeeded
                && testRequests.value("CipherRequest-OperationDecrypt").resultCode == Result::Succeeded) {
            QCOMPARE(plaintext, decrypted); // successful round trip!
            QCOMPARE(ciphertext, canonicalCiphertext);
        }
    }
}

void tst_cryptorequests::cipherTimeout_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<Key>("keyTemplate");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    // this test ensures that cipher sessions time out after some period of time.
    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    // then use that stored key to perform stream cipher encrypt/decrypt operations.
    Key keyTemplate = createTestKey(256, CryptoManager::AlgorithmAes, Key::OriginDevice,
                                    CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt,
                                    createTestKeyIdentifier(plugins));

    QTest::newRow("DefaultCryptoPlugin") << plugins << keyTemplate << CryptoTest::TestRequests();
}

void tst_cryptorequests::cipherTimeout()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(Key, keyTemplate);
    QFETCH(CryptoTest::TestRequests, testRequests);

    QSKIP("This test should only be run manually after changing CIPHER_SESSION_INACTIVITY_TIMEOUT to 10000");

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
    ccr->startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED((*ccr));

    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setCustomParameters(testRequests.value("GenerateStoredKeyRequest").customerParameters);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(gskr.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    QCOMPARE(gskrks.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(gskr, gskrss, testRequests, "GenerateStoredKeyRequest");
    Key keyReference = gskr.generatedKeyReference();
    if (testRequests.value("GenerateStoredKeyRequest").resultCode == Result::Succeeded) {
        QCOMPARE(gskrks.count(), 1);
        QVERIFY(keyReference.secretKey().isEmpty());
        QVERIFY(keyReference.privateKey().isEmpty());
        QCOMPARE(keyReference.filterData(), keyTemplate.filterData());
    }
    Key minimalKeyReference(keyReference.identifier().name(),
                                              keyReference.identifier().collectionName(),
                                              keyReference.identifier().storagePluginName());

    // now perform encryption.
    QByteArray initVector = generateInitializationVector(keyTemplate.algorithm(),
                                                 CryptoManager::BlockModeCbc);
    QByteArray plaintext("This is a long plaintext"
                         " which contains multiple blocks of data"
                         " which will be encrypted over several updates"
                         " via a stream cipher operation.");

    CipherRequest er;
    er.setManager(&m_cm);
    er.setCustomParameters(testRequests.value("CipherRequest").customerParameters);
    QSignalSpy erss(&er,  &CipherRequest::statusChanged);
    QSignalSpy ergds(&er, &CipherRequest::generatedDataChanged);
    er.setKey(minimalKeyReference);
    QCOMPARE(er.key(), minimalKeyReference);
    er.setOperation(CryptoManager::OperationEncrypt);
    QCOMPARE(er.operation(), CryptoManager::OperationEncrypt);
    er.setBlockMode(CryptoManager::BlockModeCbc);
    QCOMPARE(er.blockMode(), CryptoManager::BlockModeCbc);
    er.setEncryptionPadding(CryptoManager::EncryptionPaddingNone);
    QCOMPARE(er.encryptionPadding(), CryptoManager::EncryptionPaddingNone);
    er.setInitializationVector(initVector);
    QCOMPARE(er.initializationVector(), initVector);
    er.setCryptoPluginName(plugins.value(CryptoTest::StoragePlugin));
    QCOMPARE(er.cryptoPluginName(), plugins.value(CryptoTest::StoragePlugin));
    er.setCipherMode(CipherRequest::InitializeCipher);
    QCOMPARE(er.cipherMode(), CipherRequest::InitializeCipher);

    QCOMPARE(ergds.count(), 0);
    START_AND_WAIT_FOR_REQUEST_RESULT(er, erss, testRequests, "CipherRequest");
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
    WAIT_FOR_REQUEST_SUCCEEDED(er);

    // wait for 12 seconds, which is greater than the 10 second timeout.
    QTest::qWait(12000);

    // now update the cipher session with the second chunk of data.
    // since the timeout was exceeded, this should not succeed.
    chunk = plaintext.mid(16, 32);
    er.setCipherMode(CipherRequest::UpdateCipher);
    er.setData(chunk);
    er.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(er);
    QCOMPARE(er.result().errorMessage(), QLatin1String("Unknown cipher session token provided"));
}

void tst_cryptorequests::lockCode_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    plugins.insert(CryptoTest::InAppAuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    QTest::newRow("DefaultInAppAuthenticationPlugin") << plugins << CryptoTest::TestRequests();
}

void tst_cryptorequests::lockCode()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(CryptoTest::TestRequests, testRequests);

    InteractionParameters uiParams;
    uiParams.setAuthenticationPluginName(plugins.value(CryptoTest::InAppAuthenticationPlugin));
    uiParams.setInputType(InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(InteractionParameters::NormalEcho);
    uiParams.setPromptText(QLatin1String("Modify the lock code for the crypto plugin"));

    LockCodeRequest lcr;
    lcr.setManager(&m_cm);
    lcr.setCustomParameters(testRequests.value("LockCodeRequest").customerParameters);
    QCOMPARE(lcr.lockStatus(), LockCodeRequest::Unknown);
    lcr.setLockCodeRequestType(LockCodeRequest::QueryLockStatus);
    QCOMPARE(lcr.lockCodeRequestType(), LockCodeRequest::QueryLockStatus);
    lcr.setLockCodeTargetType(LockCodeRequest::MetadataDatabase);
    QCOMPARE(lcr.lockCodeTargetType(), LockCodeRequest::MetadataDatabase);
    lcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(lcr);
    QCOMPARE(lcr.lockStatus(), LockCodeRequest::Unlocked);

    lcr.setLockCodeTargetType(LockCodeRequest::ExtensionPlugin);
    QCOMPARE(lcr.lockCodeTargetType(), LockCodeRequest::ExtensionPlugin);
    lcr.setLockCodeTarget(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(lcr.lockCodeTarget(), plugins.value(CryptoTest::CryptoPlugin));
    lcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(lcr);
    QCOMPARE(lcr.lockStatus(), LockCodeRequest::Unsupported);

    lcr.setLockCodeRequestType(LockCodeRequest::ModifyLockCode);
    QCOMPARE(lcr.lockCodeRequestType(), LockCodeRequest::ModifyLockCode);
    lcr.setLockCodeTargetType(LockCodeRequest::ExtensionPlugin);
    QCOMPARE(lcr.lockCodeTargetType(), LockCodeRequest::ExtensionPlugin);
    lcr.setLockCodeTarget(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(lcr.lockCodeTarget(), plugins.value(CryptoTest::CryptoPlugin));
    lcr.setInteractionParameters(uiParams);
    QCOMPARE(lcr.interactionParameters(), uiParams);
    lcr.startRequest();
    WAIT_FOR_REQUEST_FAILED(lcr, testRequests.value("ModifyLockCode").errorCode);   // xxx this will fail
    QVERIFY(lcr.result().errorMessage().startsWith(QStringLiteral("Crypto plugin")));
    QVERIFY(lcr.result().errorMessage().endsWith(QStringLiteral("does not support locking")));

    uiParams.setPromptText(QLatin1String("Provide the lock code for the crypto plugin"));
    uiParams.setAuthenticationPluginName(plugins.value(CryptoTest::InAppAuthenticationPlugin));
    lcr.setLockCodeRequestType(LockCodeRequest::ProvideLockCode);
    lcr.setInteractionParameters(uiParams);
    lcr.startRequest();
    WAIT_FOR_REQUEST_FAILED(lcr, testRequests.value("ProvideLockCode").errorCode);
    QVERIFY(lcr.result().errorMessage().startsWith(QStringLiteral("Crypto plugin")));
    QVERIFY(lcr.result().errorMessage().endsWith(QStringLiteral("does not support locking")));

    lcr.setLockCodeRequestType(LockCodeRequest::ForgetLockCode);
    lcr.startRequest();
    WAIT_FOR_REQUEST_FAILED(lcr, testRequests.value("ForgetLockCode").errorCode);
    QVERIFY(lcr.result().errorMessage().startsWith(QStringLiteral("Crypto plugin")));
    QVERIFY(lcr.result().errorMessage().endsWith(QStringLiteral("does not support locking")));
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

    Key keyTemplate = createTestKey(256, CryptoManager::AlgorithmAes, Key::OriginDevice,
                                    CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);

    GenerateKeyRequest gkr;
    gkr.setManager(&m_cm);
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    gkr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(gkr);
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
        er.setManager(&m_cm);
        er.setData(plaintext);
        er.setInitializationVector(initVector);
        er.setKey(fullKey);
        er.setBlockMode(CryptoManager::BlockModeCbc);
        er.setPadding(CryptoManager::EncryptionPaddingNone);
        er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
        er.startRequest();
        WAIT_FOR_REQUEST_SUCCEEDED(er);
        QByteArray ciphertext = er.ciphertext();
        QVERIFY(!ciphertext.isEmpty());
        QVERIFY(ciphertext != plaintext);

        // test decrypting the ciphertext, and ensure that the roundtrip works.
        DecryptRequest dr;
        dr.setManager(&m_cm);
        dr.setData(ciphertext);
        dr.setInitializationVector(initVector);
        dr.setKey(fullKey);
        dr.setBlockMode(CryptoManager::BlockModeCbc);
        dr.setPadding(CryptoManager::EncryptionPaddingNone);
        dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
        dr.startRequest();
        WAIT_FOR_REQUEST_SUCCEEDED(dr);
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

    Key keyTemplate = createTestKey(256, CryptoManager::AlgorithmAes, Key::OriginDevice,
                                    CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
    GenerateKeyRequest gkr;
    gkr.setManager(&m_cm);
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gkr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(gkr);
    Key fullKey = gkr.generatedKey();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    EncryptRequest er;
    er.setManager(&m_cm);
    er.setData(plaintext);
    er.setInitializationVector(initVector);
    er.setKey(fullKey);
    er.setBlockMode(CryptoManager::BlockModeCbc);
    er.setPadding(CryptoManager::EncryptionPaddingNone);
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);

    Sailfish::Secrets::Secret testSecret(
                Sailfish::Secrets::Secret::Identifier(
                        QStringLiteral("testsecretname"),
                        QString(),
                        DEFAULT_TEST_STORAGE_PLUGIN));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Sailfish::Secrets::Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

    Sailfish::Secrets::StoreSecretRequest ssr;
    ssr.setManager(&m_sm);
    ssr.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::StandaloneDeviceLockSecret);
    ssr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ssr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ssr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ssr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ssr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ssr.setSecret(testSecret);
    ssr.startRequest();

    Sailfish::Secrets::DeleteSecretRequest dsr;
    dsr.setManager(&m_sm);
    dsr.setIdentifier(testSecret.identifier());
    dsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    dsr.startRequest();

    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&m_sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("testinterleavingcollection"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(PASSWORD_AGENT_TEST_AUTH_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.startRequest();

    keyTemplate.setIdentifier(Key::Identifier(
                                  QLatin1String("storedkey"),
                                  QLatin1String("testinterleavingcollection"),
                                  DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME));
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&m_cm);
    gskr.setKeyTemplate(keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.startRequest();

    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&m_sm);
    dcr.setCollectionName(QLatin1String("testinterleavingcollection"));
    dcr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
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
        if (er.status() == Request::Finished) {
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
                    if (gskr.result().errorCode() == Result::InvalidKeyIdentifier) {
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
            } else if (gskr.result().errorCode() == Result::InvalidKeyIdentifier) {
                // If the request is interleaved such that the collection
                // has not successfully been created by the time we attempt
                // to generate and store the key, we may get this error.
                // This isn't a problem, as no stale data will have been
                // written to or left in any metadata databases.
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
            if (dsr.status() == Sailfish::Secrets::Request::Finished
                    && dsr.result().code() == Sailfish::Secrets::Result::Succeeded) {
                ssr.startRequest();
            }
        }

        if (dsr.status() == Sailfish::Secrets::Request::Finished) {
            // this may not succeed if the deletion is queued "too soon" after the secret is stored
            // since the "pre-check" (which retrieves the secret metadata) may fail if the secret
            // hasn't yet been stored.
            // E.g.: interleaved as ssr.precheck/dsr.precheck/ssr.store/dsr.delete
            // But if the previous dsr succeeded, the next ssr should succeed (non-duplicate).
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
        const Key::Identifier &identifier)
{
    Key key;
    key.setIdentifier(identifier);
    key.setComponentConstraints(Key::MetaData | Key::PublicKeyData);
    key.setOperations(CryptoManager::OperationEncrypt
                     |CryptoManager::OperationVerify);

    return key;
}

static Key createPrivateKey(
        const Key::Identifier &identifier)
{
    Key key;
    key.setIdentifier(identifier);
    key.setComponentConstraints(Key::MetaData | Key::PublicKeyData | Key::PrivateKeyData);
    key.setOperations(CryptoManager::OperationEncrypt
                     |CryptoManager::OperationDecrypt
                     |CryptoManager::OperationSign
                     |CryptoManager::OperationVerify);

    return key;
}

void tst_cryptorequests::importKey_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<QByteArray>("data");
    QTest::addColumn<Key>("keyTemplate");
    QTest::addColumn<InteractionParameters>("interactionParameters");
    QTest::addColumn<QByteArray>("privateKey");
    QTest::addColumn<QByteArray>("publicKey");
    QTest::addColumn<int>("size");
    QTest::addColumn<Key::Origin>("origin");
    QTest::addColumn<CryptoManager::Algorithm>("algorithm");
    QTest::addColumn<CryptoManager::SignaturePadding>("signaturePadding");
    QTest::addColumn<CryptoManager::DigestFunction>("digestFunction");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    InteractionParameters promptForSailfishPassphrase;
    promptForSailfishPassphrase.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    promptForSailfishPassphrase.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
    promptForSailfishPassphrase.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);
    promptForSailfishPassphrase.setPromptText(QLatin1String("Enter the passphrase 'sailfish'"));

    InteractionParameters promptToCancel;
    promptToCancel.setAuthenticationPluginName(PASSWORD_AGENT_TEST_AUTH_PLUGIN);
    promptToCancel.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
    promptToCancel.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);
    promptToCancel.setPromptText(QLatin1String("Cancel input"));

    InteractionParameters noUserInteraction;

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    Key::Identifier keyIdentifier = createTestKeyIdentifier(plugins, QStringLiteral("tstcryptorequestsimportKey"));

    CryptoTest::TestRequests testRequests{ {"ImportKeyRequest", TestRequest::success()}, {"ImportStoredKeyRequest", TestRequest::success()} };

    QTest::newRow("Private RSA 2048 - no passphrase")
            << plugins
            << test_key_rsa_2048_in
            << createPrivateKey(keyIdentifier)
            << noUserInteraction
            << test_key_rsa_2048_out
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;
    QTest::newRow("Private RSA 2048 - passphrase")
            << plugins
            << test_key_rsa_2048_sailfish_in
            << createPrivateKey(keyIdentifier)
            << promptForSailfishPassphrase
            << test_key_rsa_2048_out
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;
    QTest::newRow("Public RSA 2048")
            << plugins
            << test_key_rsa_2048_pub
            << createPublicKey(keyIdentifier)
            << noUserInteraction
            << QByteArray()
            << test_key_rsa_2048_pub
            << 2048
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;

    QTest::newRow("Private RSA 1024 - no passphrase")
            << plugins
            << test_key_rsa_1024_in
            << createPrivateKey(keyIdentifier)
            << noUserInteraction
            << test_key_rsa_1024_out
            << test_key_rsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;
    QTest::newRow("Private RSA 1024 - passphrase")
            << plugins
            << test_key_rsa_1024_sailfish_in
            << createPrivateKey(keyIdentifier)
            << promptForSailfishPassphrase
            << test_key_rsa_1024_out
            << test_key_rsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;
    QTest::newRow("Public RSA 1024")
            << plugins
            << test_key_rsa_1024_pub
            << createPublicKey(keyIdentifier)
            << noUserInteraction
            << QByteArray()
            << test_key_rsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmRsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;

    QTest::newRow("Private DSA 1024 - no passphrase")
            << plugins
            << test_key_dsa_1024_in
            << createPrivateKey(keyIdentifier)
            << noUserInteraction
            << test_key_dsa_1024_out
            << test_key_dsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmDsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;
    QTest::newRow("Private DSA 1024 - passphrase")
            << plugins
            << test_key_dsa_1024_sailfish_in
            << createPrivateKey(keyIdentifier)
            << promptForSailfishPassphrase
            << test_key_dsa_1024_out
            << test_key_dsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmDsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;
    QTest::newRow("Public DSA 1024")
            << plugins
            << test_key_dsa_1024_pub
            << createPublicKey(keyIdentifier)
            << noUserInteraction
            << QByteArray()
            << test_key_dsa_1024_pub
            << 1024
            << Key::OriginImported
            << CryptoManager::AlgorithmDsa
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << testRequests;

    QTest::newRow("Private RSA 2048 - passphrase, no user interaction")
            << plugins
            << test_key_rsa_2048_sailfish_in
            << createPrivateKey(keyIdentifier)
            << noUserInteraction
            << QByteArray()
            << QByteArray()
            << 0
            << Key::OriginUnknown
            << CryptoManager::AlgorithmUnknown
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << TestRequests{ {"ImportKeyRequest", TestRequest::fail(Result::CryptoPluginIncorrectPassphrase)}, {"ImportStoredKeyRequest", TestRequest::fail(Result::CryptoPluginIncorrectPassphrase)} };

    // this test should be enabled for manual testing only, user has to cancel the dialog.
    //QTest::newRow("Private RSA 2048 - passphrase, canceled")
    //        << plugins
    //        << test_key_rsa_2048_sailfish_in
    //        << createPrivateKey(keyIdentifier)
    //        << promptToCancel
    //        << QByteArray()
    //        << QByteArray()
    //        << 0
    //        << Key::OriginUnknown
    //        << CryptoManager::AlgorithmUnknown
    //        << CryptoManager::SignaturePaddingNone
    //        << CryptoManager::DigestSha256
    //        << TestRequests{ {"ImportKeyRequest", TestRequest::fail(Result::CryptoPluginKeyImportError)}, {"ImportStoredKeyRequest", TestRequest::fail(Result::CryptoPluginKeyImportError)} };
}

void tst_cryptorequests::importKey()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(QByteArray, data);
    QFETCH(Key, keyTemplate);
    QFETCH(InteractionParameters, interactionParameters);
    QFETCH(QByteArray, privateKey);
    QFETCH(QByteArray, publicKey);
    QFETCH(int, size);
    QFETCH(Key::Origin, origin);
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::SignaturePadding, signaturePadding);
    QFETCH(CryptoManager::DigestFunction, digestFunction);
    QFETCH(CryptoTest::TestRequests, testRequests);

    Q_UNUSED(keyTemplate); // importKey just uses the data.

    ImportKeyRequest request;
    request.setManager(&m_cm);
    request.setCustomParameters(testRequests.value("ImportKeyRequest").customerParameters);

    request.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(request.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    request.setData(data);
    QCOMPARE(request.data(), data);
    request.setInteractionParameters(interactionParameters);
    QCOMPARE(request.interactionParameters(), interactionParameters);

    request.startRequest();
    WAIT_FOR_REQUEST_RESULT(request, testRequests, "ImportKeyRequest");

    const Result result = request.result();
    const Result::ResultCode resultCode = (Result::ResultCode)testRequests.value("ImportKeyRequest").resultCode;
    const Result::ErrorCode errorCode = (Result::ErrorCode)testRequests.value("ImportKeyRequest").errorCode;
    const Key importedKey = request.importedKey();

    QCOMPARE(result.errorCode(), errorCode);

    QCOMPARE(importedKey.publicKey(), publicKey);
    QCOMPARE(importedKey.privateKey(), privateKey);
    QCOMPARE(importedKey.size(), size);
    QCOMPARE(importedKey.origin(), origin);
    QCOMPARE(importedKey.algorithm(), algorithm);

    // ensure that we can perform crypto operations with the imported key.
    if (resultCode == Result::Succeeded && privateKey.size()) {
        // attempt to sign some data with the key.
        const QByteArray dataToSign("The quick brown fox jumps over the lazy dog");
        SignRequest sr;
        sr.setManager(&m_cm);
        sr.setCustomParameters(testRequests.value("SignRequest").customerParameters);
        sr.setData(dataToSign);
        sr.setDigestFunction(digestFunction);
        sr.setPadding(signaturePadding);
        sr.setKey(importedKey);
        sr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        sr.startRequest();
        WAIT_FOR_REQUEST_RESULT(sr, testRequests, "SignRequest");
        QCOMPARE(sr.signature().isEmpty(), false);

        // attempt to verify the signed data.
        VerifyRequest vr;
        vr.setManager(&m_cm);
        vr.setCustomParameters(testRequests.value("VerifyRequest").customerParameters);
        vr.setData(dataToSign);
        vr.setSignature(sr.signature());
        vr.setDigestFunction(digestFunction);
        vr.setPadding(signaturePadding);
        vr.setKey(importedKey);
        vr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
        vr.startRequest();
        WAIT_FOR_REQUEST_RESULT(vr, testRequests, "VerifyRequest");
        if (testRequests.value("VerifyRequest").resultCode == Result::Succeeded) {
            QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationSucceeded);
        }

        // attempt to verify some other random data, and ensure that it fails.
        const QByteArray randomDataToVerify("abcdef1234567890987654321fedcba");
        vr.setData(randomDataToVerify);
        vr.startRequest();
        WAIT_FOR_REQUEST_RESULT(vr, testRequests, "VerifyRequest");
        if (testRequests.value("VerifyRequest").resultCode == Result::Succeeded) {
            QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationFailed);
        }
    }
}

void tst_cryptorequests::importKeyAndStore_data()
{
    importKey_data();

    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::AuthenticationPlugin, IN_APP_TEST_AUTHENTICATION_PLUGIN);

    QTest::newRow("Private RSA 2048 - no identifier")
            << plugins
            << test_key_rsa_2048_in
            << createPrivateKey(Key::Identifier())
            << InteractionParameters()
            << QByteArray()
            << QByteArray()
            << 0
            << Key::OriginUnknown
            << CryptoManager::AlgorithmUnknown
            << CryptoManager::SignaturePaddingNone
            << CryptoManager::DigestSha256
            << TestRequests{ {"ImportKeyRequest", TestRequest::fail(Result::InvalidKeyIdentifier)}, {"ImportStoredKeyRequest", TestRequest::fail(Result::InvalidKeyIdentifier)} };
}

void tst_cryptorequests::importKeyAndStore()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(QByteArray, data);
    QFETCH(Key, keyTemplate);
    QFETCH(InteractionParameters, interactionParameters);
    QFETCH(QByteArray, privateKey);
    QFETCH(QByteArray, publicKey);
    QFETCH(int, size);
    QFETCH(Key::Origin, origin);
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::SignaturePadding, signaturePadding);
    QFETCH(CryptoManager::DigestFunction, digestFunction);
    QFETCH(CryptoTest::TestRequests, testRequests);

    if (!keyTemplate.collectionName().isEmpty()) {
        Sailfish::Secrets::CreateCollectionRequest *ccr = newCreateCollectionRequestWithDeviceLock(keyTemplate.identifier().collectionName(), plugins);
        ccr->startRequest();
        WAIT_FOR_REQUEST_SUCCEEDED((*ccr));
    }

    ImportStoredKeyRequest request;
    request.setManager(&m_cm);
    request.setCustomParameters(testRequests.value("ImportStoredKeyRequest").customerParameters);

    request.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
    QCOMPARE(request.cryptoPluginName(), plugins.value(CryptoTest::CryptoPlugin));

    request.setData(data);
    QCOMPARE(request.data(), data);
    request.setKeyTemplate(keyTemplate);
    QCOMPARE(request.keyTemplate(), keyTemplate);
    request.setInteractionParameters(interactionParameters);
    QCOMPARE(request.interactionParameters(), interactionParameters);

    request.startRequest();
    WAIT_FOR_REQUEST_RESULT(request, testRequests, "ImportStoredKeyRequest");

    const Result result = request.result();
    QCOMPARE((int)result.errorCode(), (int)testRequests.value("ImportStoredKeyRequest").errorCode);

    const Key importedKey = request.importedKeyReference();

    QCOMPARE(importedKey.publicKey(), publicKey);
    if (testRequests.value("ImportStoredKeyRequest").resultCode == Result::Succeeded) {
        // we return whatever we received, in some failure codepaths.
        // but, when we successfully store an imported key, we always
        // return a key reference which contains no private key data.
        QCOMPARE(importedKey.privateKey(), QByteArray());
        QCOMPARE(importedKey.identifier().name(), keyTemplate.identifier().name());
        QCOMPARE(importedKey.identifier().collectionName(), keyTemplate.identifier().collectionName());
        QCOMPARE(importedKey.identifier().storagePluginName().isEmpty(), keyTemplate.identifier().storagePluginName().isEmpty());
        // note that the storage plugin name may have been mapped from default placeholder to real name.
    }
    QCOMPARE(importedKey.size(), size);
    QCOMPARE(importedKey.origin(), origin);
    QCOMPARE(importedKey.algorithm(), algorithm);

    // ensure that we can perform crypto operations with the stored key.
    if (testRequests.value("ImportStoredKeyRequest").resultCode == Result::Succeeded && privateKey.size()) {
        // attempt to sign some data with the key.
        const QByteArray dataToSign("The quick brown fox jumps over the lazy dog");
        SignRequest sr;
        sr.setManager(&m_cm);
        sr.setCustomParameters(testRequests.value("SignRequest").customerParameters);
        sr.setData(dataToSign);
        sr.setDigestFunction(digestFunction);
        sr.setPadding(signaturePadding);
        sr.setKey(importedKey);
        sr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
        sr.startRequest();
        WAIT_FOR_REQUEST_RESULT(sr, testRequests, "SignRequest");
        QCOMPARE(sr.signature().isEmpty(), false);

        // attempt to verify the signed data.
        VerifyRequest vr;
        vr.setManager(&m_cm);
        vr.setCustomParameters(testRequests.value("VerifyRequest").customerParameters);
        vr.setData(dataToSign);
        vr.setSignature(sr.signature());
        vr.setDigestFunction(digestFunction);
        vr.setPadding(signaturePadding);
        vr.setKey(importedKey);
        vr.setCryptoPluginName(plugins.value(CryptoTest::CryptoPlugin));
        vr.startRequest();
        WAIT_FOR_REQUEST_RESULT(vr, testRequests, "VerifyRequest");
        if (testRequests.value("VerifyRequest").resultCode == Result::Succeeded) {
            QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationSucceeded);
        }

        // attempt to verify some other random data, and ensure that it fails.
        const QByteArray randomDataToVerify("abcdef1234567890987654321fedcba");
        vr.setData(randomDataToVerify);
        vr.startRequest();
        WAIT_FOR_REQUEST_RESULT(vr, testRequests, "VerifyRequest");
        if (testRequests.value("VerifyRequest").resultCode == Result::Succeeded) {
            QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationFailed);
        }
    }
}

void tst_cryptorequests::exampleUsbTokenPlugin()
{
    // first, ensure that it is loaded by the secrets service.
    PluginInfoRequest pir;
    pir.setManager(&m_cm);
    pir.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(pir);

    bool foundUsbTokenExampleCryptoPlugin = false;
    for (const PluginInfo &pi : pir.cryptoPlugins()) {
        if (pi.name() == TEST_USB_TOKEN_PLUGIN_NAME) {
            foundUsbTokenExampleCryptoPlugin = true;
            break;
        }
    }
    QCOMPARE(foundUsbTokenExampleCryptoPlugin, true);

    bool foundUsbTokenExampleStoragePlugin = false;
    for (const PluginInfo &pi : pir.storagePlugins()) {
        if (pi.name() == TEST_USB_TOKEN_PLUGIN_NAME) {
            foundUsbTokenExampleStoragePlugin = true;
            break;
        }
    }
    QCOMPARE(foundUsbTokenExampleStoragePlugin, true);

    // second, attempt to unlock the plugin if it is locked.
    LockCodeRequest lcr;
    lcr.setManager(&m_cm);
    lcr.setLockCodeRequestType(LockCodeRequest::QueryLockStatus);
    lcr.setLockCodeTargetType(LockCodeRequest::ExtensionPlugin);
    lcr.setLockCodeTarget(TEST_USB_TOKEN_PLUGIN_NAME);
    lcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(lcr);
    QCOMPARE(lcr.lockStatus(), LockCodeRequest::Locked);

    lcr.setLockCodeRequestType(LockCodeRequest::ProvideLockCode);
    lcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(lcr);

    lcr.setLockCodeRequestType(LockCodeRequest::QueryLockStatus);
    lcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(lcr);
    QCOMPARE(lcr.lockStatus(), LockCodeRequest::Unlocked);

    // third, attempt to retrieve the identifiers of keys stored by the plugin.
    // check that it reports the "Default" key in the "Default" collection.
    StoredKeyIdentifiersRequest skir;
    skir.setManager(&m_cm);
    skir.setStoragePluginName(TEST_USB_TOKEN_PLUGIN_NAME);
    skir.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(skir);
    bool foundDefaultKey = false;
    for (const Key::Identifier &id : skir.identifiers()) {
        if (id.storagePluginName() == TEST_USB_TOKEN_PLUGIN_NAME
                && id.collectionName() == QStringLiteral("Default")
                && id.name() == QStringLiteral("Default")) {
            foundDefaultKey = true;
            break;
        }
    }
    QCOMPARE(foundDefaultKey, true);

    // fourth, attempt to sign some data with that key.
    const QByteArray dataToSign("The quick brown fox jumps over the lazy dog");
    SignRequest sr;
    sr.setManager(&m_cm);
    sr.setData(dataToSign);
    sr.setDigestFunction(CryptoManager::DigestSha256);
    sr.setPadding(CryptoManager::SignaturePaddingNone);
    sr.setKey(Key(QStringLiteral("Default"),
                                    QStringLiteral("Default"),
                                    TEST_USB_TOKEN_PLUGIN_NAME));
    sr.setCryptoPluginName(TEST_USB_TOKEN_PLUGIN_NAME);
    sr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(sr);
    QCOMPARE(sr.signature().isEmpty(), false);

    // fifth, attempt to verify the signed data.
    VerifyRequest vr;
    vr.setManager(&m_cm);
    vr.setData(dataToSign);
    vr.setSignature(sr.signature());
    vr.setDigestFunction(CryptoManager::DigestSha256);
    vr.setPadding(CryptoManager::SignaturePaddingNone);
    vr.setKey(Key(QStringLiteral("Default"),
                                    QStringLiteral("Default"),
                                    TEST_USB_TOKEN_PLUGIN_NAME));
    vr.setCryptoPluginName(TEST_USB_TOKEN_PLUGIN_NAME);
    vr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(vr);
    QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationSucceeded);

    // sixth, attempt to verify some other random data, and ensure that it fails.
    const QByteArray randomDataToVerify("abcdef1234567890987654321fedcba");
    vr.setData(randomDataToVerify);
    vr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(vr);
    QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationFailed);

    // finally, re-lock the plugin.
    lcr.setLockCodeRequestType(LockCodeRequest::ForgetLockCode);
    lcr.startRequest();
    WAIT_FOR_REQUEST_SUCCEEDED(lcr);
}

#include "tst_cryptorequests.moc"
QTEST_MAIN(tst_cryptorequests)
