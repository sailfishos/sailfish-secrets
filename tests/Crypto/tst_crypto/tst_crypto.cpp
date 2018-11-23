/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QObject>
#include <QVariantMap>
#include <QDBusReply>
#include <QFile>

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialization_p.h"
#include "Crypto/key.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/result.h"

#include "../cryptotest.h"

using namespace Sailfish::Crypto;

class tst_crypto : public CryptoTest
{
    Q_OBJECT

private slots:
    void getPluginInfo_data();
    void getPluginInfo();
    void randomData_data();
    void randomData();
    void generateKeyEncryptDecrypt_data();
    void generateKeyEncryptDecrypt();
};

void tst_crypto::getPluginInfo_data()
{
    QTest::addColumn<QStringList>("expectedCryptoPlugins");

    QTest::newRow("DefaultPlugins")
            << (QStringList() << DEFAULT_TEST_CRYPTO_PLUGIN_NAME << DEFAULT_PLUGIN_CRYPTO_STORAGE << TEST_USB_TOKEN_PLUGIN_NAME);
}

void tst_crypto::getPluginInfo()
{
    QFETCH(QStringList, expectedCryptoPlugins);

    QDBusPendingReply<Result, QVector<PluginInfo>, QVector<PluginInfo>> reply = m_cmp.getPluginInfo();
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    const QVector<PluginInfo> cryptoPlugins = reply.argumentAt<1>();
    QStringList cryptoPluginNames;
    for (const PluginInfo &p : cryptoPlugins) {
        cryptoPluginNames.append(p.name());
    }
    QVERIFY(cryptoPluginNames.size() >= expectedCryptoPlugins.size());
    for (const QString &expect : expectedCryptoPlugins) {
        QVERIFY(cryptoPluginNames.contains(expect)
             || cryptoPluginNames.contains(PluginNameMapping::mappedPluginName(expect)));
    }
}

void tst_crypto::randomData_data()
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<QString>("csprngEngineName");
    QTest::addColumn<int>("generateRandomDataSize");
    QTest::addColumn<double>("seedRandomDataEntropyEstimate");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    TestPluginMap plugins;
    plugins.insert(CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    QTest::newRow("DefaultCryptoPlugin")
            << plugins << QStringLiteral("default")
            << 2048 << double(1.0) << CryptoTest::TestRequests();
}

void tst_crypto::randomData()
{
    QFETCH(TestPluginMap, plugins);
    QFETCH(QString, csprngEngineName);
    QFETCH(int, generateRandomDataSize);
    QFETCH(double, seedRandomDataEntropyEstimate);
    QFETCH(CryptoTest::TestRequests, testRequests);

    // test generating random data
    QDBusPendingReply<Result, QByteArray> reply = m_cmp.generateRandomData(
            generateRandomDataSize,
            csprngEngineName,
            testRequests.value("generateRandomData").customerParameters,
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    QByteArray randomData = reply.argumentAt<1>();
    QCOMPARE(randomData.size(), generateRandomDataSize);
    QVERIFY(!allCharactersAreNull(randomData));

    // test seeding the random number generator
    QDBusPendingReply<Result> seedReply = m_cmp.seedRandomDataGenerator(
            QByteArray("seed"),
            seedRandomDataEntropyEstimate,
            csprngEngineName,
            testRequests.value("seedRandomDataGenerator").customerParameters,
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(seedReply);

    // ensure that we get different random data to the original set
    reply = m_cmp.generateRandomData(
            generateRandomDataSize,
            csprngEngineName,
            testRequests.value("generateRandomData").customerParameters,
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    QByteArray seededData = reply.argumentAt<1>();
    QCOMPARE(seededData.size(), generateRandomDataSize);
    QVERIFY(!allCharactersAreNull(seededData));
    QVERIFY(seededData != randomData);
}

void tst_crypto::generateKeyEncryptDecrypt_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);

    addCryptoTestData(plugins, Key::OriginDevice,
                      CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
}

void tst_crypto::generateKeyEncryptDecrypt()
{
    FETCH_CRYPTO_TEST_DATA;

    if (keyTemplate.algorithm() != CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    const bool pluginSupportsEncryption = keyTemplate.operations() & CryptoManager::OperationEncrypt;
    const bool pluginSupportsDecryption = keyTemplate.operations() & CryptoManager::OperationDecrypt;

    // test generating a symmetric cipher key
    QDBusPendingReply<Result, Key> reply = m_cmp.generateKey(
            keyTemplate,
            KeyPairGenerationParameters(),
            KeyDerivationParameters(),
            testRequests.value("generateKey").customerParameters,
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    Key fullKey = reply.argumentAt<1>();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    QByteArray encrypted;
    QByteArray authenticationTag;

    if (pluginSupportsEncryption) {
        // test encrypting some plaintext with the generated key
        QDBusPendingReply<Result, QByteArray, QByteArray> encryptReply = m_cmp.encrypt(
                plaintext,
                initVector,
                fullKey,
                blockMode,
                padding,
                authData,
                testRequests.value("encrypt").customerParameters,
                plugins.value(CryptoTest::CryptoPlugin));
        WAIT_FOR_DBUS_REPLY_SUCCEEDED(encryptReply);
        encrypted = encryptReply.argumentAt<1>();
        QVERIFY(!encrypted.isEmpty());
        QVERIFY(encrypted != plaintext);
        authenticationTag = encryptReply.argumentAt<2>();
        QCOMPARE(authenticationTag.isEmpty(), authData.isEmpty());
    }

    if (pluginSupportsDecryption) {
        // test decrypting the ciphertext, and ensure that the roundtrip works.
        QDBusPendingReply<Result, QByteArray, CryptoManager::VerificationStatus> decryptReply = m_cmp.decrypt(
                encrypted,
                initVector,
                fullKey,
                blockMode,
                padding,
                authData,
                authenticationTag,
                testRequests.value("decrypt").customerParameters,
                plugins.value(CryptoTest::CryptoPlugin));
        WAIT_FOR_DBUS_REPLY_SUCCEEDED(decryptReply);
        QByteArray decrypted = decryptReply.argumentAt<1>();
        CryptoManager::VerificationStatus verificationStatus = decryptReply.argumentAt<2>();
        QVERIFY(!decrypted.isEmpty());
        QCOMPARE(decrypted, plaintext);
        QCOMPARE(verificationStatus == CryptoManager::VerificationSucceeded, !authenticationTag.isEmpty());
    }
}

#include "tst_crypto.moc"
QTEST_MAIN(tst_crypto)
