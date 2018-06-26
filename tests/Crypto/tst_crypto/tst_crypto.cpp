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

using namespace Sailfish::Crypto;

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dbusreply)       \
    do {                                                    \
        int maxWait = 10000;                                \
        while (!dbusreply.isFinished() && maxWait > 0) {    \
            QTest::qWait(100);                              \
            maxWait -= 100;                                 \
        }                                                   \
    } while (0)

namespace {

inline QByteArray createRandomTestData(int size) {
    QFile file("/dev/urandom");
    file.open(QIODevice::ReadOnly);
    QByteArray result = file.read(size);
    file.close();
    return result;
}

inline QByteArray generateInitializationVector(Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                               Sailfish::Crypto::CryptoManager::BlockMode blockMode)
{
    if (algorithm != Sailfish::Crypto::CryptoManager::AlgorithmAes
            || blockMode == Sailfish::Crypto::CryptoManager::BlockModeEcb) {
        return QByteArray();
    }
    switch (blockMode) {
        case Sailfish::Crypto::CryptoManager::BlockModeGcm:
            return createRandomTestData(12);
        case Sailfish::Crypto::CryptoManager::BlockModeCcm:
            return createRandomTestData(7);
    default:
        break;
    }
    return createRandomTestData(16);
}

}


class tst_crypto : public QObject
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

private:
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

        QTest::newRow("AES GCM 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES GCM 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES GCM 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone << 256;

        QTest::newRow("AES CCM 128-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCcm << CryptoManager::EncryptionPaddingNone << 128;
        QTest::newRow("AES CCM 192-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCcm << CryptoManager::EncryptionPaddingNone << 192;
        QTest::newRow("AES CCM 256-bit") << CryptoManager::AlgorithmAes << CryptoManager::BlockModeCcm << CryptoManager::EncryptionPaddingNone << 256;
    }

    CryptoManagerPrivate cm;
};

void tst_crypto::init()
{
}

void tst_crypto::cleanup()
{
}

void tst_crypto::getPluginInfo()
{
    QDBusPendingReply<Result, QVector<PluginInfo>, QVector<PluginInfo>> reply = cm.getPluginInfo();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
    QVector<PluginInfo> cryptoPlugins = reply.argumentAt<1>();
    QString cryptoPluginNames;
    for (auto p : cryptoPlugins) {
        cryptoPluginNames.append(p.name());
    }
    QVERIFY(cryptoPluginNames.size());
}

void tst_crypto::randomData()
{
    // test generating random data
    QDBusPendingReply<Result, QByteArray> reply = cm.generateRandomData(
            2048,
            QLatin1String("default"),
            QVariantMap(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray randomData = reply.argumentAt<1>();
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
    QDBusPendingReply<Result> seedReply = cm.seedRandomDataGenerator(
            QByteArray("seed"),
            1.0,
            QLatin1String("default"),
            QVariantMap(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(seedReply);
    QVERIFY(seedReply.isValid());
    QCOMPARE(seedReply.argumentAt<0>().code(), Result::Succeeded);

    // ensure that we get different random data to the original set
    reply = cm.generateRandomData(
            2048,
            QLatin1String("default"),
            QVariantMap(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray seededData = reply.argumentAt<1>();
    QCOMPARE(seededData.size(), 2048);
    allNull = true;
    for (auto c : seededData) {
        if (c != '\0') {
            allNull = false;
            break;
        }
    }
    QVERIFY(!allNull);
    QVERIFY(seededData != randomData);
}

void tst_crypto::generateKeyEncryptDecrypt_data()
{
    addCryptoTestData();
}

void tst_crypto::generateKeyEncryptDecrypt()
{
    QFETCH(CryptoManager::Algorithm, algorithm);
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(CryptoManager::EncryptionPadding, padding);
    QFETCH(int, keySize);

    // test generating a symmetric cipher key
    Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(algorithm);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    QDBusPendingReply<Result, Key> reply = cm.generateKey(
            keyTemplate,
            KeyPairGenerationParameters(),
            KeyDerivationParameters(),
            QVariantMap(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
    Key fullKey = reply.argumentAt<1>();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the generated key
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QByteArray authData;
    if (blockMode == CryptoManager::BlockModeGcm
            || blockMode == CryptoManager::BlockModeCcm) {
        authData = "fedcba9876543210";
    }

    QDBusPendingReply<Result, QByteArray, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            initVector,
            fullKey,
            blockMode,
            padding,
            authData,
            QVariantMap(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().errorMessage(), QString());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);
    QByteArray authenticationTag = encryptReply.argumentAt<2>();
    QCOMPARE(authenticationTag.isEmpty(), authData.isEmpty());

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Result, QByteArray, CryptoManager::VerificationStatus> decryptReply = cm.decrypt(
            encrypted,
            initVector,
            fullKey,
            blockMode,
            padding,
            authData,
            authenticationTag,
            QVariantMap(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().errorMessage(), QString());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    CryptoManager::VerificationStatus verificationStatus = decryptReply.argumentAt<2>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);
    QCOMPARE(verificationStatus == CryptoManager::VerificationSucceeded, !authenticationTag.isEmpty());
}

#include "tst_crypto.moc"
QTEST_MAIN(tst_crypto)
