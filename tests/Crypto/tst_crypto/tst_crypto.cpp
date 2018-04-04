/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QObject>
#include <QDBusReply>

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"
#include "Crypto/key.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/result.h"
#include "Crypto/x509certificate.h"

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
    void validateCertificateChain();

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

        QTest::newRow("CTR 128-bit") << CryptoManager::BlockModeCtr << 128;
        QTest::newRow("CTR 192-bit") << CryptoManager::BlockModeCtr << 192;
        QTest::newRow("CTR 256-bit") << CryptoManager::BlockModeCtr << 256;
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
    QDBusPendingReply<Result, QVector<CryptoPluginInfo>, QStringList> reply = cm.getPluginInfo();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
    QVector<CryptoPluginInfo> cryptoPlugins = reply.argumentAt<1>();
    QString cryptoPluginNames;
    for (auto p : cryptoPlugins) {
        cryptoPluginNames.append(p.name());
    }
    QVERIFY(cryptoPluginNames.size());
    QVERIFY(cryptoPluginNames.contains(CryptoManager::DefaultCryptoPluginName + QLatin1String(".test")));
}

void tst_crypto::randomData()
{
    // test generating random data
    QDBusPendingReply<Result, QByteArray> reply = cm.generateRandomData(
            2048,
            QLatin1String("default"),
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
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(seedReply);
    QVERIFY(seedReply.isValid());
    QCOMPARE(seedReply.argumentAt<0>().code(), Result::Succeeded);

    // ensure that we get different random data to the original set
    reply = cm.generateRandomData(
            2048,
            QLatin1String("default"),
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
    QFETCH(CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

    // test generating a symmetric cipher key
    Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    QDBusPendingReply<Result, Key> reply = cm.generateKey(
            keyTemplate,
            KeyPairGenerationParameters(),
            KeyDerivationParameters(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
    Key fullKey = reply.argumentAt<1>();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the generated key
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = (blockMode == CryptoManager::BlockModeEcb) ? "" : "0123456789abcdef";
    QDBusPendingReply<Result, QByteArray, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            initVector,
            fullKey,
            blockMode,
            CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().errorMessage(), QString());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Result, QByteArray, bool> decryptReply = cm.decrypt(
            encrypted,
            initVector,
            fullKey,
            blockMode,
            CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().errorMessage(), QString());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    bool verified = decryptReply.argumentAt<2>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);
    QVERIFY(!verified); // no authentication used in this test
}

void tst_crypto::validateCertificateChain()
{
    // TODO: do this test properly, this currently just tests datatype copy semantics
    QVector<Certificate> chain;
    X509Certificate cert;
    cert.setSignatureValue(QByteArray("testing"));
    chain << cert;

    QDBusPendingReply<Result, bool> reply = cm.validateCertificateChain(
            chain,
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Failed); // plugin doesn't support this operation yet. TODO.
}

#include "tst_crypto.moc"
QTEST_MAIN(tst_crypto)
