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
#include "Crypto/key.h"
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
    void generateKeyEncryptDecrypt();
    void validateCertificateChain();

private:
    CryptoManager cm;
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

void tst_crypto::generateKeyEncryptDecrypt()
{
    // test generating a symmetric cipher key
    Key keyTemplate;
    keyTemplate.setAlgorithm(Key::Aes256);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setBlockModes(Key::BlockModeCBC);
    keyTemplate.setEncryptionPaddings(Key::EncryptionPaddingNone);
    keyTemplate.setSignaturePaddings(Key::SignaturePaddingNone);
    keyTemplate.setDigests(Key::DigestSha256);
    keyTemplate.setOperations(Key::Encrypt | Key::Decrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    QDBusPendingReply<Result, Key> reply = cm.generateKey(
            keyTemplate,
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
    Key fullKey = reply.argumentAt<1>();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the generated key
    QByteArray plaintext = "Test plaintext data";
    QDBusPendingReply<Result, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            fullKey,
            Key::BlockModeCBC,
            Key::EncryptionPaddingNone,
            Key::DigestSha256,
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Result, QByteArray> decryptReply = cm.decrypt(
            encrypted,
            fullKey,
            Key::BlockModeCBC,
            Key::EncryptionPaddingNone,
            Key::DigestSha256,
            CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Result::Succeeded);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);
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
