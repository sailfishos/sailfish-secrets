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
    Sailfish::Crypto::CryptoManager cm;
};

void tst_crypto::init()
{
}

void tst_crypto::cleanup()
{
}

void tst_crypto::getPluginInfo()
{
    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::CryptoPluginInfo>, QStringList> reply = cm.getPluginInfo();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QVector<Sailfish::Crypto::CryptoPluginInfo> cryptoPlugins = reply.argumentAt<1>();
    QVERIFY(cryptoPlugins.size());
    QCOMPARE(cryptoPlugins.first().name(), QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
}

void tst_crypto::generateKeyEncryptDecrypt()
{
    // test generating a symmetric cipher key
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setAlgorithm(Sailfish::Crypto::Key::Aes256);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setBlockModes(Sailfish::Crypto::Key::BlockModeCBC);
    keyTemplate.setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddingNone);
    keyTemplate.setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddingNone);
    keyTemplate.setDigests(Sailfish::Crypto::Key::DigestSha256);
    keyTemplate.setOperations(Sailfish::Crypto::Key::Encrypt | Sailfish::Crypto::Key::Decrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply = cm.generateKey(
            keyTemplate,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    Sailfish::Crypto::Key fullKey = reply.argumentAt<1>();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the generated key
    QByteArray plaintext = "Test plaintext data";
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            fullKey,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> decryptReply = cm.decrypt(
            encrypted,
            fullKey,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);
}

void tst_crypto::validateCertificateChain()
{
    // TODO: do this test properly, this currently just tests datatype copy semantics
    QVector<Sailfish::Crypto::Certificate> chain;
    Sailfish::Crypto::X509Certificate cert;
    cert.setSignatureValue(QByteArray("testing"));
    chain << cert;

    QDBusPendingReply<Sailfish::Crypto::Result, bool> reply = cm.validateCertificateChain(
            chain,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed); // plugin doesn't support this operation yet. TODO.
}

#include "tst_crypto.moc"
QTEST_MAIN(tst_crypto)
