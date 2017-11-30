/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

// This test requires linkage to both Crypto and Secrets APIs.

#include <QtTest>
#include <QObject>
#include <QDBusReply>

#include "Crypto/cryptomanager.h"
#include "Crypto/key.h"
#include "Crypto/result.h"
#include "Crypto/x509certificate.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dbusreply)       \
    do {                                                    \
        int maxWait = 10000;                                \
        while (!dbusreply.isFinished() && maxWait > 0) {    \
            QTest::qWait(100);                              \
            maxWait -= 100;                                 \
        }                                                   \
    } while (0)

class tst_cryptosecrets : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void getPluginInfo();
    void generateStoredKeyEncryptDecrypt();
    void generateCryptoStoredKeyEncryptDecrypt();

private:
    Sailfish::Crypto::CryptoManager cm;
    Sailfish::Secrets::SecretManager sm;
};

void tst_cryptosecrets::init()
{
}

void tst_cryptosecrets::cleanup()
{
}

void tst_cryptosecrets::getPluginInfo()
{
    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::CryptoPluginInfo>, QStringList> reply = cm.getPluginInfo();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QVector<Sailfish::Crypto::CryptoPluginInfo> cryptoPlugins = reply.argumentAt<1>();
    QVERIFY(cryptoPlugins.size());
    QCOMPARE(cryptoPlugins.first().name(), QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    QStringList storagePlugins = reply.argumentAt<2>();
    QVERIFY(storagePlugins.size());
    QVERIFY(storagePlugins.contains(QLatin1String("org.sailfishos.secrets.plugin.storage.sqlite")));
}

void tst_cryptosecrets::generateStoredKeyEncryptDecrypt()
{
    // test generating a symmetric cipher key and storing securely.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setAlgorithm(Sailfish::Crypto::Key::Aes256);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setBlockModes(Sailfish::Crypto::Key::BlockModeCBC);
    keyTemplate.setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddingNone);
    keyTemplate.setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddingNone);
    keyTemplate.setDigests(Sailfish::Crypto::Key::DigestSha256);
    keyTemplate.setOperations(Sailfish::Crypto::Key::Encrypt | Sailfish::Crypto::Key::Decrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // first, create the collection via the Secrets API.
    QDBusPendingReply<Sailfish::Secrets::Result> secretsreply = sm.createCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tst_cryptosecrets_gsked")));
    // note that the secret key data will never enter the client process address space.
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply = cm.generateStoredKey(
            keyTemplate,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"),
            QLatin1String("org.sailfishos.secrets.plugin.storage.sqlite"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    Sailfish::Crypto::Key keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            keyReference,
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
            keyReference,
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

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > filterReply = sm.findSecrets(
                keyTemplate.identifier().collectionName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 1);
    QCOMPARE(filterReply.argumentAt<1>().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(filterReply.argumentAt<1>().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    filterReply = sm.findSecrets(
                keyTemplate.identifier().collectionName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 0);

    // clean up by deleting the collection in which the secret is stored.
    secretsreply = sm.deleteCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    decryptReply = cm.decrypt(
            encrypted,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    secretsreply = sm.createCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    reply = cm.generateStoredKey(
                keyTemplate,
                QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"),
                QLatin1String("org.sailfishos.secrets.plugin.storage.sqlite"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    encryptReply = cm.encrypt(
            plaintext,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    decryptReply = cm.decrypt(
            encrypted,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // delete the key via deleteStoredKey, and test that the deletion worked.
    QDBusPendingReply<Sailfish::Crypto::Result> deleteKeyReply = cm.deleteStoredKey(
                keyReference.identifier());
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(deleteKeyReply);
    QVERIFY(deleteKeyReply.isValid());
    QCOMPARE(deleteKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);

    decryptReply = cm.decrypt(
            encrypted,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            QLatin1String("org.sailfishos.crypto.plugin.crypto.openssl"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = sm.getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName()),
            Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    secretsreply = sm.deleteCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_cryptosecrets::generateCryptoStoredKeyEncryptDecrypt()
{
    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setAlgorithm(Sailfish::Crypto::Key::Aes256);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setBlockModes(Sailfish::Crypto::Key::BlockModeCBC);
    keyTemplate.setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddingNone);
    keyTemplate.setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddingNone);
    keyTemplate.setDigests(Sailfish::Crypto::Key::DigestSha256);
    keyTemplate.setOperations(Sailfish::Crypto::Key::Encrypt | Sailfish::Crypto::Key::Decrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // first, create the collection via the Secrets API.
    QDBusPendingReply<Sailfish::Secrets::Result> secretsreply = sm.createCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName,
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply = cm.generateStoredKey(
            keyTemplate,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    Sailfish::Crypto::Key keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> decryptReply = cm.decrypt(
            encrypted,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > filterReply = sm.findSecrets(
                keyTemplate.identifier().collectionName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 1);
    QCOMPARE(filterReply.argumentAt<1>().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(filterReply.argumentAt<1>().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    filterReply = sm.findSecrets(
                keyTemplate.identifier().collectionName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 0);

    // clean up by deleting the collection in which the secret is stored.
    secretsreply = sm.deleteCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    decryptReply = cm.decrypt(
            encrypted,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    secretsreply = sm.createCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName,
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    reply = cm.generateStoredKey(
                keyTemplate,
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    encryptReply = cm.encrypt(
            plaintext,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    decryptReply = cm.decrypt(
            encrypted,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // delete the key via deleteStoredKey, and test that the deletion worked.
    QDBusPendingReply<Sailfish::Crypto::Result> deleteKeyReply = cm.deleteStoredKey(
                keyReference.identifier());
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(deleteKeyReply);
    QVERIFY(deleteKeyReply.isValid());
    QCOMPARE(deleteKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);

    decryptReply = cm.decrypt(
            encrypted,
            keyReference,
            Sailfish::Crypto::Key::BlockModeCBC,
            Sailfish::Crypto::Key::EncryptionPaddingNone,
            Sailfish::Crypto::Key::DigestSha256,
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = sm.getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName()),
            Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    secretsreply = sm.deleteCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::PreventUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}

#include "tst_cryptosecrets.moc"
QTEST_MAIN(tst_cryptosecrets)
