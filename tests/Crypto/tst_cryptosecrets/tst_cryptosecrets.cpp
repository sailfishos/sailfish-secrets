/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

// This test requires linkage to both Crypto and Secrets APIs.

#include <QtTest>
#include <QObject>
#include <QVariantMap>
#include <QDBusReply>

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"
#include "Crypto/key.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/interactionparameters.h"
#include "Crypto/result.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dbusreply)       \
    do {                                                    \
        int maxWait = 10000;                                \
        while (!dbusreply.isFinished() && maxWait > 0) {    \
            QTest::qWait(100);                              \
            maxWait -= 100;                                 \
        }                                                   \
    } while (0)

class TestSecretManager : public Sailfish::Secrets::SecretManager
{
    Q_OBJECT

public:
    TestSecretManager(QObject *parent = Q_NULLPTR)
        : Sailfish::Secrets::SecretManager(parent) {}
    ~TestSecretManager() {}
    Sailfish::Secrets::SecretManagerPrivate *d_ptr() const { return Sailfish::Secrets::SecretManager::pimpl(); }
};

class tst_cryptosecrets : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void getPluginInfo();
    void secretsStoredKey_data();
    void secretsStoredKey();
    void cryptoStoredKey_data();
    void cryptoStoredKey();

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
        QTest::addColumn<Sailfish::Crypto::CryptoManager::BlockMode>("blockMode");
        QTest::addColumn<int>("keySize");

        QTest::newRow("ECB 128-bit") << Sailfish::Crypto::CryptoManager::BlockModeEcb << 128;
        QTest::newRow("ECB 192-bit") << Sailfish::Crypto::CryptoManager::BlockModeEcb << 192;
        QTest::newRow("ECB 256-bit") << Sailfish::Crypto::CryptoManager::BlockModeEcb << 256;

        QTest::newRow("CBC 128-bit") << Sailfish::Crypto::CryptoManager::BlockModeCbc << 128;
        QTest::newRow("CBC 192-bit") << Sailfish::Crypto::CryptoManager::BlockModeCbc << 192;
        QTest::newRow("CBC 256-bit") << Sailfish::Crypto::CryptoManager::BlockModeCbc << 256;

        QTest::newRow("CFB-1 128-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb1 << 128;
        QTest::newRow("CFB-1 192-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb1 << 192;
        QTest::newRow("CFB-1 256-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb1 << 256;

        QTest::newRow("CFB-8 128-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb8 << 128;
        QTest::newRow("CFB-8 192-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb8 << 192;
        QTest::newRow("CFB-8 256-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb8 << 256;

        QTest::newRow("CFB-128 128-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb128 << 128;
        QTest::newRow("CFB-128 192-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb128 << 192;
        QTest::newRow("CFB-128 256-bit") << Sailfish::Crypto::CryptoManager::BlockModeCfb128 << 256;

        QTest::newRow("OFB 128-bit") << Sailfish::Crypto::CryptoManager::BlockModeOfb << 128;
        QTest::newRow("OFB 192-bit") << Sailfish::Crypto::CryptoManager::BlockModeOfb << 192;
        QTest::newRow("OFB 256-bit") << Sailfish::Crypto::CryptoManager::BlockModeOfb << 256;

        QTest::newRow("CTR 128-bit") << Sailfish::Crypto::CryptoManager::CryptoManager::BlockModeCtr << 128;
        QTest::newRow("CTR 192-bit") << Sailfish::Crypto::CryptoManager::CryptoManager::BlockModeCtr << 192;
        QTest::newRow("CTR 256-bit") << Sailfish::Crypto::CryptoManager::CryptoManager::BlockModeCtr << 256;
    }

    Sailfish::Crypto::CryptoManagerPrivate cm;
    TestSecretManager sm;
};

void tst_cryptosecrets::init()
{
}

void tst_cryptosecrets::cleanup()
{
}

void tst_cryptosecrets::getPluginInfo()
{
    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::PluginInfo>, QVector<Sailfish::Crypto::PluginInfo> > reply = cm.getPluginInfo();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);

    QVector<Sailfish::Crypto::PluginInfo> cryptoPlugins = reply.argumentAt<1>();
    QStringList cryptoPluginNames;
    for (auto p : cryptoPlugins) {
        cryptoPluginNames.append(p.name());
    }
    QVERIFY(cryptoPluginNames.size());
    QVERIFY(cryptoPluginNames.contains(Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test")));
    QVERIFY(cryptoPluginNames.contains(Sailfish::Crypto::CryptoManager::DefaultCryptoStoragePluginName + QLatin1String(".test")));

    QVector<Sailfish::Crypto::PluginInfo> storagePlugins = reply.argumentAt<2>();
    QStringList storagePluginNames;
    for (auto p : storagePlugins) {
        storagePluginNames.append(p.name());
    }
    QVERIFY(storagePluginNames.size());
    QVERIFY(storagePluginNames.contains(Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
}

void tst_cryptosecrets::secretsStoredKey_data()
{
    addCryptoTestData();
}

void tst_cryptosecrets::secretsStoredKey()
{
    QFETCH(Sailfish::Crypto::CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

    // test generating a symmetric cipher key and storing securely.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // first, create the collection via the Secrets API.
    QDBusPendingReply<Sailfish::Secrets::Result> secretsreply = sm.d_ptr()->createCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(
                                  QLatin1String("storedkey"),
                                  QLatin1String("tst_cryptosecrets_gsked"),
                                  Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    // note that the secret key data will never enter the client process address space.
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply = cm.generateStoredKey(
            keyTemplate,
            Sailfish::Crypto::KeyPairGenerationParameters(),
            Sailfish::Crypto::KeyDerivationParameters(),
            Sailfish::Crypto::InteractionParameters(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    Sailfish::Crypto::Key keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, bool> decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > filterReply = sm.d_ptr()->findSecrets(
                keyTemplate.identifier().collectionName(),
                keyTemplate.identifier().storagePluginName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 1);
    QCOMPARE(filterReply.argumentAt<1>().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(filterReply.argumentAt<1>().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    filterReply = sm.d_ptr()->findSecrets(
                keyTemplate.identifier().collectionName(),
                keyTemplate.identifier().storagePluginName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 0);

    // clean up by deleting the collection in which the secret is stored.
    secretsreply = sm.d_ptr()->deleteCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    secretsreply = sm.d_ptr()->createCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    reply = cm.generateStoredKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                Sailfish::Crypto::KeyDerivationParameters(),
                Sailfish::Crypto::InteractionParameters(),
                QVariantMap(),
                Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    encryptReply = cm.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
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
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = sm.d_ptr()->getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName(),
                    keyReference.identifier().storagePluginName()),
            Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    secretsreply = sm.d_ptr()->deleteCollection(
                QLatin1String("tst_cryptosecrets_gsked"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_cryptosecrets::cryptoStoredKey_data()
{
    addCryptoTestData();
}

void tst_cryptosecrets::cryptoStoredKey()
{
    QFETCH(Sailfish::Crypto::CryptoManager::BlockMode, blockMode);
    QFETCH(int, keySize);

    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setSize(keySize);
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);
    keyTemplate.setComponentConstraints(Sailfish::Crypto::Key::MetaData
                                      | Sailfish::Crypto::Key::PublicKeyData
                                      | Sailfish::Crypto::Key::PrivateKeyData);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    // first, create the collection via the Secrets API.
    QDBusPendingReply<Sailfish::Secrets::Result> secretsreply = sm.d_ptr()->createCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(
                Sailfish::Crypto::Key::Identifier(
                          QLatin1String("storedkey"),
                          QLatin1String("tstcryptosecretsgcsked"),
                          Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")));
    // note that the secret key data will never enter the client process address space.
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply = cm.generateStoredKey(
            keyTemplate,
            Sailfish::Crypto::KeyPairGenerationParameters(),
            Sailfish::Crypto::KeyDerivationParameters(),
            Sailfish::Crypto::InteractionParameters(),
            QVariantMap(),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    Sailfish::Crypto::Key keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    QByteArray initVector = generateInitializationVector(keyTemplate.algorithm(), blockMode);
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, QByteArray> encryptReply = cm.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QVariantMap(),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, bool> decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().errorMessage(), QString());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > filterReply = sm.d_ptr()->findSecrets(
                keyTemplate.identifier().collectionName(),
                keyTemplate.identifier().storagePluginName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 1);
    QCOMPARE(filterReply.argumentAt<1>().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(filterReply.argumentAt<1>().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    filterReply = sm.d_ptr()->findSecrets(
                keyTemplate.identifier().collectionName(),
                keyTemplate.identifier().storagePluginName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 0);

    // ensure that we can get a reference via a stored key request
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> storedKeyReply = cm.storedKey(
            keyReference.identifier(),
            Sailfish::Crypto::Key::MetaData);
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QVERIFY(storedKeyReply.argumentAt<1>().customParameters().isEmpty());
    QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back public key data and custom parameters via a stored key request
    storedKeyReply = cm.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData);
        storedKeyReply.waitForFinished();
        QVERIFY(storedKeyReply.isValid());
        QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
        QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
        QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
        QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back the secret key data via a stored key request
    storedKeyReply = cm.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData
                    | Sailfish::Crypto::Key::PrivateKeyData);
        storedKeyReply.waitForFinished();
        QVERIFY(storedKeyReply.isValid());
        QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
        QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
        QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
        QVERIFY(!storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // clean up by deleting the collection in which the secret is stored.
    secretsreply = sm.d_ptr()->deleteCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    secretsreply = sm.d_ptr()->createCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    reply = cm.generateStoredKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                Sailfish::Crypto::KeyDerivationParameters(),
                Sailfish::Crypto::InteractionParameters(),
                QVariantMap(),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    encryptReply = cm.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QVariantMap(),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
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
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = sm.d_ptr()->getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName(),
                    keyReference.identifier().storagePluginName()),
            Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    secretsreply = sm.d_ptr()->deleteCollection(
                QLatin1String("tstcryptosecretsgcsked"),
                Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // now test the case where the key is stored in a "normal" storage plugin rather than a crypto plugin.
    secretsreply = sm.d_ptr()->createCollection(
                    QLatin1String("tstcryptosecretsgcsked2"),
                    Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                    Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                    Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                    Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(
                Sailfish::Crypto::Key::Identifier(
                    QLatin1String("storedkey2"),
                    QLatin1String("tstcryptosecretsgcsked2"),
                    Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    reply = cm.generateStoredKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                Sailfish::Crypto::KeyDerivationParameters(),
                Sailfish::Crypto::InteractionParameters(),
                QVariantMap(),
                Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    encryptReply = cm.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(encryptReply);
    QVERIFY(encryptReply.isValid());
    QCOMPARE(encryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // ensure that we can get a reference to that Key via the Secrets API
    filter.clear();
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    filterReply = sm.d_ptr()->findSecrets(
                keyTemplate.identifier().collectionName(),
                keyTemplate.identifier().storagePluginName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 1);
    QCOMPARE(filterReply.argumentAt<1>().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(filterReply.argumentAt<1>().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    filterReply = sm.d_ptr()->findSecrets(
                keyTemplate.identifier().collectionName(),
                keyTemplate.identifier().storagePluginName(),
                filter,
                Sailfish::Secrets::SecretManager::OperatorAnd,
                Sailfish::Secrets::SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 0);

    // ensure that we can get a reference via a stored key request
    storedKeyReply = cm.storedKey(
            keyReference.identifier(),
            Sailfish::Crypto::Key::MetaData);
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QVERIFY(storedKeyReply.argumentAt<1>().customParameters().isEmpty());
    QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back public key data and custom parameters via a stored key request
    storedKeyReply = cm.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData);
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
    QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back the secret key data via a stored key request
    storedKeyReply = cm.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData
                    | Sailfish::Crypto::Key::PrivateKeyData);
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
    QVERIFY(!storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // delete the key via deleteStoredKey, and test that the deletion worked.
    deleteKeyReply = cm.deleteStoredKey(
                keyReference.identifier());
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(deleteKeyReply);
    QVERIFY(deleteKeyReply.isValid());
    QCOMPARE(deleteKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);

    decryptReply = cm.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPaddingNone,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName + QLatin1String(".test"));
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(decryptReply);
    QVERIFY(decryptReply.isValid());
    QCOMPARE(decryptReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    secretReply = sm.d_ptr()->getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName(),
                    keyReference.identifier().storagePluginName()),
            Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    secretsreply = sm.d_ptr()->deleteCollection(
                QLatin1String("tstcryptosecretsgcsked2"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretsreply);
    QVERIFY(secretsreply.isValid());
    QCOMPARE(secretsreply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}

#include "tst_cryptosecrets.moc"
QTEST_MAIN(tst_cryptosecrets)
