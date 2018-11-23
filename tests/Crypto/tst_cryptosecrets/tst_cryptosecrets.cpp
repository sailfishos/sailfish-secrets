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
#include <QFile>

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialization_p.h"
#include "Crypto/key.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/interactionparameters.h"
#include "Crypto/result.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialization_p.h"

#include "../cryptotest.h"

using namespace Sailfish::Crypto;

class tst_cryptosecrets : public CryptoTest
{
    Q_OBJECT

private slots:
    void init() { qtest_init(); }
    void cleanup() { qtest_cleanup(); }

    void getPluginInfo_data();
    void getPluginInfo();
    void secretsStoredKey_data();
    void secretsStoredKey();
    void cryptoStoredKey_data();
    void cryptoStoredKey();
};

void tst_cryptosecrets::getPluginInfo_data()
{
    QTest::addColumn<QStringList>("expectedStoragePlugins");

    QTest::newRow("DefaultPlugins")
            << (QStringList() << DEFAULT_TEST_STORAGE_PLUGIN << DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME << TEST_USB_TOKEN_PLUGIN_NAME);
}

void tst_cryptosecrets::getPluginInfo()
{
    QFETCH(QStringList, expectedStoragePlugins);

    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::PluginInfo>, QVector<Sailfish::Crypto::PluginInfo> > reply = m_cmp.getPluginInfo();
    WAIT_FOR_DBUS_REPLY(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);

    const QVector<Sailfish::Crypto::PluginInfo> cryptoPlugins = reply.argumentAt<1>();
    QStringList cryptoPluginNames;
    for (auto p : cryptoPlugins) {
        cryptoPluginNames.append(p.name());
    }
    QVERIFY(cryptoPluginNames.size());

    const QVector<Sailfish::Crypto::PluginInfo> storagePlugins = reply.argumentAt<2>();
    QStringList storagePluginNames;
    for (auto p : storagePlugins) {
        storagePluginNames.append(p.name());
    }
    QVERIFY(storagePluginNames.size() >= expectedStoragePlugins.size());
    for (const QString &expect : expectedStoragePlugins) {
        QVERIFY(storagePluginNames.contains(expect)
             || storagePluginNames.contains(PluginNameMapping::mappedPluginName(expect)));
    }
}

void tst_cryptosecrets::secretsStoredKey_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_STORAGE_PLUGIN);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_ENCRYPTION_PLUGIN);

    Sailfish::Crypto::Key::Identifier identifier(QStringLiteral("storedkey"),
                                                 QStringLiteral("tst_cryptosecrets_gsked"),
                                                 plugins.value(CryptoTest::StoragePlugin));

    addCryptoTestData(plugins, Key::OriginDevice, CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt, identifier);
}

void tst_cryptosecrets::secretsStoredKey()
{
    FETCH_CRYPTO_TEST_DATA;
    if (keyTemplate.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }
    if (blockMode == CryptoManager::BlockModeGcm || blockMode == CryptoManager::BlockModeCcm) {
        QSKIP("Authenticated modes are not supported by the current test.");
    }

    // test generating a symmetric cipher key and storing securely.

    // first, create the collection via the Secrets API.
    QDBusPendingReply<Sailfish::Secrets::Result> secretsreply = m_smp.createCollection(
                keyTemplate.identifier().collectionName(),
                plugins.value(CryptoTest::StoragePlugin),
                plugins.value(CryptoTest::EncryptionPlugin),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);
    m_populatedCollections.append({ keyTemplate.identifier().collectionName(), plugins.value(CryptoTest::StoragePlugin), Sailfish::Secrets::SecretManager::PreventInteraction});

    // note that the secret key data will never enter the client process address space.
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply = m_cmp.generateStoredKey(
            keyTemplate,
            Sailfish::Crypto::KeyPairGenerationParameters(),
            Sailfish::Crypto::KeyDerivationParameters(),
            Sailfish::Crypto::InteractionParameters(),
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    Sailfish::Crypto::Key keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> encryptReply = m_cmp.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            padding,
            QByteArray(),
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(encryptReply);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, Sailfish::Crypto::CryptoManager::VerificationStatus> decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(decryptReply);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > filterReply = m_smp.findSecrets(
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
    filterReply = m_smp.findSecrets(
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
    secretsreply = m_smp.deleteCollection(
                keyTemplate.identifier().collectionName(),
                plugins.value(CryptoTest::StoragePlugin),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_FAILED(decryptReply);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    secretsreply = m_smp.createCollection(
                keyTemplate.identifier().collectionName(),
                plugins.value(CryptoTest::StoragePlugin),
                plugins.value(CryptoTest::EncryptionPlugin),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);
    m_populatedCollections.append({ keyTemplate.identifier().collectionName(), plugins.value(CryptoTest::StoragePlugin), Sailfish::Secrets::SecretManager::PreventInteraction});

    reply = m_cmp.generateStoredKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                Sailfish::Crypto::KeyDerivationParameters(),
                Sailfish::Crypto::InteractionParameters(),
                QVariantMap(),
                plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    encryptReply = m_cmp.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            padding,
            QByteArray(),
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(encryptReply);
    encrypted = encryptReply.argumentAt<1>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(decryptReply);
    decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // delete the key via deleteStoredKey, and test that the deletion worked.
    QDBusPendingReply<Sailfish::Crypto::Result> deleteKeyReply = m_cmp.deleteStoredKey(
                keyReference.identifier());
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(deleteKeyReply);

    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            QByteArray(),
            QByteArray(),
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_FAILED(decryptReply);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = m_smp.getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName(),
                    keyReference.identifier().storagePluginName()),
            Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_DBUS_REPLY_FAILED(secretReply);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);
}

void tst_cryptosecrets::cryptoStoredKey_data()
{
    TestPluginMap plugins;
    plugins.insert(CryptoTest::CryptoPlugin, DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    plugins.insert(CryptoTest::StoragePlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    plugins.insert(CryptoTest::EncryptionPlugin, DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);

    Sailfish::Crypto::Key::Identifier identifier(QStringLiteral("storedkey"),
                                                 QStringLiteral("tstcryptosecretsgcsked"),
                                                 plugins.value(CryptoTest::StoragePlugin));

    addCryptoTestData(plugins, Key::OriginDevice, CryptoManager::OperationEncrypt | CryptoManager::OperationDecrypt, identifier);
}

void tst_cryptosecrets::cryptoStoredKey()
{
    FETCH_CRYPTO_TEST_DATA;
    if (keyTemplate.algorithm() != Sailfish::Crypto::CryptoManager::AlgorithmAes) {
        QSKIP("Only AES is supported by the current test.");
    }

    keyTemplate.setComponentConstraints(Sailfish::Crypto::Key::MetaData
                                      | Sailfish::Crypto::Key::PublicKeyData
                                      | Sailfish::Crypto::Key::PrivateKeyData);
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    // first, create the collection via the Secrets API.
    QDBusPendingReply<Sailfish::Secrets::Result> secretsreply = m_smp.createCollection(
                keyTemplate.identifier().collectionName(),
                plugins.value(CryptoTest::StoragePlugin),
                plugins.value(CryptoTest::EncryptionPlugin),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);
    m_populatedCollections.append({ keyTemplate.identifier().collectionName(), plugins.value(CryptoTest::StoragePlugin), Sailfish::Secrets::SecretManager::PreventInteraction});

    // note that the secret key data will never enter the client process address space.
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply = m_cmp.generateStoredKey(
            keyTemplate,
            Sailfish::Crypto::KeyPairGenerationParameters(),
            Sailfish::Crypto::KeyDerivationParameters(),
            Sailfish::Crypto::InteractionParameters(),
            QVariantMap(),
            plugins.value(CryptoTest::EncryptionPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    Sailfish::Crypto::Key keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, QByteArray> encryptReply = m_cmp.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            QVariantMap(),
            plugins.value(CryptoTest::EncryptionPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(encryptReply);
    QByteArray encrypted = encryptReply.argumentAt<1>();
    QByteArray authTag = encryptReply.argumentAt<2>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, Sailfish::Crypto::CryptoManager::VerificationStatus> decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            authTag,
            QVariantMap(),
            plugins.value(CryptoTest::StoragePlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(decryptReply);
    QByteArray decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > filterReply = m_smp.findSecrets(
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
    filterReply = m_smp.findSecrets(
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
    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> storedKeyReply = m_cmp.storedKey(
            keyReference.identifier(),
            Sailfish::Crypto::Key::MetaData,
            QVariantMap());
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QVERIFY(storedKeyReply.argumentAt<1>().customParameters().isEmpty());
    QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back public key data and custom parameters via a stored key request
    storedKeyReply = m_cmp.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData,
                QVariantMap());
        storedKeyReply.waitForFinished();
        QVERIFY(storedKeyReply.isValid());
        QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
        QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
        QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
        QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back the secret key data via a stored key request
    storedKeyReply = m_cmp.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData
                    | Sailfish::Crypto::Key::PrivateKeyData,
                QVariantMap());
        storedKeyReply.waitForFinished();
        QVERIFY(storedKeyReply.isValid());
        QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
        QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
        QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
        QVERIFY(!storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // clean up by deleting the collection in which the secret is stored.
    secretsreply = m_smp.deleteCollection(
                keyTemplate.identifier().collectionName(),
                plugins.value(CryptoTest::StoragePlugin),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            authTag,
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_FAILED(decryptReply);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    secretsreply = m_smp.createCollection(
                keyTemplate.identifier().collectionName(),
                plugins.value(CryptoTest::StoragePlugin),
                plugins.value(CryptoTest::StoragePlugin),
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);
    m_populatedCollections.append({ keyTemplate.identifier().collectionName(), plugins.value(CryptoTest::StoragePlugin), Sailfish::Secrets::SecretManager::PreventInteraction});

    reply = m_cmp.generateStoredKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                Sailfish::Crypto::KeyDerivationParameters(),
                Sailfish::Crypto::InteractionParameters(),
                QVariantMap(),
                plugins.value(CryptoTest::StoragePlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    encryptReply = m_cmp.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(encryptReply);
    encrypted = encryptReply.argumentAt<1>();
    authTag = encryptReply.argumentAt<2>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            authTag,
            QVariantMap(),
            plugins.value(CryptoTest::StoragePlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(decryptReply);
    decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // delete the key via deleteStoredKey, and test that the deletion worked.
    QDBusPendingReply<Sailfish::Crypto::Result> deleteKeyReply = m_cmp.deleteStoredKey(
                keyReference.identifier());
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(deleteKeyReply);

    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            authTag,
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_FAILED(decryptReply);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = m_smp.getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName(),
                    keyReference.identifier().storagePluginName()),
            Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_DBUS_REPLY_FAILED(secretReply);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    secretsreply = m_smp.deleteCollection(
                keyTemplate.identifier().collectionName(),
                plugins.value(CryptoTest::StoragePlugin),
                Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);

    // now test the case where the key is stored in a "normal" storage plugin rather than a crypto plugin.
    secretsreply = m_smp.createCollection(
                    QLatin1String("tstcryptosecretsgcsked2"),
                    plugins.value(CryptoTest::StoragePlugin),
                    plugins.value(CryptoTest::EncryptionPlugin),
                    Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                    Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(secretsreply);
    m_populatedCollections.append({ QLatin1String("tstcryptosecretsgcsked2"), plugins.value(CryptoTest::StoragePlugin), Sailfish::Secrets::SecretManager::PreventInteraction});

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(
                Sailfish::Crypto::Key::Identifier(
                    QLatin1String("storedkey2"),
                    QLatin1String("tstcryptosecretsgcsked2"),
                    plugins.value(CryptoTest::StoragePlugin)));
    reply = m_cmp.generateStoredKey(
                keyTemplate,
                Sailfish::Crypto::KeyPairGenerationParameters(),
                Sailfish::Crypto::KeyDerivationParameters(),
                Sailfish::Crypto::InteractionParameters(),
                QVariantMap(),
                plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply);
    keyReference = reply.argumentAt<1>();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());

    // test encrypting some plaintext with the stored key.
    encryptReply = m_cmp.encrypt(
            plaintext,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(encryptReply);
    encrypted = encryptReply.argumentAt<1>();
    authTag = encryptReply.argumentAt<2>();
    QVERIFY(!encrypted.isEmpty());
    QVERIFY(encrypted != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            authTag,
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(decryptReply);
    decrypted = decryptReply.argumentAt<1>();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(decrypted, plaintext);

    // ensure that we can get a reference to that Key via the Secrets API
    filter.clear();
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    filterReply = m_smp.findSecrets(
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
    filterReply = m_smp.findSecrets(
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
    storedKeyReply = m_cmp.storedKey(
            keyReference.identifier(),
            Sailfish::Crypto::Key::MetaData,
            QVariantMap());
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QVERIFY(storedKeyReply.argumentAt<1>().customParameters().isEmpty());
    QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back public key data and custom parameters via a stored key request
    storedKeyReply = m_cmp.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData,
                QVariantMap());
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
    QVERIFY(storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // and that we can read back the secret key data via a stored key request
    storedKeyReply = m_cmp.storedKey(
                keyReference.identifier(),
                Sailfish::Crypto::Key::MetaData
                    | Sailfish::Crypto::Key::PublicKeyData
                    | Sailfish::Crypto::Key::PrivateKeyData,
                QVariantMap());
    storedKeyReply.waitForFinished();
    QVERIFY(storedKeyReply.isValid());
    QCOMPARE(storedKeyReply.argumentAt<0>().code(), Sailfish::Crypto::Result::Succeeded);
    QCOMPARE(storedKeyReply.argumentAt<1>().algorithm(), keyTemplate.algorithm());
    QCOMPARE(storedKeyReply.argumentAt<1>().customParameters(), keyTemplate.customParameters());
    QVERIFY(!storedKeyReply.argumentAt<1>().secretKey().isEmpty());

    // delete the key via deleteStoredKey, and test that the deletion worked.
    deleteKeyReply = m_cmp.deleteStoredKey(
                keyReference.identifier());
    WAIT_FOR_DBUS_REPLY_SUCCEEDED(deleteKeyReply);

    decryptReply = m_cmp.decrypt(
            encrypted,
            initVector,
            keyReference,
            blockMode,
            padding,
            authData,
            authTag,
            QVariantMap(),
            plugins.value(CryptoTest::CryptoPlugin));
    WAIT_FOR_DBUS_REPLY_FAILED(decryptReply);
    QCOMPARE(decryptReply.argumentAt<0>().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    secretReply = m_smp.getSecret(
            Sailfish::Secrets::Secret::Identifier(
                    keyReference.identifier().name(),
                    keyReference.identifier().collectionName(),
                    keyReference.identifier().storagePluginName()),
            Sailfish::Secrets::SecretManager::PreventInteraction);
    WAIT_FOR_DBUS_REPLY_FAILED(secretReply);
    QCOMPARE(secretReply.argumentAt<0>().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);
}

#include "tst_cryptosecrets.moc"
QTEST_MAIN(tst_cryptosecrets)
