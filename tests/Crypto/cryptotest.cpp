/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Bea Lam <bea.lam@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "cryptotest.h"

#include "Secrets/deletecollectionrequest.h"

#include <QtDebug>

using namespace Sailfish::Crypto;

CryptoTest::CryptoTest(QObject *parent)
    : QObject(parent)
    , m_devRandom(nullptr)
{
}

void CryptoTest::qtest_init()
{

}

void CryptoTest::qtest_cleanup()
{
    while (m_populatedCollections.size() > 0) {
        auto testCollection = m_populatedCollections.takeLast();
        QDBusPendingReply<Result> reply = m_smp.deleteCollection(
                    testCollection.name,
                    testCollection.storagePlugin,
                    testCollection.userInteractionMode);
        WAIT_FOR_DBUS_REPLY(reply);
    }
}

QByteArray CryptoTest::createRandomTestData(int size)
{
    if (!m_devRandom) {
        m_devRandom = new QFile("/dev/urandom", this);
        m_devRandom->open(QIODevice::ReadOnly);
    }
    if (m_devRandom->isOpen()) {
        return m_devRandom->read(size);
    }
    qWarning() << "Cannot open" << m_devRandom->fileName();
    return QByteArray();
}

QByteArray CryptoTest::generateInitializationVector(Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                                    Sailfish::Crypto::CryptoManager::BlockMode blockMode)
{
    if (algorithm != CryptoManager::AlgorithmAes || blockMode == CryptoManager::BlockModeEcb) {
        return QByteArray();
    }
    switch (blockMode) {
        case CryptoManager::BlockModeGcm:
            return createRandomTestData(12);
        case CryptoManager::BlockModeCcm:
            return createRandomTestData(7);
    default:
        break;
    }
    return createRandomTestData(16);
}

QByteArray CryptoTest::generateRsaPlaintext(Sailfish::Crypto::CryptoManager::EncryptionPadding padding, int keySize)
{
    if (padding == CryptoManager::EncryptionPaddingNone) {
        // Otherwise OpenSSL will complain about too small / too large data size.
        // See https://stackoverflow.com/questions/17746263/rsa-encryption-using-public-key-data-size-based-on-key
        QByteArray plaintext = createRandomTestData(keySize / 8 - 1);
        plaintext.prepend('\0');
        return plaintext;
    } else if (padding == CryptoManager::EncryptionPaddingRsaOaep) {
        // Otherwise OpenSSL will complain about too small / too large data size.
        return createRandomTestData(keySize / 32);
    }

    return createRandomTestData(42);
}

bool CryptoTest::allCharactersAreNull(const QString &s)
{
    for (auto c : s) {
        if (c != '\0') {
            return false;
        }
    }
    return true;
}

Sailfish::Crypto::Key CryptoTest::createTestKey(int keySize,
                                                Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                                Sailfish::Crypto::Key::Origin origins,
                                                Sailfish::Crypto::CryptoManager::Operations operations,
                                                Key::Identifier keyIdentifier)
{
    Key key;
    key.setSize(keySize);
    key.setAlgorithm(algorithm);
    key.setOrigin(origins);
    key.setOperations(operations);
    key.setFilterData(QLatin1String("test"), QLatin1String("true"));
    key.setIdentifier(keyIdentifier);
    return key;
}

void CryptoTest::addCryptoTestData(const TestPluginMap &plugins,
                                   Key::Origin keyOrigin,
                                   Sailfish::Crypto::CryptoManager::Operations operations,
                                   Key::Identifier keyIdentifier,
                                   const QByteArray &plaintext,
                                   const TestRequests &testRequests)
{
    QTest::addColumn<TestPluginMap>("plugins");
    QTest::addColumn<CryptoManager::BlockMode>("blockMode");
    QTest::addColumn<CryptoManager::EncryptionPadding>("padding");
    QTest::addColumn<Sailfish::Crypto::Key>("keyTemplate");

    QTest::addColumn<QByteArray>("authData");
    QTest::addColumn<QByteArray>("plaintext");
    QTest::addColumn<QByteArray>("initVector");
    QTest::addColumn<CryptoTest::TestRequests>("testRequests");

    QByteArray authData16 = createRandomTestData(16);
    QByteArray plaintextData = plaintext.isEmpty() ? "Test plaintext data" : plaintext;
    QByteArray initVector;


    // AES algorithm:

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeEcb);
    QTest::newRow("AES ECB 128-bit")
            << plugins << CryptoManager::BlockModeEcb << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES ECB 192-bit")
            << plugins << CryptoManager::BlockModeEcb << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES ECB 256-bit")
            << plugins << CryptoManager::BlockModeEcb << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeCbc);
    QTest::newRow("AES CBC 128-bit")
            << plugins << CryptoManager::BlockModeCbc << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CBC 192-bit")
            << plugins << CryptoManager::BlockModeCbc << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CBC 256-bit")
            << plugins << CryptoManager::BlockModeCbc << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeCfb1);
    QTest::newRow("AES CFB-1 128-bit")
            << plugins << CryptoManager::BlockModeCfb1 << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CFB-1 192-bit")
            << plugins << CryptoManager::BlockModeCfb1 << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CFB-1 256-bit")
            << plugins << CryptoManager::BlockModeCfb1 << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeCfb8);
    QTest::newRow("AES CFB-8 128-bit")
            << plugins << CryptoManager::BlockModeCfb8 << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CFB-8 192-bit")
            << plugins << CryptoManager::BlockModeCfb8 << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CFB-8 256-bit")
            << plugins << CryptoManager::BlockModeCfb8 << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeCfb128);
    QTest::newRow("AES CFB-128 128-bit")
            << plugins << CryptoManager::BlockModeCfb128 << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CFB-128 192-bit")
            << plugins << CryptoManager::BlockModeCfb128 << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CFB-128 256-bit")
            << plugins << CryptoManager::BlockModeCfb128 << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeOfb);
    QTest::newRow("AES OFB 128-bit")
            << plugins << CryptoManager::BlockModeOfb << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES OFB 192-bit")
            << plugins << CryptoManager::BlockModeOfb << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES OFB 256-bit")
            << plugins << CryptoManager::BlockModeOfb << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeCtr);
    QTest::newRow("AES CTR 128-bit")
            << plugins << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CTR 192-bit")
            << plugins << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;
    QTest::newRow("AES CTR 256-bit")
            << plugins << CryptoManager::BlockModeCtr << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << QByteArray() << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeGcm);
    QTest::newRow("AES GCM 128-bit")
            << plugins << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << authData16 << plaintextData << initVector << testRequests;
    QTest::newRow("AES GCM 192-bit")
            << plugins << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << authData16 << plaintextData << initVector << testRequests;
    QTest::newRow("AES GCM 256-bit")
            << plugins << CryptoManager::BlockModeGcm << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << authData16 << plaintextData << initVector << testRequests;

    initVector = generateInitializationVector(CryptoManager::AlgorithmAes, CryptoManager::BlockModeCcm);
    QTest::newRow("AES CCM 128-bit")
            << plugins << CryptoManager::BlockModeCcm << CryptoManager::EncryptionPaddingNone
            << createTestKey(128, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << authData16 << plaintextData << initVector << testRequests;
    QTest::newRow("AES CCM 192-bit")
            << plugins << CryptoManager::BlockModeCcm << CryptoManager::EncryptionPaddingNone
            << createTestKey(192, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << authData16 << plaintextData << initVector << testRequests;
    QTest::newRow("AES CCM 256-bit")
            << plugins << CryptoManager::BlockModeCcm << CryptoManager::EncryptionPaddingNone
            << createTestKey(256, CryptoManager::AlgorithmAes, keyOrigin, operations, keyIdentifier)
            << authData16 << plaintextData << initVector << testRequests;


    // RSA algorithm:

    initVector = generateInitializationVector(CryptoManager::AlgorithmRsa, CryptoManager::BlockModeUnknown);
    QTest::newRow("RSA 512-bit (no padding)")
            << plugins << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingNone
            << createTestKey(512, CryptoManager::AlgorithmRsa, keyOrigin, operations, keyIdentifier)
            << QByteArray() << generateRsaPlaintext(CryptoManager::EncryptionPaddingNone, 512) << QByteArray() << testRequests;
    QTest::newRow("RSA 512-bit (PKCS1 padding")
            << plugins << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaPkcs1
            << createTestKey(512, CryptoManager::AlgorithmRsa, keyOrigin, operations, keyIdentifier)
            << QByteArray() << generateRsaPlaintext(CryptoManager::EncryptionPaddingRsaPkcs1, 512) << QByteArray() << testRequests;
    QTest::newRow("RSA 512-bit (OAEP padding)")
            << plugins << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaOaep
            << createTestKey(512, CryptoManager::AlgorithmRsa, keyOrigin, operations, keyIdentifier)
            << QByteArray() << generateRsaPlaintext(CryptoManager::EncryptionPaddingRsaOaep, 512) << QByteArray() << testRequests;
    QTest::newRow("RSA 1024-bit (no padding)")
            << plugins << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingNone
            << createTestKey(1024, CryptoManager::AlgorithmRsa, keyOrigin, operations, keyIdentifier)
            << QByteArray() << generateRsaPlaintext(CryptoManager::EncryptionPaddingNone, 1024) << QByteArray() << testRequests;
    QTest::newRow("RSA 1024-bit (PKCS1 padding")
            << plugins << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaPkcs1
            << createTestKey(1024, CryptoManager::AlgorithmRsa, keyOrigin, operations, keyIdentifier)
            << QByteArray() << generateRsaPlaintext(CryptoManager::EncryptionPaddingRsaPkcs1, 1024) << QByteArray() << testRequests;
    QTest::newRow("RSA 1024-bit (OAEP padding)")
            << plugins << CryptoManager::BlockModeUnknown << CryptoManager::EncryptionPaddingRsaOaep
            << createTestKey(1024, CryptoManager::AlgorithmRsa, keyOrigin, operations, keyIdentifier)
            << QByteArray() << generateRsaPlaintext(CryptoManager::EncryptionPaddingRsaOaep, 1024) << QByteArray() << testRequests;

}
