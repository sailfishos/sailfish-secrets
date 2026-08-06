/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "../../../daemon/SecretsImpl/masterkeymanager_p.h"
#include "../../../daemon/SecretsImpl/appsupportkeystore_p.h"

#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QLoggingCategory>
#include <QtTest/QTest>

using namespace Sailfish::Secrets::Daemon::ApiImpl;

Q_LOGGING_CATEGORY(lcSailfishSecretsDaemon,
                   "org.sailfishos.secrets.daemon", QtWarningMsg)

class tst_masterkey : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init();
    void cleanup();
    void envelopeRoundTrip();
    void envelopeRejectsMalformedInput();
    void derivationIsSeparatedAndIdentityBound();
    void opaqueReferenceRoundTrip();
    void alphaResetIsOneShot();
    void resetTransactionResumesAtEveryStage();

private:
    MasterKeyEnvelope envelope() const;
    QString testPath() const;
};

QString tst_masterkey::testPath() const
{
    return QStringLiteral("/tmp/secrets-tst-masterkey");
}

MasterKeyEnvelope tst_masterkey::envelope() const
{
    MasterKeyEnvelope result;
    result.sailfishUserId = 100000;
    result.secureUserId = Q_UINT64_C(0x1020304050607080);
    result.identityEpoch = QByteArray::fromHex("00112233445566778899aabbccddeeff");
    result.backendVersion = 4;
    result.keyMintKeyBlob = QByteArrayLiteral("opaque-keymint-key-blob");
    result.nonce = QByteArray::fromHex("000102030405060708090a0b");
    result.ciphertext = QByteArray(32, '\x5a');
    result.authenticationTag = QByteArray(16, '\xa5');
    return result;
}

void tst_masterkey::init()
{
    cleanup();
}

void tst_masterkey::cleanup()
{
    QDir(testPath()).removeRecursively();
    QDir(testPath() + QStringLiteral("-reset-v1-test")).removeRecursively();
    QDir(testPath() + QStringLiteral("-generation-v1-test")).removeRecursively();
}

void tst_masterkey::envelopeRoundTrip()
{
    const MasterKeyEnvelope expected = envelope();
    const QByteArray serialized = expected.serialize();
    QVERIFY(!serialized.isEmpty());

    MasterKeyEnvelope actual;
    QVERIFY(MasterKeyEnvelope::deserialize(serialized, &actual));
    QCOMPARE(actual.sailfishUserId, expected.sailfishUserId);
    QCOMPARE(actual.secureUserId, expected.secureUserId);
    QCOMPARE(actual.identityEpoch, expected.identityEpoch);
    QCOMPARE(actual.backendVersion, expected.backendVersion);
    QCOMPARE(actual.keyMintKeyBlob, expected.keyMintKeyBlob);
    QCOMPARE(actual.nonce, expected.nonce);
    QCOMPARE(actual.ciphertext, expected.ciphertext);
    QCOMPARE(actual.authenticationTag, expected.authenticationTag);
    QCOMPARE(actual.authenticatedData(), expected.authenticatedData());
}

void tst_masterkey::envelopeRejectsMalformedInput()
{
    const QByteArray serialized = envelope().serialize();
    QVERIFY(!serialized.isEmpty());

    MasterKeyEnvelope parsed;
    QVERIFY(!MasterKeyEnvelope::deserialize(QByteArray(), &parsed));
    QVERIFY(!MasterKeyEnvelope::deserialize(serialized.left(serialized.size() - 1), &parsed));
    QVERIFY(!MasterKeyEnvelope::deserialize(serialized + QByteArrayLiteral("trailing"), &parsed));

    QByteArray badMagic(serialized);
    badMagic[0] = static_cast<char>(badMagic.at(0) ^ 1);
    QVERIFY(!MasterKeyEnvelope::deserialize(badMagic, &parsed));

    MasterKeyEnvelope badEpoch = envelope();
    badEpoch.identityEpoch.chop(1);
    QVERIFY(badEpoch.serialize().isEmpty());
}

void tst_masterkey::derivationIsSeparatedAndIdentityBound()
{
    QByteArray root(32, '\x33');
    QByteArray bookkeeping;
    QByteArray device;
    QByteArray appSupport;
    QVERIFY(MasterKeyDerivation::derive(root, envelope(), &bookkeeping, &device,
                                        &appSupport));
    QCOMPARE(bookkeeping.size(), 64);
    QCOMPARE(device.size(), 32);
    QCOMPARE(appSupport.size(), 64);
    QVERIFY(bookkeeping != device.toHex());
    QVERIFY(bookkeeping != appSupport);
    QVERIFY(device.toHex() != appSupport);

    MasterKeyEnvelope changed = envelope();
    changed.identityEpoch[0] = static_cast<char>(changed.identityEpoch.at(0) ^ 1);
    QByteArray changedBookkeeping;
    QByteArray changedDevice;
    QVERIFY(MasterKeyDerivation::derive(root, changed,
                                        &changedBookkeeping, &changedDevice));
    QVERIFY(bookkeeping != changedBookkeeping);
    QVERIFY(device != changedDevice);

    MasterKeyDerivation::clear(&root);
    QVERIFY(root.isEmpty());
}

void tst_masterkey::opaqueReferenceRoundTrip()
{
    const AppSupportKeyReference expected = AppSupportKeyReference::create();
    QVERIFY(expected.isValid());
    const QByteArray serialized = expected.serialize();
    QCOMPARE(serialized.size(), int(AppSupportKeyReference::SerializedSize));

    AppSupportKeyReference actual;
    QVERIFY(AppSupportKeyReference::deserialize(serialized, &actual));
    QCOMPARE(actual.identifier, expected.identifier);

    QByteArray malformed = serialized;
    malformed[0] = static_cast<char>(malformed.at(0) ^ 1);
    QVERIFY(!AppSupportKeyReference::deserialize(malformed, &actual));
    QVERIFY(!AppSupportKeyReference::deserialize(serialized + QByteArray(1, '\0'), &actual));

    const AppSupportKeyReference second = AppSupportKeyReference::create();
    QVERIFY(second.isValid());
    QVERIFY(second.identifier != expected.identifier);
}

void tst_masterkey::alphaResetIsOneShot()
{
    QVERIFY(QDir().mkpath(testPath()));
    QFile alphaFile(testPath() + QStringLiteral("/alpha.db"));
    QVERIFY(alphaFile.open(QIODevice::WriteOnly));
    QCOMPARE(alphaFile.write("alpha", 5), qint64(5));
    alphaFile.close();

    MasterKeyStore store(testPath(), true);
    QString error;
    QVERIFY2(store.prepare(&error), qPrintable(error));
    QVERIFY(!QFile::exists(alphaFile.fileName()));
    QByteArray migrationTransaction;
    QCOMPARE(store.resetStage(&migrationTransaction, &error),
             MasterKeyStore::GenerationCommitted);
    QCOMPARE(store.generation(&error), quint64(1));
    QVERIFY2(store.acknowledgeReset(&error), qPrintable(error));
    QVERIFY2(store.acknowledgeAndroidReset(1, migrationTransaction, &error),
             qPrintable(error));
    QVERIFY2(store.finishReset(&error), qPrintable(error));

    QFile currentFile(testPath() + QStringLiteral("/current.db"));
    QVERIFY(currentFile.open(QIODevice::WriteOnly));
    currentFile.close();
    QVERIFY2(store.prepare(&error), qPrintable(error));
    QVERIFY(QFile::exists(currentFile.fileName()));
}

void tst_masterkey::resetTransactionResumesAtEveryStage()
{
    MasterKeyStore store(testPath(), true);
    QString error;
    QVERIFY2(store.prepare(&error), qPrintable(error));
    QByteArray migrationTransaction;
    QCOMPARE(store.resetStage(&migrationTransaction, &error),
             MasterKeyStore::GenerationCommitted);
    QVERIFY2(store.acknowledgeReset(&error), qPrintable(error));
    QVERIFY2(store.acknowledgeAndroidReset(1, migrationTransaction, &error),
             qPrintable(error));
    QVERIFY2(store.finishReset(&error), qPrintable(error));
    QVERIFY2(store.store(envelope(), &error), qPrintable(error));

    const QByteArray transaction = QByteArray::fromHex(
                "00112233445566778899aabbccddeeff");
    QVERIFY2(store.beginReset(transaction, &error), qPrintable(error));

    QByteArray actualTransaction;
    QCOMPARE(store.resetStage(&actualTransaction, &error), MasterKeyStore::ResetStarted);
    QCOMPARE(actualTransaction, transaction);

    MasterKeyStore resumed(testPath(), true);
    QVERIFY2(resumed.deleteForReset(&error), qPrintable(error));
    QCOMPARE(resumed.resetStage(&actualTransaction, &error), MasterKeyStore::StorageDeleted);
    MasterKeyEnvelope absent;
    QVERIFY2(resumed.load(&absent, &error), qPrintable(error));
    QVERIFY(!absent.isValid());

    QVERIFY2(resumed.deleteForReset(&error), qPrintable(error));
    quint64 generation = 0;
    QVERIFY2(resumed.commitResetGeneration(&generation, &error), qPrintable(error));
    QCOMPARE(generation, quint64(2));
    quint64 repeatedGeneration = 0;
    QVERIFY2(resumed.commitResetGeneration(&repeatedGeneration, &error),
             qPrintable(error));
    QCOMPARE(repeatedGeneration, generation);
    QVERIFY2(resumed.acknowledgeReset(&error), qPrintable(error));
    QCOMPARE(resumed.resetStage(&actualTransaction, &error), MasterKeyStore::LifecycleAcknowledged);
    QVERIFY2(resumed.acknowledgeAndroidReset(generation, transaction, &error),
             qPrintable(error));
    QCOMPARE(resumed.resetStage(&actualTransaction, &error), MasterKeyStore::AndroidAcknowledged);
    QVERIFY2(resumed.finishReset(&error), qPrintable(error));
    QCOMPARE(resumed.resetStage(&actualTransaction, &error), MasterKeyStore::NoReset);
}

QTEST_APPLESS_MAIN(tst_masterkey)

#include "tst_masterkey.moc"
