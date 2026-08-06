/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "masterkeymanager_p.h"

#include "dataprotector_p.h"

#include <QtCore/QBuffer>
#include <QtCore/QDataStream>
#include <QtCore/QDir>
#include <QtCore/QFile>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

namespace {

const QByteArray EnvelopeMagic("SFSMKEY1", 8);
const QByteArray FormatMarker(QByteArrayLiteral("sailfish-secrets-keymint-v1\n"));
const QByteArray ResetMagic("SFRESET1", 8);
const QByteArray GenerationMagic("SFSGEN01", 8);
const int RootKeySize = 32;
const int MaximumEnvelopeSize = 1024 * 1024;
const quint32 MaximumBlobSize = 1024 * 1024;

void appendBlob(QDataStream *stream, const QByteArray &blob)
{
    *stream << quint32(blob.size());
    if (!blob.isEmpty()) {
        stream->writeRawData(blob.constData(), blob.size());
    }
}

bool readBlob(QDataStream *stream, QByteArray *blob, quint32 maximumSize)
{
    quint32 size = 0;
    *stream >> size;
    if (stream->status() != QDataStream::Ok || size > maximumSize) {
        return false;
    }
    blob->resize(static_cast<int>(size));
    return size == 0
            || stream->readRawData(blob->data(), static_cast<int>(size)) == static_cast<int>(size);
}

QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    unsigned int outputSize = EVP_MAX_MD_SIZE;
    unsigned char output[EVP_MAX_MD_SIZE];
    if (!HMAC(EVP_sha256(), key.constData(), key.size(),
              reinterpret_cast<const unsigned char *>(data.constData()), data.size(),
              output, &outputSize)) {
        return QByteArray();
    }
    return QByteArray(reinterpret_cast<const char *>(output), static_cast<int>(outputSize));
}

QByteArray hkdfExpand(const QByteArray &pseudoRandomKey,
                      const QByteArray &info,
                      int outputSize)
{
    QByteArray output;
    QByteArray previous;
    quint8 counter = 1;
    while (output.size() < outputSize && counter != 0) {
        QByteArray input(previous);
        input.append(info);
        input.append(static_cast<char>(counter));
        previous = hmacSha256(pseudoRandomKey, input);
        if (previous.size() != 32) {
            return QByteArray();
        }
        output.append(previous);
        ++counter;
    }
    output.truncate(outputSize);
    OPENSSL_cleanse(previous.data(), previous.size());
    return output;
}

QString dataProtectorError(const QString &operation,
                           Sailfish::Secrets::Daemon::ApiImpl::DataProtector::Status status)
{
    return QStringLiteral("%1 failed with DataProtector status %2").arg(operation).arg(status);
}

} // namespace

using namespace Sailfish::Secrets::Daemon::ApiImpl;

bool MasterKeyEnvelope::isValid() const
{
    return sailfishUserId != 0
            && secureUserId != 0
            && identityEpoch.size() == IdentityEpochSize
            && backendVersion != 0
            && !keyMintKeyBlob.isEmpty()
            && keyMintKeyBlob.size() <= static_cast<int>(MaximumBlobSize)
            && !nonce.isEmpty() && nonce.size() <= 32
            && ciphertext.size() == RootKeySize
            && !authenticationTag.isEmpty() && authenticationTag.size() <= 32;
}

QByteArray MasterKeyEnvelope::authenticatedData() const
{
    QByteArray result;
    QDataStream stream(&result, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    stream.writeRawData(EnvelopeMagic.constData(), EnvelopeMagic.size());
    stream << quint16(CurrentVersion) << quint16(0);
    stream << sailfishUserId << secureUserId << backendVersion;
    appendBlob(&stream, identityEpoch);
    appendBlob(&stream, keyMintKeyBlob);
    appendBlob(&stream, nonce);
    return stream.status() == QDataStream::Ok ? result : QByteArray();
}

QByteArray MasterKeyEnvelope::serialize() const
{
    if (!isValid()) {
        return QByteArray();
    }

    QByteArray result = authenticatedData();
    QBuffer buffer(&result);
    if (!buffer.open(QIODevice::Append)) {
        return QByteArray();
    }
    QDataStream stream(&buffer);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    appendBlob(&stream, ciphertext);
    appendBlob(&stream, authenticationTag);
    return stream.status() == QDataStream::Ok ? result : QByteArray();
}

bool MasterKeyEnvelope::deserialize(const QByteArray &data, MasterKeyEnvelope *envelope)
{
    if (!envelope || data.isEmpty() || data.size() > MaximumEnvelopeSize) {
        return false;
    }

    QByteArray input(data);
    QDataStream stream(&input, QIODevice::ReadOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);

    char magic[8];
    quint16 version = 0;
    quint16 reserved = 0;
    MasterKeyEnvelope parsed;
    if (stream.readRawData(magic, sizeof(magic)) != sizeof(magic)
            || QByteArray(magic, sizeof(magic)) != EnvelopeMagic) {
        return false;
    }
    stream >> version >> reserved;
    stream >> parsed.sailfishUserId >> parsed.secureUserId >> parsed.backendVersion;
    if (version != CurrentVersion || reserved != 0
            || !readBlob(&stream, &parsed.identityEpoch, IdentityEpochSize)
            || !readBlob(&stream, &parsed.keyMintKeyBlob, MaximumBlobSize)
            || !readBlob(&stream, &parsed.nonce, 32)
            || !readBlob(&stream, &parsed.ciphertext, RootKeySize)
            || !readBlob(&stream, &parsed.authenticationTag, 32)
            || stream.status() != QDataStream::Ok
            || !stream.atEnd()
            || !parsed.isValid()) {
        return false;
    }

    *envelope = parsed;
    return true;
}

QByteArray MasterKeyDerivation::randomRootKey()
{
    QFile random(QStringLiteral("/dev/urandom"));
    if (!random.open(QIODevice::ReadOnly)) {
        return QByteArray();
    }
    const QByteArray key = random.read(RootKeySize);
    return key.size() == RootKeySize ? key : QByteArray();
}

bool MasterKeyDerivation::derive(const QByteArray &rootKey,
                                 const MasterKeyEnvelope &envelope,
                                 QByteArray *bookkeepingDatabaseKey,
                                 QByteArray *deviceLockKey,
                                 QByteArray *appSupportDatabaseKey)
{
    if (rootKey.size() != RootKeySize || !envelope.isValid()
            || !bookkeepingDatabaseKey || !deviceLockKey) {
        return false;
    }

    const QByteArray salt = hmacSha256(
                QByteArrayLiteral("sailfish-secrets-masterkey-v1"),
                envelope.authenticatedData());
    QByteArray pseudoRandomKey = hmacSha256(salt, rootKey);
    QByteArray bookkeeping = hkdfExpand(
                pseudoRandomKey,
                QByteArrayLiteral("sailfish-secrets/bookkeeping-db/v1"), RootKeySize);
    QByteArray device = hkdfExpand(
                pseudoRandomKey,
                QByteArrayLiteral("sailfish-secrets/device-lock/v1"), RootKeySize);
    QByteArray appSupport;
    if (appSupportDatabaseKey) {
        appSupport = hkdfExpand(
                    pseudoRandomKey,
                    QByteArrayLiteral("sailfish-secrets/appsupport-db/v1"), RootKeySize);
    }
    if (bookkeeping.size() != RootKeySize || device.size() != RootKeySize
            || (appSupportDatabaseKey && appSupport.size() != RootKeySize)) {
        clear(&bookkeeping);
        clear(&device);
        clear(&appSupport);
        clear(&pseudoRandomKey);
        return false;
    }

    *bookkeepingDatabaseKey = bookkeeping.toHex();
    *deviceLockKey = device;
    if (appSupportDatabaseKey) {
        *appSupportDatabaseKey = appSupport.toHex();
    }
    clear(&bookkeeping);
    clear(&appSupport);
    clear(&pseudoRandomKey);
    return true;
}

void MasterKeyDerivation::clear(QByteArray *data)
{
    if (!data) {
        return;
    }
    if (!data->isEmpty()) {
        OPENSSL_cleanse(data->data(), data->size());
    }
    data->clear();
}

MasterKeyStore::MasterKeyStore(const QString &secretsPath, bool autotestMode)
    : m_secretsPath(secretsPath)
    , m_formatPath(QDir(secretsPath).absoluteFilePath(
                       autotestMode ? QStringLiteral("keymint-format-test")
                                    : QStringLiteral("keymint-format")))
    , m_envelopePath(QDir(secretsPath).absoluteFilePath(
                         autotestMode ? QStringLiteral("masterkey-v1-test")
                                      : QStringLiteral("masterkey-v1")))
    , m_resetPath(secretsPath + (autotestMode
                                ? QStringLiteral("-reset-v1-test")
                                : QStringLiteral("-reset-v1")))
    , m_generationPath(secretsPath + (autotestMode
                                     ? QStringLiteral("-generation-v1-test")
                                     : QStringLiteral("-generation-v1")))
{
}

bool MasterKeyStore::prepare(QString *errorMessage)
{
    QByteArray marker;
    DataProtector protector(m_formatPath);
    const DataProtector::Status status = protector.getData(&marker);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Reading master-key format"), status);
        }
        return false;
    }
    if (!marker.isEmpty() && marker != FormatMarker) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unknown Sailfish Secrets master-key format");
        }
        return false;
    }

    if (marker.isEmpty()) {
        // Data written before the KeyMint-backed format was alpha data and
        // has no safe migration path.  Reset only this user's exact Secrets
        // directory, then durably mark the new format.
        QDir oldStore(m_secretsPath);
        if (oldStore.exists() && !oldStore.removeRecursively()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to reset alpha Sailfish Secrets data");
            }
            return false;
        }
        if (!QDir().mkpath(m_secretsPath) || !writeFormatMarker(errorMessage)) {
            return false;
        }
    }

    QByteArray generationTransaction;
    QString generationError;
    quint64 currentGeneration = generation(&generationError, &generationTransaction);
    if (!generationError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = generationError;
        }
        return false;
    }

    QByteArray resetTransaction;
    QString resetError;
    const ResetStage stage = resetStage(&resetTransaction, &resetError);
    if (!resetError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = resetError;
        }
        return false;
    }

    if (currentGeneration == 0) {
        QByteArray random = MasterKeyDerivation::randomRootKey();
        const QByteArray transactionId = random.left(16);
        MasterKeyDerivation::clear(&random);
        if (transactionId.size() != 16
                || !writeGeneration(1, transactionId, errorMessage)
                || !writeResetState(GenerationCommitted, transactionId,
                                    AlphaMigrationReset, errorMessage)) {
            return false;
        }
    } else if (!generationTransaction.isEmpty() && stage == NoReset) {
        // Recover a crash after committing the initial generation but before
        // committing its migration-reset marker.
        if (!writeResetState(GenerationCommitted, generationTransaction,
                             AlphaMigrationReset, errorMessage)) {
            return false;
        }
    }
    return true;
}

bool MasterKeyStore::load(MasterKeyEnvelope *envelope, QString *errorMessage) const
{
    QByteArray serialized;
    DataProtector protector(m_envelopePath);
    const DataProtector::Status status = protector.getData(&serialized);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Reading master-key envelope"), status);
        }
        return false;
    }
    if (serialized.isEmpty()) {
        *envelope = MasterKeyEnvelope();
        return true;
    }
    if (!MasterKeyEnvelope::deserialize(serialized, envelope)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid Sailfish Secrets master-key envelope");
        }
        return false;
    }
    return true;
}

bool MasterKeyStore::store(const MasterKeyEnvelope &envelope, QString *errorMessage)
{
    const QByteArray serialized = envelope.serialize();
    if (serialized.isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Refusing to store an invalid master-key envelope");
        }
        return false;
    }
    DataProtector protector(m_envelopePath);
    const DataProtector::Status status = protector.putData(serialized);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Writing master-key envelope"), status);
        }
        return false;
    }
    return true;
}

bool MasterKeyStore::beginReset(const QByteArray &transactionId,
                                QString *errorMessage,
                                ResetReason reason)
{
    if (transactionId.size() != 16) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid reset transaction id");
        }
        return false;
    }

    QByteArray currentTransaction;
    QString stageError;
    ResetReason currentReason = CredentialRemovalReset;
    const ResetStage currentStage = resetStage(&currentTransaction, &stageError,
                                               &currentReason);
    if (!stageError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = stageError;
        }
        return false;
    }
    if (currentStage != NoReset && currentTransaction != transactionId) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("A different reset transaction is already pending");
        }
        return false;
    }
    if (currentStage != NoReset && currentReason != reason) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Reset transaction reason changed");
        }
        return false;
    }
    return currentStage >= ResetStarted
            || writeResetState(ResetStarted, transactionId, reason, errorMessage);
}

bool MasterKeyStore::deleteForReset(QString *errorMessage)
{
    QByteArray transactionId;
    QString stageError;
    ResetReason reason = CredentialRemovalReset;
    const ResetStage stage = resetStage(&transactionId, &stageError, &reason);
    if (!stageError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = stageError;
        }
        return false;
    }
    if (stage == NoReset || transactionId.size() != 16) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("No reset transaction is pending");
        }
        return false;
    }
    if (stage >= StorageDeleted) {
        return true;
    }

    QDir store(m_secretsPath);
    if (store.exists() && !store.removeRecursively()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to delete Sailfish Secrets storage");
        }
        return false;
    }
    if (!QDir().mkpath(m_secretsPath) || !writeFormatMarker(errorMessage)) {
        return false;
    }
    return writeResetState(StorageDeleted, transactionId, reason, errorMessage);
}

bool MasterKeyStore::commitResetGeneration(quint64 *committedGeneration,
                                           QString *errorMessage)
{
    QByteArray transactionId;
    QString stageError;
    ResetReason reason = CredentialRemovalReset;
    const ResetStage stage = resetStage(&transactionId, &stageError, &reason);
    if (!stageError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = stageError;
        }
        return false;
    }
    if (stage < StorageDeleted || transactionId.size() != 16) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("Reset storage deletion has not committed");
        }
        return false;
    }
    QByteArray lastTransaction;
    quint64 value = generation(errorMessage, &lastTransaction);
    if (errorMessage && !errorMessage->isEmpty()) {
        return false;
    }
    if (lastTransaction != transactionId) {
        if (value == Q_UINT64_C(0xffffffffffffffff)
                || !writeGeneration(value + 1, transactionId, errorMessage)) {
            return false;
        }
        ++value;
    }
    if (stage < GenerationCommitted
            && !writeResetState(GenerationCommitted, transactionId,
                                reason, errorMessage)) {
        return false;
    }
    if (committedGeneration) {
        *committedGeneration = value;
    }
    return true;
}

bool MasterKeyStore::acknowledgeAndroidReset(
        quint64 acknowledgedGeneration,
        const QByteArray &acknowledgedTransaction,
        QString *errorMessage)
{
    QByteArray transactionId;
    QString stageError;
    ResetReason reason = CredentialRemovalReset;
    const ResetStage stage = resetStage(&transactionId, &stageError, &reason);
    if (!stageError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = stageError;
        }
        return false;
    }
    const quint64 currentGeneration = generation(errorMessage);
    if ((errorMessage && !errorMessage->isEmpty())
            || acknowledgedGeneration != currentGeneration
            || acknowledgedTransaction != transactionId
            || stage < LifecycleAcknowledged) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("Android acknowledged the wrong reset transaction");
        }
        return false;
    }
    return stage >= AndroidAcknowledged
            || writeResetState(AndroidAcknowledged, transactionId,
                               reason, errorMessage);
}

bool MasterKeyStore::acknowledgeReset(QString *errorMessage)
{
    QByteArray transactionId;
    QString stageError;
    ResetReason reason = CredentialRemovalReset;
    const ResetStage stage = resetStage(&transactionId, &stageError, &reason);
    if (!stageError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = stageError;
        }
        return false;
    }
    if (stage < GenerationCommitted || transactionId.size() != 16) {
        if (errorMessage && errorMessage->isEmpty()) {
            *errorMessage = QStringLiteral("Reset generation has not committed");
        }
        return false;
    }
    return stage >= LifecycleAcknowledged
            || writeResetState(LifecycleAcknowledged, transactionId,
                               reason, errorMessage);
}

bool MasterKeyStore::finishReset(QString *errorMessage)
{
    QByteArray transactionId;
    QString stageError;
    ResetReason reason = CredentialRemovalReset;
    const ResetStage stage = resetStage(&transactionId, &stageError, &reason);
    if (!stageError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = stageError;
        }
        return false;
    }
    if (stage == NoReset) {
        return true;
    }
    if (stage != AndroidAcknowledged) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Reset has not been acknowledged");
        }
        return false;
    }
    const quint64 currentGeneration = generation(errorMessage);
    if ((errorMessage && !errorMessage->isEmpty())
            || !writeGeneration(currentGeneration, QByteArray(16, '\0'), errorMessage)) {
        return false;
    }
    QDir resetDirectory(m_resetPath);
    if (resetDirectory.exists() && !resetDirectory.removeRecursively()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to clear completed reset transaction");
        }
        return false;
    }
    return true;
}

MasterKeyStore::ResetStage MasterKeyStore::resetStage(
        QByteArray *transactionId,
        QString *errorMessage,
        ResetReason *reason) const
{
    QByteArray serialized;
    DataProtector protector(m_resetPath);
    const DataProtector::Status status = protector.getData(&serialized);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Reading reset transaction"), status);
        }
        return NoReset;
    }
    if (serialized.isEmpty()) {
        if (transactionId) {
            transactionId->clear();
        }
        return NoReset;
    }

    QByteArray input(serialized);
    QDataStream stream(&input, QIODevice::ReadOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    char magic[8];
    quint32 stageValue = 0;
    quint32 reasonValue = 0;
    QByteArray parsedTransaction;
    if (stream.readRawData(magic, sizeof(magic)) != sizeof(magic)
            || QByteArray(magic, sizeof(magic)) != ResetMagic) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid reset transaction marker");
        }
        return NoReset;
    }
    stream >> stageValue >> reasonValue;
    if (!readBlob(&stream, &parsedTransaction, 16)
            || parsedTransaction.size() != 16
            || stream.status() != QDataStream::Ok || !stream.atEnd()
            || stageValue < ResetStarted || stageValue > AndroidAcknowledged
            || reasonValue < AlphaMigrationReset
            || reasonValue > IdentityInvalidationReset) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Malformed reset transaction marker");
        }
        return NoReset;
    }
    if (transactionId) {
        *transactionId = parsedTransaction;
    }
    if (reason) {
        *reason = static_cast<ResetReason>(reasonValue);
    }
    return static_cast<ResetStage>(stageValue);
}

quint64 MasterKeyStore::generation(
        QString *errorMessage,
        QByteArray *lastTransactionId) const
{
    QByteArray serialized;
    DataProtector protector(m_generationPath);
    const DataProtector::Status status = protector.getData(&serialized);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Reading store generation"), status);
        }
        return 0;
    }
    if (serialized.isEmpty()) {
        if (lastTransactionId) {
            lastTransactionId->clear();
        }
        return 0;
    }
    QByteArray input(serialized);
    QDataStream stream(&input, QIODevice::ReadOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    char magic[8];
    quint64 value = 0;
    QByteArray transactionId;
    if (stream.readRawData(magic, sizeof(magic)) != sizeof(magic)
            || QByteArray(magic, sizeof(magic)) != GenerationMagic) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid store generation marker");
        }
        return 0;
    }
    stream >> value;
    if (!readBlob(&stream, &transactionId, 16) || transactionId.size() != 16
            || stream.status() != QDataStream::Ok || !stream.atEnd() || value == 0) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Malformed store generation marker");
        }
        return 0;
    }
    if (lastTransactionId) {
        *lastTransactionId = transactionId == QByteArray(16, '\0')
                ? QByteArray() : transactionId;
    }
    return value;
}

bool MasterKeyStore::writeFormatMarker(QString *errorMessage) const
{
    DataProtector protector(m_formatPath);
    const DataProtector::Status status = protector.putData(FormatMarker);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Writing master-key format"), status);
        }
        return false;
    }
    return true;
}

bool MasterKeyStore::writeResetState(ResetStage stage,
                                     const QByteArray &transactionId,
                                     ResetReason reason,
                                     QString *errorMessage) const
{
    QByteArray serialized;
    QDataStream stream(&serialized, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    stream.writeRawData(ResetMagic.constData(), ResetMagic.size());
    stream << quint32(stage) << quint32(reason);
    appendBlob(&stream, transactionId);
    if (stream.status() != QDataStream::Ok) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to serialize reset transaction");
        }
        return false;
    }

    DataProtector protector(m_resetPath);
    const DataProtector::Status status = protector.putData(serialized);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Writing reset transaction"), status);
        }
        return false;
    }
    return true;
}

bool MasterKeyStore::writeGeneration(
        quint64 value,
        const QByteArray &transactionId,
        QString *errorMessage) const
{
    if (value == 0 || transactionId.size() != 16) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid store generation state");
        }
        return false;
    }
    QByteArray serialized;
    QDataStream stream(&serialized, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    stream.writeRawData(GenerationMagic.constData(), GenerationMagic.size());
    stream << value;
    appendBlob(&stream, transactionId);
    if (stream.status() != QDataStream::Ok) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to serialize store generation");
        }
        return false;
    }
    DataProtector protector(m_generationPath);
    const DataProtector::Status status = protector.putData(serialized);
    if (status != DataProtector::Success) {
        if (errorMessage) {
            *errorMessage = dataProtectorError(QStringLiteral("Writing store generation"), status);
        }
        return false;
    }
    return true;
}
