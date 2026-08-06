/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_MASTERKEYMANAGER_P_H
#define SAILFISHSECRETS_APIIMPL_MASTERKEYMANAGER_P_H

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QUuid>

namespace Sailfish {
namespace Secrets {
namespace Daemon {
namespace ApiImpl {

class MasterKeyEnvelope
{
public:
    enum { CurrentVersion = 1, IdentityEpochSize = 16 };

    quint32 sailfishUserId = 0;
    quint64 secureUserId = 0;
    QByteArray identityEpoch;
    quint32 backendVersion = 0;
    QByteArray keyMintKeyBlob;
    QByteArray nonce;
    QByteArray ciphertext;
    QByteArray authenticationTag;

    bool isValid() const;
    QByteArray authenticatedData() const;
    QByteArray serialize() const;
    static bool deserialize(const QByteArray &data, MasterKeyEnvelope *envelope);
};

class MasterKeyDerivation
{
public:
    static QByteArray randomRootKey();
    static bool derive(const QByteArray &rootKey,
                       const MasterKeyEnvelope &envelope,
                       QByteArray *bookkeepingDatabaseKey,
                       QByteArray *deviceLockKey,
                       QByteArray *appSupportDatabaseKey = Q_NULLPTR);
    static void clear(QByteArray *data);
};

class MasterKeyStore
{
public:
    enum ResetStage {
        NoReset = 0,
        ResetStarted = 1,
        StorageDeleted = 2,
        GenerationCommitted = 3,
        LifecycleAcknowledged = 4,
        AndroidAcknowledged = 5
    };

    enum ResetReason {
        AlphaMigrationReset = 1,
        CredentialRemovalReset = 2,
        IdentityInvalidationReset = 3
    };

    explicit MasterKeyStore(const QString &secretsPath, bool autotestMode = false);

    bool prepare(QString *errorMessage);
    bool load(MasterKeyEnvelope *envelope, QString *errorMessage) const;
    bool store(const MasterKeyEnvelope &envelope, QString *errorMessage);

    bool beginReset(const QByteArray &transactionId,
                    QString *errorMessage,
                    ResetReason reason = CredentialRemovalReset);
    bool deleteForReset(QString *errorMessage);
    bool commitResetGeneration(quint64 *generation, QString *errorMessage);
    bool acknowledgeAndroidReset(quint64 generation,
                                 const QByteArray &transactionId,
                                 QString *errorMessage);
    bool acknowledgeReset(QString *errorMessage);
    bool finishReset(QString *errorMessage);
    ResetStage resetStage(QByteArray *transactionId,
                          QString *errorMessage,
                          ResetReason *reason = Q_NULLPTR) const;
    quint64 generation(QString *errorMessage,
                       QByteArray *lastTransactionId = Q_NULLPTR) const;

private:
    QString m_secretsPath;
    QString m_formatPath;
    QString m_envelopePath;
    QString m_resetPath;
    QString m_generationPath;

    bool writeFormatMarker(QString *errorMessage) const;
    bool writeResetState(ResetStage stage,
                         const QByteArray &transactionId,
                         ResetReason reason,
                         QString *errorMessage) const;
    bool writeGeneration(quint64 generation,
                         const QByteArray &transactionId,
                         QString *errorMessage) const;
};

} // namespace ApiImpl
} // namespace Daemon
} // namespace Secrets
} // namespace Sailfish

#endif // SAILFISHSECRETS_APIIMPL_MASTERKEYMANAGER_P_H
