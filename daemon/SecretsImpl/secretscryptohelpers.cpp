/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "SecretsImpl/secrets_p.h"
#include "SecretsImpl/secretsrequestprocessor_p.h"

#include "Secrets/result.h"

#include "Crypto/result.h"
#include "Crypto/key.h"

#include "util_p.h"

#include <QtCore/QStringList>
#include <QtCore/QVector>
#include <QtCore/QByteArray>
#include <QtCore/QMutexLocker>
#include <QtCore/QMutex>
#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsCryptoHelpers, "org.sailfishos.secrets.cryptohelpers")

// The methods in this file exist to help fulfil Sailfish Crypto API requests,
// while allowing the use of a single (secrets) database for atomicity reasons.

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::RequestProcessor::confirmCollectionStoragePlugin(
        const QString &collectionName,
        const QString &storagePluginName) const
{
    Sailfish::Secrets::Daemon::Sqlite::DatabaseLocker locker(m_db);

    const QString selectCollectionPluginsQuery = QStringLiteral(
                 "SELECT"
                    " StoragePluginName"
                  " FROM Collections"
                  " WHERE CollectionName = ?;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query sq = m_db->prepare(selectCollectionPluginsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to prepare select collection plugins query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db->execute(sq, &errorText)) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to execute select collection plugins query: %1").arg(errorText));
    }

    QString collectionStoragePluginName;
    if (sq.next()) {
        collectionStoragePluginName = sq.value(0).value<QString>();
    }

    if (storagePluginName != collectionStoragePluginName) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidExtensionPluginError,
                                         QString::fromLatin1("The identified collection is not stored by that plugin"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

QMap<QString, QObject*>
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::potentialCryptoStoragePlugins() const
{
    return m_requestProcessor->potentialCryptoStoragePlugins();
}

QMap<QString, QObject*>
Sailfish::Secrets::Daemon::ApiImpl::RequestProcessor::potentialCryptoStoragePlugins() const
{
    return m_potentialCryptoStoragePlugins;
}

QStringList
Sailfish::Secrets::Daemon::ApiImpl::RequestProcessor::storagePluginNames() const
{
    return m_storagePlugins.keys();
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storagePluginNames(
        pid_t callerPid,
        quint64 cryptoRequestId,
        QStringList *names) const
{
    // TODO: Access control
    Q_UNUSED(callerPid)
    Q_UNUSED(cryptoRequestId)

    *names = m_requestProcessor->storagePluginNames();
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}


Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::confirmCollectionStoragePlugin(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const QString &collectionName,
        const QString &storagePluginName) const
{
    // TODO: Access control
    Q_UNUSED(callerPid)
    Q_UNUSED(cryptoRequestId)

    return m_requestProcessor->confirmCollectionStoragePlugin(collectionName, storagePluginName);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::keyEntryIdentifiers(
        pid_t callerPid,
        quint64 cryptoRequestId,
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    // NOTE: the existence of this method introduces a potential security risk,
    // as it means that the keyName must be stored in plain-text
    // (in order to be useful when returned to clients).
    // But, this means that if any key is stored in secrets
    // storage, there is a potential known-plaintext issue!

    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    QMutexLocker(m_db.accessMutex());

    const QString selectKeyIdentifiersQuery = QStringLiteral(
                "SELECT"
                   " KeyName,"
                   " CollectionName"
                " FROM KeyEntries;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query sq = m_db.prepare(selectKeyIdentifiersQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to prepare select key identifiers query: %1").arg(errorText));
    }

    if (!m_db.execute(sq, &errorText)) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to execute select key identifiers query: %1").arg(errorText));
    }

    while (sq.next()) {
        identifiers->append(Sailfish::Crypto::Key::Identifier(sq.value(0).value<QString>(),
                                                              sq.value(1).value<QString>()));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::keyEntry(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        QString *cryptoPluginName,
        QString *storagePluginName)
{
    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    QMutexLocker(m_db.accessMutex());

    const QString selectKeyPluginsQuery = QStringLiteral(
                "SELECT"
                   " CryptoPluginName,"
                   " StoragePluginName"
                " FROM KeyEntries"
                " WHERE KeyName = ?"
                " AND CollectionName = ?;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query sq = m_db.prepare(selectKeyPluginsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to prepare select key plugins query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(identifier.name())
           << QVariant::fromValue<QString>(identifier.collectionName());
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to execute select key plugins query: %1").arg(errorText));
    }

    if (sq.next()) {
        *cryptoPluginName = sq.value(0).value<QString>();
        *storagePluginName = sq.value(1).value<QString>();
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::addKeyEntry(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QString &cryptoPluginName,
        const QString &storagePluginName)
{
    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    QMutexLocker(m_db.accessMutex());

    const QString insertKeyEntryQuery = QStringLiteral(
                "INSERT INTO KeyEntries ("
                "   CollectionName,"
                "   HashedSecretName,"
                "   KeyName,"
                "   CryptoPluginName,"
                "   StoragePluginName )"
                " VALUES ( ?,?,?,?,? );"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query iq = m_db.prepare(insertKeyEntryQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to prepare insert key entry query: %1").arg(errorText));
    }

    QVariantList values;
    const QString hashedSecretName = Sailfish::Secrets::Daemon::Util::generateHashedSecretName(
                identifier.collectionName(), identifier.name());
    values << QVariant::fromValue<QString>(identifier.collectionName())
           << QVariant::fromValue<QString>(hashedSecretName)
           << QVariant::fromValue<QString>(identifier.name())
           << QVariant::fromValue<QString>(cryptoPluginName)
           << QVariant::fromValue<QString>(storagePluginName);
    iq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QLatin1String("Unable to begin insert key entry transaction"));
    }

    if (!m_db.execute(iq, &errorText)) {
        m_db.rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to execute insert key entry query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QLatin1String("Unable to commit insert key entry transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::removeKeyEntry(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // TODO: access control
    Q_UNUSED(callerPid);
    Q_UNUSED(cryptoRequestId);

    QMutexLocker(m_db.accessMutex());

    const QString deleteKeyEntryQuery = QStringLiteral(
                "DELETE FROM KeyEntries"
                " WHERE CollectionName = ?"
                " AND KeyName = ?;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteKeyEntryQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to prepare delete key entry query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(identifier.collectionName())
           << QVariant::fromValue<QString>(identifier.name());
    dq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QLatin1String("Unable to begin delete key entry transaction"));
    }

    if (!m_db.execute(dq, &errorText)) {
        m_db.rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromLatin1("Unable to execute delete key entry query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QLatin1String("Unable to commit delete key entry transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

// The crypto plugin can store keys, thus it is an EncryptedStoragePlugin.
// To prevent the daemon process from ever seeing the key data, the key
// is not stored through the normal setCollectionSecret() API, but instead
// is generated and stored directly by the Crypto plugin.
// However, we need to update the bookkeeping (main secrets metadata database)
// so that foreign key constraints etc continue to work appropriately.
Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKeyMetadata(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QString &storagePluginName)
{
    // step one: check if the Collection is stored in the storagePluginName, else return fail.
    Sailfish::Secrets::Result confirmPluginResult = confirmCollectionStoragePlugin(
                callerPid,
                cryptoRequestId,
                identifier.collectionName(),
                storagePluginName);
    if (confirmPluginResult.code() != Sailfish::Secrets::Result::Succeeded) {
        return confirmPluginResult;
    }

    // step two: perform the "set collection secret metadata" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(Sailfish::Secrets::Secret::Identifier(identifier.name(), identifier.collectionName()))
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(Sailfish::Secrets::SecretManager::PreventUserInteractionMode)
             << QVariant::fromValue<QString>(QString());
    Sailfish::Secrets::Result enqueueResult(Sailfish::Secrets::Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Sailfish::Secrets::Daemon::ApiImpl::SetCollectionSecretMetadataRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Sailfish::Secrets::Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::StoreKeyMetadataCryptoApiHelperRequest);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Pending);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storeKey(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QByteArray &serialisedKey,
        const QMap<QString, QString> &filterData,
        const QString &storagePluginName)
{
    // step one: check if the Collection is stored in the storagePluginName, else return fail.
    Sailfish::Secrets::Result confirmPluginResult = confirmCollectionStoragePlugin(
                callerPid,
                cryptoRequestId,
                identifier.collectionName(),
                storagePluginName);
    if (confirmPluginResult.code() != Sailfish::Secrets::Result::Succeeded) {
        return confirmPluginResult;
    }

    // step two: perform the "set collection secret" request, as a secrets-for-crypto request.
    Sailfish::Secrets::Secret secret(Sailfish::Secrets::Secret::Identifier(identifier.name(), identifier.collectionName()));
    secret.setFilterData(filterData);
    secret.setType(Sailfish::Secrets::Secret::TypeCryptoKey);
    secret.setData(serialisedKey);
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret>(secret)
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(Sailfish::Secrets::SecretManager::PreventUserInteractionMode)
             << QVariant::fromValue<QString>(QString());
    Sailfish::Secrets::Result enqueueResult(Sailfish::Secrets::Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Sailfish::Secrets::Daemon::ApiImpl::SetCollectionSecretRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Sailfish::Secrets::Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::StoreKeyCryptoApiHelperRequest);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Pending);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKey(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // perform the "delete collection secret" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(Sailfish::Secrets::Secret::Identifier(identifier.name(), identifier.collectionName()))
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(Sailfish::Secrets::SecretManager::PreventUserInteractionMode)
             << QVariant::fromValue<QString>(QString());
    Sailfish::Secrets::Result enqueueResult(Sailfish::Secrets::Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Sailfish::Secrets::Daemon::ApiImpl::DeleteCollectionSecretRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Sailfish::Secrets::Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::DeleteStoredKeyCryptoApiHelperRequest);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Pending);
}

// This method is only called in the "cleanup a failed generatedStoredKey() attempt" codepath!
Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::deleteStoredKeyMetadata(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    // perform the "delete collection secret metadata" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(Sailfish::Secrets::Secret::Identifier(identifier.name(), identifier.collectionName()));
    Sailfish::Secrets::Result enqueueResult(Sailfish::Secrets::Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Sailfish::Secrets::Daemon::ApiImpl::DeleteCollectionSecretMetadataRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Sailfish::Secrets::Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::DeleteStoredKeyMetadataCryptoApiHelperRequest);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Pending);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::storedKey(
        pid_t callerPid,
        quint64 cryptoRequestId,
        const Sailfish::Crypto::Key::Identifier &identifier,
        QByteArray *serialisedKey,
        QMap<QString, QString> *filterData)
{
    Q_UNUSED(serialisedKey); // this request is always asynchronous
    Q_UNUSED(filterData);

    // perform the "get collection secret" request, as a secrets-for-crypto request.
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(Sailfish::Secrets::Secret::Identifier(identifier.name(), identifier.collectionName()))
             << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(Sailfish::Secrets::SecretManager::PreventUserInteractionMode)
             << QVariant::fromValue<QString>(QString());
    Sailfish::Secrets::Result enqueueResult(Sailfish::Secrets::Result::Succeeded);
    handleRequest(
                callerPid,
                cryptoRequestId,
                Sailfish::Secrets::Daemon::ApiImpl::GetCollectionSecretRequest,
                inParams,
                enqueueResult);
    if (enqueueResult.code() == Sailfish::Secrets::Result::Failed) {
        return enqueueResult;
    }
    m_cryptoApiHelperRequests.insert(cryptoRequestId, Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::StoredKeyCryptoApiHelperRequest);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Pending);
}

void
Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::asynchronousCryptoRequestCompleted(
        quint64 cryptoRequestId,
        const Sailfish::Secrets::Result &result,
        const QVariantList &parameters)
{
    if (!m_cryptoApiHelperRequests.contains(cryptoRequestId)) {
        qCWarning(lcSailfishSecretsCryptoHelpers) << "Unknown asynchronous secrets request finished for crypto request:" << cryptoRequestId;
        return;
    }

    Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue::CryptoApiHelperRequestType type = m_cryptoApiHelperRequests.take(cryptoRequestId);
    switch (type) {
        case StoredKeyCryptoApiHelperRequest: {
            Sailfish::Secrets::Secret secret = parameters.size() ? parameters.first().value<Sailfish::Secrets::Secret>() : Sailfish::Secrets::Secret();
            emit storedKeyCompleted(cryptoRequestId, result, secret.data(), secret.filterData());
            break;
        }
        case DeleteStoredKeyCryptoApiHelperRequest: {
            emit deleteStoredKeyCompleted(cryptoRequestId, result);
            break;
        }
        case StoreKeyCryptoApiHelperRequest: {
            emit storeKeyCompleted(cryptoRequestId, result);
            break;
        }
        case StoreKeyMetadataCryptoApiHelperRequest: {
            emit storeKeyMetadataCompleted(cryptoRequestId, result);
            break;
        }
        case DeleteStoredKeyMetadataCryptoApiHelperRequest: {
            emit deleteStoredKeyMetadataCompleted(cryptoRequestId, result);
            break;
        }
        default: {
            // this type of method shouldn't be asynchronous!  (may change in the future, in which case, new case needs to be added above)
            qCWarning(lcSailfishSecretsCryptoHelpers) << "Asynchronous secrets request finished for synchronous crypto request:" << cryptoRequestId;
            break;
        }
    }
}
