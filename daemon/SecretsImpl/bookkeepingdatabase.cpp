/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "bookkeepingdatabase_p.h"

using namespace Sailfish::Secrets;

static const char *setupEnforceForeignKeys =
        "\n PRAGMA foreign_keys = ON;";

static const char *setupEncoding =
        "\n PRAGMA encoding = \"UTF-16\";";

static const char *setupTempStore =
        "\n PRAGMA temp_store = MEMORY;";

static const char *setupJournal =
        "\n PRAGMA journal_mode = WAL;";

static const char *setupSynchronous =
        "\n PRAGMA synchronous = FULL;";

static const char *createCollectionsTable =
        "\n CREATE TABLE Collections ("
        "   CollectionId INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   CollectionName TEXT NOT NULL,"
        "   ApplicationId TEXT NOT NULL,"
        "   UsesDeviceLockKey INTEGER NOT NULL,"
        "   StoragePluginName TEXT NOT NULL,"
        "   EncryptionPluginName TEXT NOT NULL,"
        "   AuthenticationPluginName TEXT NOT NULL,"
        "   UnlockSemantic INTEGER NOT NULL,"
        "   CustomLockTimeoutMs INTEGER NOT NULL,"
        "   AccessControlMode INTEGER NOT NULL,"
        "   CONSTRAINT collectionNameUnique UNIQUE (CollectionName));";

static const char *createSecretsTable =
        "\n CREATE TABLE Secrets ("
        "   SecretId INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   CollectionName TEXT NOT NULL,"
        "   HashedSecretName TEXT NOT NULL,"
        "   ApplicationId TEXT NOT NULL,"
        "   UsesDeviceLockKey INTEGER NOT NULL,"
        "   StoragePluginName TEXT NOT NULL,"
        "   EncryptionPluginName TEXT NOT NULL,"
        "   AuthenticationPluginName TEXT NOT NULL,"
        "   UnlockSemantic INTEGER NOT NULL,"
        "   CustomLockTimeoutMs INTEGER NOT NULL,"
        "   AccessControlMode INTEGER NOT NULL,"
        "   FOREIGN KEY (CollectionName) REFERENCES Collections(CollectionName) ON DELETE CASCADE,"
        "   CONSTRAINT collectionSecretNameUnique UNIQUE (CollectionName, HashedSecretName));";

static const char *createKeyEntriesTable =
        "\n CREATE TABLE KeyEntries ("
        "   KeyId INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   CollectionName TEXT NOT NULL,"
        "   HashedSecretName TEXT NOT NULL,"
        "   KeyName TEXT NOT NULL,"        /* potential security (known-plaintext) issue!!! */
        "   CryptoPluginName TEXT NOT NULL,"
        "   StoragePluginName TEXT NOT NULL,"
        "   FOREIGN KEY (CollectionName, HashedSecretName) REFERENCES Secrets(CollectionName,HashedSecretName) ON DELETE CASCADE,"
        "   CONSTRAINT collectionKeyNameUnique UNIQUE (CollectionName, KeyName));";

static const char *setupStatements[] =
{
    setupEnforceForeignKeys,
    setupEncoding,
    setupTempStore,
    setupJournal,
    setupSynchronous,
    NULL
};

static const char *createStatements[] =
{
    createCollectionsTable,
    createSecretsTable,
    createKeyEntriesTable,
    NULL
};

static Daemon::Sqlite::UpgradeOperation upgradeVersions[] = {
    { 0, 0 },
};

static const int currentSchemaVersion = 1;

Daemon::ApiImpl::BookkeepingDatabase::BookkeepingDatabase()
{
}

Daemon::ApiImpl::BookkeepingDatabase::~BookkeepingDatabase()
{
}

bool
Daemon::ApiImpl::BookkeepingDatabase::initialise(bool autotestMode)
{
    return m_db.open(QLatin1String("QSQLITE"),
                     QLatin1String("sailfishsecretsd"),
                     QLatin1String("secrets.db"),
                     setupStatements,
                     createStatements,
                     upgradeVersions,
                     currentSchemaVersion,
                     QLatin1String("sailfishsecretsd"),
                     autotestMode);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::insertCollection(
        const QString &collectionName,
        const QString &callerApplicationId,
        bool usesDeviceLockKey,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        int unlockSemantic,
        int customLockTimeoutMs,
        SecretManager::AccessControlMode accessControlMode)
{
    const QString insertCollectionQuery = QStringLiteral(
                "INSERT INTO Collections ("
                  "CollectionName,"
                  "ApplicationId,"
                  "UsesDeviceLockKey,"
                  "StoragePluginName,"
                  "EncryptionPluginName,"
                  "AuthenticationPluginName,"
                  "UnlockSemantic,"
                  "CustomLockTimeoutMs,"
                  "AccessControlMode"
                ")"
                " VALUES ("
                  "?,?,?,?,?,?,?,?,?"
                ");");

    QString errorText;
    Daemon::Sqlite::Database::Query iq = m_db.prepare(insertCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare insert collection query: %1").arg(errorText));
    }

    QVariantList ivalues;
    ivalues << collectionName
            << callerApplicationId
            << QVariant::fromValue<int>(usesDeviceLockKey ? 1 : 0)
            << storagePluginName
            << encryptionPluginName
            << authenticationPluginName
            << unlockSemantic
            << customLockTimeoutMs
            << static_cast<int>(accessControlMode);
    iq.bindValues(ivalues);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to begin insert collection transaction"));
    }

    if (!m_db.execute(iq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute insert collection query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to commit insert collection transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::collectionNames(
        QStringList *names)
{
    const QString selectCollectionNamesQuery = QStringLiteral(
                 "SELECT CollectionName"
                 " FROM Collections;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectCollectionNamesQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select collection names query: %1").arg(errorText));
    }

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select collection names query: %1").arg(errorText));
    }

    while (sq.next()) {
        const QString cname = sq.value(0).value<QString>();
        if (!cname.isEmpty() && cname.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) != 0) {
            names->append(cname);
        }
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::collectionAlreadyExists(
        const QString &collectionName,
        bool *exists)
{
    const QString selectCollectionsCountQuery = QStringLiteral(
                 "SELECT"
                    " Count(*)"
                  " FROM Collections"
                  " WHERE CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectCollectionsCountQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select collections query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select collections query: %1").arg(errorText));
    }

    if (sq.next() && sq.value(0).value<int>() > 0) {
        *exists = true;
    } else {
        *exists = false;
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::collectionMetadata(
        const QString &collectionName,
        bool *exists,
        QString *applicationId,
        bool *usesDeviceLockKey,
        QString *storagePluginName,
        QString *encryptionPluginName,
        QString *authenticationPluginName,
        int *unlockSemantic,
        int *customLockTimeoutMs,
        SecretManager::AccessControlMode *accessControlMode)
{
    const QString selectCollectionsQuery = QStringLiteral(
                 "SELECT"
                    " ApplicationId,"
                    " UsesDeviceLockKey,"
                    " StoragePluginName,"
                    " EncryptionPluginName,"
                    " AuthenticationPluginName,"
                    " UnlockSemantic,"
                    " CustomLockTimeoutMs,"
                    " AccessControlMode"
                  " FROM Collections"
                  " WHERE CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectCollectionsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select collections query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select collections query: %1").arg(errorText));
    }
    if (exists) {
        *exists = false;
    }

    if (sq.next()) {
        if (exists) {
            *exists = true;
        }
        if (applicationId) {
            *applicationId = sq.value(0).value<QString>();
        }
        if (usesDeviceLockKey) {
            *usesDeviceLockKey = sq.value(1).value<int>() > 0;
        }
        if (storagePluginName) {
            *storagePluginName = sq.value(2).value<QString>();
        }
        if (encryptionPluginName) {
            *encryptionPluginName = sq.value(3).value<QString>();
        }
        if (authenticationPluginName) {
            *authenticationPluginName = sq.value(4).value<QString>();
        }
        if (unlockSemantic) {
            *unlockSemantic = sq.value(5).value<int>();
        }
        if (customLockTimeoutMs) {
            *customLockTimeoutMs = sq.value(6).value<int>();
        }
        if (accessControlMode) {
            *accessControlMode = static_cast<SecretManager::AccessControlMode>(sq.value(7).value<int>());
        }
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::deleteCollection(
        const QString &collectionName)
{
    const QString deleteCollectionQuery = QStringLiteral(
                "DELETE FROM Collections"
                " WHERE CollectionName = ?;");

    QString errorText;
    Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare delete collection query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    dq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to begin delete collection transaction"));
    }

    if (!m_db.execute(dq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute delete collection query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to commit delete collection transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::cleanupDeleteCollection(
        const QString &collectionName,
        const Result &originalFailureResult)
{
    Result dcr = deleteCollection(collectionName);
    if (dcr.code() != Result::Succeeded) {
        dcr.setErrorMessage(QString::fromLatin1("%1 while removing artifacts due to plugin operation failure: %2: %3")
                            .arg(dcr.errorMessage(),
                                 QString::number(originalFailureResult.errorCode()),
                                 originalFailureResult.errorMessage()));
    }
    return dcr;
}

Result
Daemon::ApiImpl::BookkeepingDatabase::secretAlreadyExists(
        const QString &collectionName,
        const QString &hashedSecretName,
        bool *exists)
{
    const QString selectSecretsCountQuery = QStringLiteral(
                 "SELECT"
                    " Count(*)"
                  " FROM Secrets"
                  " WHERE CollectionName = ?"
                  " AND HashedSecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query ssq = m_db.prepare(selectSecretsCountQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select secrets query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(hashedSecretName);
    ssq.bindValues(values);

    if (!m_db.execute(ssq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select secrets query: %1").arg(errorText));
    }

    if (ssq.next()) {
        *exists = ssq.value(0).value<int>() > 0;
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::insertSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QString &applicationId,
        bool usesDeviceLockKey,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        int unlockSemantic,
        int customLockTimeoutMs,
        SecretManager::AccessControlMode accessControlMode)
{
    const QString insertSecretQuery = QStringLiteral(
                "INSERT INTO Secrets ("
                  "CollectionName,"
                  "HashedSecretName,"
                  "ApplicationId,"
                  "UsesDeviceLockKey,"
                  "StoragePluginName,"
                  "EncryptionPluginName,"
                  "AuthenticationPluginName,"
                  "UnlockSemantic,"
                  "CustomLockTimeoutMs,"
                  "AccessControlMode"
                ")"
                " VALUES ("
                  "?,?,?,?,?,?,?,?,?,?"
                ");");

    QString errorText;
    Daemon::Sqlite::Database::Query iq = m_db.prepare(insertSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare insert secret query: %1").arg(errorText));
    }

    QVariantList ivalues;
    ivalues << QVariant::fromValue<QString>(collectionName);
    ivalues << QVariant::fromValue<QString>(hashedSecretName);
    ivalues << QVariant::fromValue<QString>(applicationId);
    ivalues << QVariant::fromValue<int>(usesDeviceLockKey ? 1 : 0);
    ivalues << QVariant::fromValue<QString>(storagePluginName);
    ivalues << QVariant::fromValue<QString>(encryptionPluginName);
    ivalues << QVariant::fromValue<QString>(authenticationPluginName);
    ivalues << QVariant::fromValue<int>(unlockSemantic);
    ivalues << QVariant::fromValue<int>(customLockTimeoutMs);
    ivalues << QVariant::fromValue<int>(static_cast<int>(accessControlMode));
    iq.bindValues(ivalues);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to begin insert secret transaction"));
    }

    if (!m_db.execute(iq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute insert secret query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to commit insert secret transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::updateSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QString &applicationId,
        bool usesDeviceLockKey,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        int unlockSemantic,
        int customLockTimeoutMs,
        SecretManager::AccessControlMode accessControlMode)
{
    const QString updateSecretQuery = QStringLiteral(
                 "UPDATE Secrets"
                 " SET ApplicationId = ?,"
                     " UsesDeviceLockKey = ?,"
                     " StoragePluginName = ?,"
                     " EncryptionPluginName = ?,"
                     " AuthenticationPluginName = ?,"
                     " UnlockSemantic = ?,"
                     " CustomLockTimeoutMs = ?,"
                     " AccessControlMode = ?"
                 " WHERE CollectionName = ?"
                 " AND HashedSecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query iq = m_db.prepare(updateSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare update secret query: %1").arg(errorText));
    }

    QVariantList ivalues;
    ivalues << QVariant::fromValue<QString>(applicationId);
    ivalues << QVariant::fromValue<int>(usesDeviceLockKey ? 1 : 0);
    ivalues << QVariant::fromValue<QString>(storagePluginName);
    ivalues << QVariant::fromValue<QString>(encryptionPluginName);
    ivalues << QVariant::fromValue<QString>(authenticationPluginName);
    ivalues << QVariant::fromValue<int>(unlockSemantic);
    ivalues << QVariant::fromValue<int>(customLockTimeoutMs);
    ivalues << QVariant::fromValue<int>(static_cast<int>(accessControlMode));
    ivalues << QVariant::fromValue<QString>(collectionName);
    ivalues << QVariant::fromValue<QString>(hashedSecretName);
    iq.bindValues(ivalues);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to begin update secret transaction"));
    }

    if (!m_db.execute(iq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute update secret query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to commit update secret transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::deleteSecret(
        const QString &collectionName,
        const QString &hashedSecretName)
{
    const QString deleteSecretQuery = QStringLiteral(
                "DELETE FROM Secrets"
                " WHERE CollectionName = ?"
                " AND HashedSecretName = ?;");

    QString errorText;
    Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare delete secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(hashedSecretName);
    dq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to begin delete secret transaction"));
    }

    if (!m_db.execute(dq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute delete secret query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to commit delete secret transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::cleanupDeleteSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const Result &originalFailureResult)
{
    Result dsr = deleteSecret(collectionName, hashedSecretName);
    if (dsr.code() != Result::Succeeded) {
        dsr.setErrorMessage(QString::fromLatin1("%1 while removing artifacts due to plugin operation failure: %2: %3")
                            .arg(dsr.errorMessage(),
                                 QString::number(originalFailureResult.errorCode()),
                                 originalFailureResult.errorMessage()));
    }
    return dsr;
}

Result
Daemon::ApiImpl::BookkeepingDatabase::secretMetadata(
        const QString &collectionName,
        const QString &hashedSecretName,
        bool *exists,
        QString *applicationId,
        bool *usesDeviceLockKey,
        QString *storagePluginName,
        QString *encryptionPluginName,
        QString *authenticationPluginName,
        int *unlockSemantic,
        int *customLockTimeoutMs,
        SecretManager::AccessControlMode *accessControlMode)
{
    const QString selectSecretsQuery = QStringLiteral(
                 "SELECT"
                    " ApplicationId,"
                    " UsesDeviceLockKey,"
                    " StoragePluginName,"
                    " EncryptionPluginName,"
                    " AuthenticationPluginName,"
                    " UnlockSemantic,"
                    " CustomLockTimeoutMs,"
                    " AccessControlMode"
                  " FROM Secrets"
                  " WHERE CollectionName = ?"
                  " AND HashedSecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectSecretsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select secrets query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(hashedSecretName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select secrets query: %1").arg(errorText));
    }

    if (exists) {
        *exists = false;
    }

    if (sq.next()) {
        if (exists) {
            *exists = true;
        }
        if (applicationId) {
            *applicationId = sq.value(0).value<QString>();
        }
        if (usesDeviceLockKey) {
            *usesDeviceLockKey = sq.value(1).value<int>() > 0;
        }
        if (storagePluginName) {
            *storagePluginName = sq.value(2).value<QString>();
        }
        if (encryptionPluginName) {
            *encryptionPluginName = sq.value(3).value<QString>();
        }
        if (authenticationPluginName) {
            *authenticationPluginName = sq.value(4).value<QString>();
        }
        if (unlockSemantic) {
            *unlockSemantic = sq.value(5).value<int>();
        }
        if (customLockTimeoutMs) {
            *customLockTimeoutMs = sq.value(6).value<int>();
        }
        if (accessControlMode) {
            *accessControlMode = static_cast<SecretManager::AccessControlMode>(sq.value(7).value<int>());
        }
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::collectionStoragePluginName(
        const QString &collectionName,
        QString *collectionStoragePluginName)
{
    const QString selectCollectionPluginsQuery = QStringLiteral(
                 "SELECT"
                    " StoragePluginName"
                  " FROM Collections"
                  " WHERE CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectCollectionPluginsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select collection plugins query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select collection plugins query: %1").arg(errorText));
    }

    if (sq.next()) {
        *collectionStoragePluginName = sq.value(0).value<QString>();
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::keyStoragePluginName(
        const QString &collectionName,
        const QString &hashedKeyName,
        QString *keyStoragePluginName)
{
    const QString selectCollectionPluginsQuery = QStringLiteral(
                 "SELECT"
                    " StoragePluginName"
                  " FROM Secrets"
                  " WHERE HashedSecretName = ?"
                  " AND CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectCollectionPluginsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select key plugins query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(hashedKeyName);
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select key plugins query: %1").arg(errorText));
    }

    if (sq.next()) {
        *keyStoragePluginName = sq.value(0).value<QString>();
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::keyIdentifiers(
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    const QString selectKeyIdentifiersQuery = QStringLiteral(
                "SELECT"
                   " KeyName,"
                   " CollectionName"
                " FROM KeyEntries;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectKeyIdentifiersQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select key identifiers query: %1").arg(errorText));
    }

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select key identifiers query: %1").arg(errorText));
    }

    while (sq.next()) {
        identifiers->append(Sailfish::Crypto::Key::Identifier(
                                sq.value(0).value<QString>(),
                                sq.value(1).value<QString>()));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::keyPluginNames(
        const QString &collectionName,
        const QString &keyName,
        QString *cryptoPluginName,
        QString *storagePluginName)
{
    const QString selectKeyPluginsQuery = QStringLiteral(
                "SELECT"
                   " CryptoPluginName,"
                   " StoragePluginName"
                " FROM KeyEntries"
                " WHERE KeyName = ?"
                " AND CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectKeyPluginsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select key plugins query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(keyName)
           << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select key plugins query: %1").arg(errorText));
    }

    if (sq.next()) {
        *cryptoPluginName = sq.value(0).value<QString>();
        *storagePluginName = sq.value(1).value<QString>();
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::addKeyEntry(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QString &keyName,
        const QString &cryptoPluginName,
        const QString &storagePluginName)
{
    // NOTE: the existence of the keyName parameter to this method
    // introduces a potential security risk, as it means that the
    // keyName must be stored in plain-text (in order to be able to
    // return keyIdentifiers() to clients).
    // But, this means that if any key is stored in secrets
    // storage, there is a potential known-plaintext issue!

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
    Daemon::Sqlite::Database::Query iq = m_db.prepare(insertKeyEntryQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare insert key entry query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName)
           << QVariant::fromValue<QString>(hashedSecretName)
           << QVariant::fromValue<QString>(keyName)
           << QVariant::fromValue<QString>(cryptoPluginName)
           << QVariant::fromValue<QString>(storagePluginName);
    iq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to begin insert key entry transaction"));
    }

    if (!m_db.execute(iq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute insert key entry query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to commit insert key entry transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::BookkeepingDatabase::removeKeyEntry(
        const QString &collectionName,
        const QString &keyName)
{
    const QString deleteKeyEntryQuery = QStringLiteral(
                "DELETE FROM KeyEntries"
                " WHERE CollectionName = ?"
                " AND KeyName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteKeyEntryQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare delete key entry query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName)
           << QVariant::fromValue<QString>(keyName);
    dq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to begin delete key entry transaction"));
    }

    if (!m_db.execute(dq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute delete key entry query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                      QLatin1String("Unable to commit delete key entry transaction"));
    }

    return Result(Result::Succeeded);
}
