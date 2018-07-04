/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "metadatadb_p.h"
#include "controller_p.h"

using namespace Sailfish::Secrets;

// arg %1 must be a 64-character hex string = 32 byte key.
static const char *setupEncryptionKey =
        "\n PRAGMA key = \"x\'%1\'\";";

// arg %1 must be a 64-character hex string = 32 byte key.
static const char *setupReEncryptionKey =
        "\n PRAGMA rekey = \"x\'%1\'\";";

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
        "   EncryptionPluginName TEXT NOT NULL,"
        "   AuthenticationPluginName TEXT NOT NULL,"
        "   UnlockSemantic INTEGER NOT NULL,"
        "   AccessControlMode INTEGER NOT NULL,"
        "   CONSTRAINT collectionNameUnique UNIQUE (CollectionName));";

static const char *createSecretsTable =
        "\n CREATE TABLE Secrets ("
        "   SecretId INTEGER PRIMARY KEY AUTOINCREMENT,"
        "   CollectionName TEXT NOT NULL,"
        "   SecretName TEXT NOT NULL,"
        "   ApplicationId TEXT NOT NULL,"
        "   UsesDeviceLockKey INTEGER NOT NULL,"
        "   EncryptionPluginName TEXT NOT NULL,"
        "   AuthenticationPluginName TEXT NOT NULL,"
        "   UnlockSemantic INTEGER NOT NULL,"
        "   AccessControlMode INTEGER NOT NULL,"
        "   Type Text,"
        "   CryptoPluginName TEXT,"
        "   FOREIGN KEY (CollectionName) REFERENCES Collections(CollectionName) ON DELETE CASCADE,"
        "   CONSTRAINT collectionSecretNameUnique UNIQUE (CollectionName, SecretName));";

static const char *createStatements[] =
{
    createCollectionsTable,
    createSecretsTable,
    NULL
};

static Daemon::Sqlite::UpgradeOperation upgradeVersions[] = {
    { 0, 0 },
};

static const int currentSchemaVersion = 1;

Daemon::ApiImpl::MetadataDatabase::MetadataDatabase(
        const QString &defaultEncryptionPluginName,
        const QString &defaultAuthenticationPluginName,
        const QString &storagePluginName,
        bool pluginIsEncryptedStorage,
        bool autotestMode)
    : m_defaultEncryptionPluginName(defaultEncryptionPluginName)
    , m_defaultAuthenticationPluginName(defaultAuthenticationPluginName)
    , m_storagePluginName(storagePluginName)
    , m_pluginIsEncryptedStorage(pluginIsEncryptedStorage)
    , m_autotestMode(autotestMode)
{
}

Daemon::ApiImpl::MetadataDatabase::~MetadataDatabase()
{
}

QString Daemon::ApiImpl::MetadataDatabase::databaseConnectionName() const
{
    return QStringLiteral("%1-metadata").arg(m_storagePluginName);
}

QString Daemon::ApiImpl::MetadataDatabase::databaseFileName() const
{
    return QStringLiteral("metadata.db");
}

bool Daemon::ApiImpl::MetadataDatabase::openDatabase(const QByteArray &hexKey)
{
    const QByteArray setupKeyStatement = QString::fromLatin1(setupEncryptionKey).arg(QString::fromLatin1(hexKey)).toLatin1();
    const char *setupKeyStatementData = setupKeyStatement.constData();
    const char *setupStatements[] = {
        setupKeyStatementData,
        setupEnforceForeignKeys,
        setupEncoding,
        setupTempStore,
        setupJournal,
        setupSynchronous,
        NULL
    };

    bool success = m_db.open(QStringLiteral("QSQLCIPHER"),
                             m_storagePluginName,
                             databaseFileName(),
                             setupStatements,
                             createStatements,
                             upgradeVersions,
                             currentSchemaVersion,
                             databaseConnectionName(),
                             m_autotestMode);

    if (success) {
        QStringList cnames;
        Result result = collectionNames(&cnames, false);
        if (!cnames.contains(QStringLiteral("standalone"))) {
            CollectionMetadata metadata;
            metadata.collectionName = QStringLiteral("standalone");
            metadata.ownerApplicationId = QStringLiteral("standalone");
            metadata.usesDeviceLockKey = false;
            metadata.encryptionPluginName = QStringLiteral("standalone");
            metadata.authenticationPluginName = QStringLiteral("standalone");
            metadata.unlockSemantic = 0;
            metadata.accessControlMode = SecretManager::NoAccessControlMode;
            result = insertCollectionMetadata(metadata);
            if (result.code() != Result::Succeeded) {
                qWarning() << "Failed to insert the notional standalone collection in plugin" << m_storagePluginName
                           << result.errorMessage();
                success = false;
            }
        }
    }

    return success;
}

QString Daemon::ApiImpl::MetadataDatabase::errorMessage() const
{
    return m_db.lastError().text();
}

bool Daemon::ApiImpl::MetadataDatabase::isOpen() const
{
    return m_db.isOpen();
}

bool Daemon::ApiImpl::MetadataDatabase::beginTransaction()
{
    return m_db.beginTransaction();
}

bool Daemon::ApiImpl::MetadataDatabase::commitTransaction()
{
    return m_db.commitTransaction();
}

bool Daemon::ApiImpl::MetadataDatabase::rollbackTransaction()
{
    return m_db.rollbackTransaction();
}

bool Daemon::ApiImpl::MetadataDatabase::withinTransaction()
{
    return m_db.withinTransaction();
}

Result
Daemon::ApiImpl::MetadataDatabase::isLocked(
        bool *locked) const
{
    Result retn(Result::Succeeded);
    if (!m_db.isOpen()) {
        *locked = true;
    } else {
        const QString lockedQuery = QStringLiteral("SELECT Count(*) FROM sqlite_master;");
        QString errorText;
        Daemon::Sqlite::Database::Query lq = m_db.prepare(lockedQuery, &errorText);
        if (!errorText.isEmpty()) {
            retn = Result(Result::DatabaseQueryError,
                          QString::fromUtf8("Unable to prepare is locked query: %1")
                                       .arg(errorText));
        } else if (!m_db.execute(lq, &errorText)) {
            // unable to execute - the encryption key must be wrong (locked)
            *locked = true;
        } else {
            // able to execute - the encryption key is correct (unlocked)
            *locked = false;
        }
    }

    return retn;
}

Result
Daemon::ApiImpl::MetadataDatabase::lock()
{
    m_db.close();
    QSqlDatabase::removeDatabase(databaseConnectionName());
    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::unlock(
        const QByteArray &hexKey)
{
    Result retn(Result::Succeeded);
    if (hexKey.length() != 64) {
        retn = Result(Result::IncorrectAuthenticationCodeError,
                      QLatin1String("The bookkeeping database key is not a 256 bit key"));
    } else {
        if (!m_db.isOpen()) {
            if (!openDatabase(hexKey)) {
                retn = Result(Result::DatabaseError,
                              QStringLiteral("Unable to initialize the bookkeeping database with the given key"));
            }
        } else {
            const QString setupKeyStatement = QString::fromLatin1(setupEncryptionKey).arg(QString::fromLatin1(hexKey));
            QString errorText;
            Daemon::Sqlite::Database::Query kq = m_db.prepare(setupKeyStatement, &errorText);
            if (!errorText.isEmpty()) {
                retn = Result(Result::DatabaseQueryError,
                              QString::fromUtf8("Unable to prepare setup key query: %1").arg(errorText));
            } else if (!m_db.beginTransaction()) {
                retn = Result(Result::DatabaseTransactionError,
                              QString::fromUtf8("Unable to begin setup key transaction"));
            } else if (!m_db.execute(kq, &errorText)) {
                m_db.rollbackTransaction();
                retn = Result(Result::DatabaseQueryError,
                              QString::fromUtf8("Unable to execute setup key query: %1").arg(errorText));
            } else if (!m_db.commitTransaction()) {
                m_db.rollbackTransaction();
                retn = Result(Result::DatabaseTransactionError,
                              QString::fromUtf8("Unable to commit setup key transaction"));
            }
        }
    }

    return retn;
}

Result
Daemon::ApiImpl::MetadataDatabase::reencrypt(
        const QByteArray &oldHexKey,
        const QByteArray &newHexKey)
{
    Result retn = unlock(oldHexKey);
    if (retn.code() != Result::Succeeded) {
        return retn;
    }

    bool locked = false;
    retn = isLocked(&locked);
    if (retn.code() != Result::Succeeded) {
        return retn;
    }

    if (locked) {
        return Result(Result::CollectionIsLockedError,
                      QString::fromUtf8("The old bookkeeping key was not correct"));
    }

    if (newHexKey.length() != 64) {
        return Result(Result::IncorrectAuthenticationCodeError,
                      QLatin1String("The new bookkeeping key is not a 256 bit key"));
    }

    const QString setupReKeyStatement = QString::fromLatin1(setupReEncryptionKey).arg(QString::fromLatin1(newHexKey));
    QString errorText;
    Daemon::Sqlite::Database::Query kq = m_db.prepare(setupReKeyStatement, &errorText);
    if (!errorText.isEmpty()) {
        retn = Result(Result::DatabaseQueryError,
                      QString::fromUtf8("Unable to prepare setup rekey query: %1").arg(errorText));
    } else if (!m_db.beginTransaction()) {
        retn = Result(Result::DatabaseTransactionError,
                      QString::fromUtf8("Unable to begin setup rekey transaction"));
    } else if (!m_db.execute(kq, &errorText)) {
        m_db.rollbackTransaction();
        retn = Result(Result::DatabaseQueryError,
                      QString::fromUtf8("Unable to execute setup rekey query: %1").arg(errorText));
    } else if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        retn = Result(Result::DatabaseTransactionError,
                      QString::fromUtf8("Unable to commit setup rekey transaction"));
    }

    return retn;
}

//-------------------------------------------------------------------

Result
Daemon::ApiImpl::MetadataDatabase::insertCollectionMetadata(
        const CollectionMetadata &metadata)
{
    const QString insertCollectionQuery = QStringLiteral(
                "INSERT INTO Collections ("
                  "CollectionName,"
                  "ApplicationId,"
                  "UsesDeviceLockKey,"
                  "EncryptionPluginName,"
                  "AuthenticationPluginName,"
                  "UnlockSemantic,"
                  "AccessControlMode"
                ")"
                " VALUES ("
                  "?,?,?,?,?,?,?"
                ");");

    QString errorText;
    Daemon::Sqlite::Database::Query iq = m_db.prepare(insertCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare insert collection query: %1").arg(errorText));
    }

    QVariantList ivalues;
    ivalues << metadata.collectionName
            << metadata.ownerApplicationId
            << QVariant::fromValue<int>(metadata.usesDeviceLockKey ? 1 : 0)
            << metadata.encryptionPluginName
            << metadata.authenticationPluginName
            << metadata.unlockSemantic
            << static_cast<int>(metadata.accessControlMode);
    iq.bindValues(ivalues);

    if (!m_db.execute(iq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute insert collection query: %1").arg(errorText));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::collectionNames(
        QStringList *names,
        bool removeStandalone)
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
        if (!cname.isEmpty()) {
            if (!removeStandalone || cname.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) != 0) {
                names->append(cname);
            }
        }
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::collectionAlreadyExists(
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
Daemon::ApiImpl::MetadataDatabase::collectionMetadata(
        const QString &collectionName,
        CollectionMetadata *metadata,
        bool *exists)
{
    const QString selectCollectionQuery = QStringLiteral(
                 "SELECT"
                    " ApplicationId,"
                    " UsesDeviceLockKey,"
                    " EncryptionPluginName,"
                    " AuthenticationPluginName,"
                    " UnlockSemantic,"
                    " AccessControlMode"
                  " FROM Collections"
                  " WHERE CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select collection query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select collection query: %1").arg(errorText));
    }

    if (exists) *exists = false;
    if (sq.next()) {
        if (exists) *exists = true;
        metadata->ownerApplicationId = sq.value(0).value<QString>();
        metadata->usesDeviceLockKey = sq.value(1).value<int>() > 0;
        metadata->encryptionPluginName = sq.value(2).value<QString>();
        metadata->authenticationPluginName = sq.value(3).value<QString>();
        metadata->unlockSemantic = sq.value(4).value<int>();
        metadata->accessControlMode = static_cast<SecretManager::AccessControlMode>(sq.value(5).value<int>());
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::deleteCollectionMetadata(
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

    if (!m_db.execute(dq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute delete collection query: %1").arg(errorText));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::secretAlreadyExists(
        const QString &collectionName,
        const QString &secretName,
        bool *exists)
{
    const QString selectSecretsCountQuery = QStringLiteral(
                 "SELECT"
                    " Count(*)"
                  " FROM Secrets"
                  " WHERE CollectionName = ?"
                  " AND SecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query ssq = m_db.prepare(selectSecretsCountQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select secrets query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(secretName);
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
Daemon::ApiImpl::MetadataDatabase::insertSecretMetadata(
        const SecretMetadata &metadata)
{
    const QString insertSecretQuery = QStringLiteral(
                "INSERT INTO Secrets ("
                  "CollectionName,"
                  "SecretName,"
                  "ApplicationId,"
                  "UsesDeviceLockKey,"
                  "EncryptionPluginName,"
                  "AuthenticationPluginName,"
                  "UnlockSemantic,"
                  "AccessControlMode,"
                  "Type,"
                  "CryptoPluginName"
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
    ivalues << QVariant::fromValue<QString>(metadata.collectionName);
    ivalues << QVariant::fromValue<QString>(metadata.secretName);
    ivalues << QVariant::fromValue<QString>(metadata.ownerApplicationId);
    ivalues << QVariant::fromValue<int>(metadata.usesDeviceLockKey ? 1 : 0);
    ivalues << QVariant::fromValue<QString>(metadata.encryptionPluginName);
    ivalues << QVariant::fromValue<QString>(metadata.authenticationPluginName);
    ivalues << QVariant::fromValue<int>(metadata.unlockSemantic);
    ivalues << QVariant::fromValue<int>(static_cast<int>(metadata.accessControlMode));
    ivalues << QVariant::fromValue<QString>(metadata.secretType);
    ivalues << QVariant::fromValue<QString>(metadata.cryptoPluginName);
    iq.bindValues(ivalues);

    if (!m_db.execute(iq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute insert secret query: %1").arg(errorText));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::updateSecretMetadata(
        const SecretMetadata &metadata)
{
    const QString updateSecretQuery = QStringLiteral(
                 "UPDATE Secrets"
                 " SET ApplicationId = ?,"
                     " UsesDeviceLockKey = ?,"
                     " EncryptionPluginName = ?,"
                     " AuthenticationPluginName = ?,"
                     " UnlockSemantic = ?,"
                     " AccessControlMode = ?,"
                     " Type = ?,"
                     " CryptoPluginName = ?"
                 " WHERE CollectionName = ?"
                 " AND SecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query iq = m_db.prepare(updateSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare update secret query: %1").arg(errorText));
    }

    QVariantList ivalues;
    ivalues << QVariant::fromValue<QString>(metadata.ownerApplicationId);
    ivalues << QVariant::fromValue<int>(metadata.usesDeviceLockKey ? 1 : 0);
    ivalues << QVariant::fromValue<QString>(metadata.encryptionPluginName);
    ivalues << QVariant::fromValue<QString>(metadata.authenticationPluginName);
    ivalues << QVariant::fromValue<int>(metadata.unlockSemantic);
    ivalues << QVariant::fromValue<int>(static_cast<int>(metadata.accessControlMode));
    ivalues << QVariant::fromValue<QString>(metadata.secretType);
    ivalues << QVariant::fromValue<QString>(metadata.cryptoPluginName);
    ivalues << QVariant::fromValue<QString>(metadata.collectionName);
    ivalues << QVariant::fromValue<QString>(metadata.secretName);
    iq.bindValues(ivalues);

    if (!m_db.execute(iq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute update secret query: %1").arg(errorText));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::deleteSecretMetadata(
        const QString &collectionName,
        const QString &secretName)
{
    const QString deleteSecretQuery = QStringLiteral(
                "DELETE FROM Secrets"
                " WHERE CollectionName = ?"
                " AND SecretName = ?;");

    QString errorText;
    Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare delete secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(secretName);
    dq.bindValues(values);

    if (!m_db.execute(dq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute delete secret query: %1").arg(errorText));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::secretMetadata(
        const QString &collectionName,
        const QString &secretName,
        SecretMetadata *metadata,
        bool *exists)
{
    const QString selectSecretsQuery = QStringLiteral(
                 "SELECT"
                    " ApplicationId,"
                    " UsesDeviceLockKey,"
                    " EncryptionPluginName,"
                    " AuthenticationPluginName,"
                    " UnlockSemantic,"
                    " AccessControlMode"
                  " FROM Secrets"
                  " WHERE CollectionName = ?"
                  " AND SecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectSecretsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select secrets query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(secretName);
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select secrets query: %1").arg(errorText));
    }

    if (exists) *exists = false;
    if (sq.next()) {
        if (exists) *exists = true;
        metadata->ownerApplicationId = sq.value(0).value<QString>();
        metadata->usesDeviceLockKey = sq.value(1).value<int>() > 0;
        metadata->encryptionPluginName = sq.value(2).value<QString>();
        metadata->authenticationPluginName = sq.value(3).value<QString>();
        metadata->unlockSemantic = sq.value(4).value<int>();
        metadata->accessControlMode = static_cast<SecretManager::AccessControlMode>(sq.value(5).value<int>());
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::secretNames(
        const QString &collectionName,
        QStringList *names)
{
    const QString selectSecretNamesQuery = QStringLiteral(
                 "SELECT SecretName"
                 " FROM Secrets"
                 " WHERE CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectSecretNamesQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select secret names query: %1").arg(errorText));
    }

    QVariantList values;
    values << collectionName;
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select secret names query: %1").arg(errorText));
    }

    while (sq.next()) {
        const QString sname = sq.value(0).value<QString>();
        names->append(sname);
    }

    return Result(Result::Succeeded);
}

Result
Daemon::ApiImpl::MetadataDatabase::keyNames(
        const QString &collectionName,
        QStringList *names)
{
    const QString selectKeyNamesQuery = QStringLiteral(
                 "SELECT SecretName"
                 " FROM Secrets"
                 " WHERE CollectionName = ?"
                 " AND Type = 'CryptoKey';"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectKeyNamesQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to prepare select key names query: %1").arg(errorText));
    }

    QVariantList values;
    values << collectionName;
    sq.bindValues(values);

    if (!m_db.execute(sq, &errorText)) {
        return Result(Result::DatabaseQueryError,
                      QString::fromLatin1("Unable to execute select key names query: %1").arg(errorText));
    }

    while (sq.next()) {
        const QString sname = sq.value(0).value<QString>();
        names->append(sname);
    }

    return Result(Result::Succeeded);
}

bool Daemon::ApiImpl::MetadataDatabase::initializeCollectionsFromPluginData(
        const QStringList &existingCollectionNames)
{
    // retrieve the cnames from the metadata db
    QStringList cnames;
    Result result = collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return false;
    }

    bool modificationsSucceeded = true;

    // delete any collection in metadata db which is not in plugin
    for (const QString &cname : cnames) {
        if (!existingCollectionNames.contains(cname)) {
            if (deleteCollectionMetadata(cname).code() != Result::Succeeded) {
                modificationsSucceeded = false;
            }
        }
    }
    // add any collection which is not in metadata db to it.
    // TODO: this is imprecise, as we've "lost" information.
    //       we just assume "default" values but it may be incorrect.
    // FIXME: how should we fix this issue?
    for (const QString &cname : existingCollectionNames) {
        if (!cnames.contains(cname)) {
            CollectionMetadata defaultMetadata;
            defaultMetadata.collectionName = cname;
            defaultMetadata.ownerApplicationId = QStringLiteral("imported");
            defaultMetadata.usesDeviceLockKey = false;
            defaultMetadata.encryptionPluginName = m_pluginIsEncryptedStorage
                                                 ? m_storagePluginName
                                                 : m_defaultEncryptionPluginName;
            defaultMetadata.authenticationPluginName = m_defaultAuthenticationPluginName;
            defaultMetadata.unlockSemantic = SecretManager::CustomLockKeepUnlocked;
            defaultMetadata.accessControlMode = SecretManager::NoAccessControlMode;
            if (insertCollectionMetadata(defaultMetadata).code() != Result::Succeeded) {
                modificationsSucceeded = false;
            }
        }
    }

    return modificationsSucceeded;
}

bool Daemon::ApiImpl::MetadataDatabase::initializeSecretsFromPluginData(
        const QVector<Secret::Identifier> &identifiers,
        const QStringList &lockedCollectionNames)
{
    // build up map of metadata identifiers, sorted by collection name
    QMap<QString, QStringList> metadataCNameToSNames;
    QStringList cnames;
    Result result = collectionNames(&cnames);
    if (result.code() != Result::Succeeded) {
        return false;
    }
    for (const QString &cname : cnames) {
        QStringList snames;
        result = secretNames(cname, &snames);
        if (result.code() != Result::Succeeded) {
            return false;
        }
        metadataCNameToSNames.insert(cname, snames);
    }

    // build up map of plugin data identifiers, sorted by collection name
    QMap<QString, QStringList> pluginCNameToSNames;
    for (const Secret::Identifier &ident : identifiers) {
        pluginCNameToSNames[ident.collectionName()].append(ident.name());
    }

    bool modificationsSucceeded = true;

    // delete any secret in metadata db which is not in plugin
    for (const QString &cname : metadataCNameToSNames.keys()) {
        const QStringList &snames(metadataCNameToSNames[cname]);
        // don't delete secrets in locked collections, as we won't
        // know which ones still exist or not.
        if (!lockedCollectionNames.contains(cname)) {
            for (const QString &sname : snames) {
                if (!pluginCNameToSNames.contains(cname)
                        || !pluginCNameToSNames[cname].contains(sname)) {
                    // delete this secret, it must have been removed from the plugin.
                    if (deleteSecretMetadata(cname, sname).code() != Result::Succeeded) {
                        modificationsSucceeded = false;
                    }
                }
            }
        }
    }
    // add any secret which is not in metadata db to it.
    // TODO: this is imprecise, as we've "lost" information.
    //       we just assume "default" values but it may be incorrect.
    // FIXME: how should we fix this issue?
    for (const QString &cname : pluginCNameToSNames.keys()) {
        const QStringList &snames(pluginCNameToSNames[cname]);
        for (const QString &sname : snames) {
            if (!metadataCNameToSNames.contains(cname)
                    || !metadataCNameToSNames[cname].contains(sname)) {
                // add this secret, it must have been added to the plugin.
                SecretMetadata defaultMetadata;
                defaultMetadata.collectionName = cname;
                defaultMetadata.secretName = sname;
                defaultMetadata.ownerApplicationId = QStringLiteral("imported");
                defaultMetadata.usesDeviceLockKey = false;
                defaultMetadata.encryptionPluginName = m_pluginIsEncryptedStorage
                                                     ? m_storagePluginName
                                                     : m_defaultEncryptionPluginName;
                defaultMetadata.authenticationPluginName = m_defaultAuthenticationPluginName;
                defaultMetadata.unlockSemantic = SecretManager::CustomLockKeepUnlocked;
                defaultMetadata.accessControlMode = SecretManager::NoAccessControlMode;
                if (insertSecretMetadata(defaultMetadata).code() != Result::Succeeded) {
                    modificationsSucceeded = false;
                }
            }
        }
    }

    return modificationsSucceeded;
}
