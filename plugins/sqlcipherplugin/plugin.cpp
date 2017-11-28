/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

#include <QStandardPaths>
#include <QFile>
#include <QCryptographicHash>

Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptedStoragePlugin_IID)

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

static const char *createSecretsTable =
        "\n CREATE TABLE Secrets ("
        "   HashedSecretName TEXT NOT NULL,"
        "   SecretName TEXT NOT NULL,"
        "   Secret BLOB,"
        "   Timestamp DATE,"
        "   PRIMARY KEY (HashedSecretName));";

static const char *createSecretsFilterDataTable =
        "\n CREATE TABLE SecretsFilterData ("
        "   HashedSecretName TEXT NOT NULL,"
        "   Field TEXT NOT NULL,"
        "   Value TEXT,"
        "   FOREIGN KEY (HashedSecretName) REFERENCES Secrets (HashedSecretName) ON DELETE CASCADE,"
        "   PRIMARY KEY (HashedSecretName, Field));";

static const char *createStatements[] =
{
    createSecretsTable,
    createSecretsFilterDataTable,
    NULL
};

static Sailfish::Secrets::Daemon::Sqlite::UpgradeOperation upgradeVersions[] = {
    { 0, 0 },
};

static const int currentSchemaVersion = 1;

namespace {
    QString databaseDirPath(bool isTestPlugin, const QString &databaseSubdir) {
        // note: these paths are very dependent upon the implementation of database.cpp
        const QString systemDataDirPath(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + QLatin1String("/system/"));
        const QString privilegedDataDirPath(systemDataDirPath + QLatin1String("privileged/"));
        const QString subdir = isTestPlugin
                             ? QString(QLatin1String("Secrets/%1/")).arg(databaseSubdir)
                             : QString(QLatin1String("Secrets/%1-test/")).arg(databaseSubdir);
        return privilegedDataDirPath + subdir;
    }
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::openCollectionDatabase(
        const QString &collectionName,
        const QByteArray &key,
        bool createIfNotExists)
{
    Sailfish::Secrets::Result retn(Sailfish::Secrets::Result::Succeeded);
    const QByteArray hexKey = key.toHex().length() == 64
                            ? key.toHex()
                            : QCryptographicHash::hash(key, QCryptographicHash::Sha256).toHex();
    if (hexKey.length() != 64) {
        retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::IncorrectAuthenticationKeyError,
                                         QLatin1String("The given key is not a 256 bit key, and could not be converted to one"));
    } else {
        const QByteArray setupKeyStatement = QString::fromLatin1(setupEncryptionKey).arg(QLatin1String(hexKey)).toLatin1();
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

        const QString databaseFilename = collectionName + QLatin1String(".db");
        const bool exists = QFile::exists(databaseFilename);
        if (!exists && !createIfNotExists) {
            retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseError,
                                             QLatin1String("The collection database doesn't exist"));
        } else {
            Sailfish::Secrets::Daemon::Sqlite::Database *db = new Sailfish::Secrets::Daemon::Sqlite::Database;
            if (!db->open(QLatin1String("QSQLCIPHER"),
                          m_databaseSubdir,
                          databaseFilename,
                          setupStatements,
                          createStatements,
                          upgradeVersions,
                          currentSchemaVersion,
                          collectionName,
                          isTestPlugin())) {
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseError,
                                                 QLatin1String("SQLCipher plugin was unable to open the collection database"));
            } else {
                m_collectionDatabases.insert(collectionName, db);
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
            }
        }
    }
    return retn;
}

Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::SqlCipherPlugin(QObject *parent)
    : Sailfish::Secrets::EncryptedStoragePlugin(parent)
    , m_databaseSubdir(QLatin1String("sqlcipherplugin"))
    , m_databaseDirPath(databaseDirPath(isTestPlugin(), m_databaseSubdir))
{
}

Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::~SqlCipherPlugin()
{
    // for each collection db in cache, close and delete.
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::createCollection(
        const QString &collectionName,
        const QByteArray &key)
{
    Sailfish::Secrets::Result retn(Sailfish::Secrets::Result::OperationNotSupportedError,
                                   QLatin1String("TODO: SQLCIPHER"));
    bool validName = collectionName.size() <= 31;
    if (!validName) {
        retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QLatin1String("SQLCipher plugin only supports collection names shorter than 32 characters"));
    } else {
        for (QString::const_iterator it = collectionName.constBegin(); it != collectionName.constEnd(); it++) {
            const char curr = it->toLatin1();
            if (curr == 0
                    || !((curr >= 48 && curr <= 57)
                      || (curr >= 65 && curr <= 90)
                      || (curr >= 97 && curr <= 122))) {
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                                 QLatin1String("SQLCipher plugin only supports collection names with alphanumeric Latin-1 characters"));
                validName = false;
                break;
            }
        }
    }

    if (validName) {
        const QString databaseFilename = collectionName + QLatin1String(".db");
        const QString collectionPath = m_databaseDirPath + databaseFilename;
        if (QFile::exists(collectionPath) || m_collectionDatabases.contains(collectionName)) {
            retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::CollectionAlreadyExistsError,
                                             QLatin1String("A collection with that name already exists"));
        } else {
            // create a new database to hold this collection.
            retn = openCollectionDatabase(collectionName, key, true);
        }
    }

    return retn;
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::removeCollection(
        const QString &collectionName)
{
    Sailfish::Secrets::Result retn(Sailfish::Secrets::Result::Succeeded);
    delete m_collectionDatabases.take(collectionName);
    const QString collectionPath = m_databaseDirPath + collectionName + QLatin1String(".db");
    if (QFile::exists(collectionPath)) {
        if (!QFile::remove(collectionPath)) {
            retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                             QLatin1String("SQLCipher plugin: failed to remove collection database!"));
        }
    }
    return retn;
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::isLocked(
        const QString &collectionName,
        bool *locked)
{
    Sailfish::Secrets::Result retn(Sailfish::Secrets::Result::Succeeded);
    Sailfish::Secrets::Daemon::Sqlite::Database *db = m_collectionDatabases.value(collectionName);
    if (db) {
        // The collection has been opened in the past, check to see if it is locked.
        const QString lockedQuery = QStringLiteral("SELECT Count(*) FROM sqlite_master;");
        QString errorText;
        Sailfish::Secrets::Daemon::Sqlite::Database::Query lq = db->prepare(lockedQuery, &errorText);
        if (!errorText.isEmpty()) {
            retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("SQLCipher plugin unable to prepare is locked query: %1").arg(errorText));
        } else if (!db->execute(lq, &errorText)) {
qWarning() << "XXXXXXXXXXXXX is locked query error:" << errorText;
            *locked = true;
        } else {
            *locked = false;
        }
    } else {
        // the collection is either locked (not opened), or it doesn't exist.
        const QString collectionPath = m_databaseDirPath + collectionName + QLatin1String(".db");
        if (QFile::exists(collectionPath)) {
            *locked = true;
        } else {
            retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                             QLatin1String("No collection with that name exists"));
        }
    }

    return retn;
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::setEncryptionKey(
        const QString &collectionName,
        const QByteArray &key)
{
    Sailfish::Secrets::Result retn(Sailfish::Secrets::Result::Succeeded);
    Sailfish::Secrets::Daemon::Sqlite::Database *db = m_collectionDatabases.value(collectionName);
    if (db) {
        const QByteArray hexKey = key.toHex().length() == 64
                                ? key.toHex()
                                : QCryptographicHash::hash(key, QCryptographicHash::Sha256).toHex();
        if (hexKey.length() != 64) {
            retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::IncorrectAuthenticationKeyError,
                                             QLatin1String("The given key is not a 256 bit key, and could not be converted to one"));
        } else {
            Sailfish::Secrets::Daemon::Sqlite::DatabaseLocker locker(db);
            const QString setupKeyStatement = QString::fromLatin1(setupEncryptionKey).arg(QLatin1String(hexKey));
            QString errorText;
            Sailfish::Secrets::Daemon::Sqlite::Database::Query kq = db->prepare(setupKeyStatement, &errorText);
            if (!errorText.isEmpty()) {
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                                 QString::fromUtf8("SQLCipher plugin unable to prepare setup key query: %1").arg(errorText));
            } else if (!db->beginTransaction()) {
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                                 QString::fromUtf8("SQLCipher plugin unable to begin setup key transaction"));
            } else if (!db->execute(kq, &errorText)) {
                db->rollbackTransaction();
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                                 QString::fromUtf8("SQLCipher plugin unable to execute setup key query: %1").arg(errorText));
            } else if (!db->commitTransaction()) {
                db->rollbackTransaction();
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                                 QString::fromUtf8("SQLCipher plugin unable to commit setup key transaction"));
            }
        }
    } else {
        retn = openCollectionDatabase(collectionName, key, false);
    }

    return retn;
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::reencrypt(
        const QString &collectionName,
        const QByteArray &oldkey,
        const QByteArray &newkey)
{
    Sailfish::Secrets::Result retn = setEncryptionKey(collectionName, oldkey);
    if (retn.code() == Sailfish::Secrets::Result::Succeeded) {
        Sailfish::Secrets::Daemon::Sqlite::Database *db = m_collectionDatabases.value(collectionName);
        if (!db) {
            retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::UnknownError,
                                             QLatin1String("Unable to open collection database for rekeying"));
        } else {
            const QByteArray hexKey = newkey.toHex().length() == 64
                                    ? newkey.toHex()
                                    : QCryptographicHash::hash(newkey, QCryptographicHash::Sha256).toHex();
            if (hexKey.length() != 64) {
                retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::IncorrectAuthenticationKeyError,
                                                 QLatin1String("The given key is not a 256 bit key, and could not be converted to one"));
            } else {
                Sailfish::Secrets::Daemon::Sqlite::DatabaseLocker locker(db);
                const QString setupReKeyStatement = QString::fromLatin1(setupReEncryptionKey).arg(QLatin1String(hexKey));
                QString errorText;
                Sailfish::Secrets::Daemon::Sqlite::Database::Query kq = db->prepare(setupReKeyStatement, &errorText);
                if (!errorText.isEmpty()) {
                    retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                                     QString::fromUtf8("SQLCipher plugin unable to prepare setup rekey query: %1").arg(errorText));
                } else if (!db->beginTransaction()) {
                    retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                                     QString::fromUtf8("SQLCipher plugin unable to begin setup rekey transaction"));
                } else if (!db->execute(kq, &errorText)) {
                    db->rollbackTransaction();
                    retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                                     QString::fromUtf8("SQLCipher plugin unable to execute setup rekey query: %1").arg(errorText));
                } else if (!db->commitTransaction()) {
                    db->rollbackTransaction();
                    retn = Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                                     QString::fromUtf8("SQLCipher plugin unable to commit setup rekey transaction"));
                }
            }
        }
    }

    return retn;
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::setSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QString &secretName,
        const QByteArray &secret,
        const Sailfish::Secrets::Secret::FilterData &filterData)
{
    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (hashedSecretName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    }

    Sailfish::Secrets::Daemon::Sqlite::Database *db = m_collectionDatabases.value(collectionName);
    if (!db) {
        const QString collectionPath = m_databaseDirPath + collectionName + QLatin1String(".db");
        return QFile::exists(collectionPath)
                ? Sailfish::Secrets::Result(Sailfish::Secrets::Result::CollectionIsLockedError,
                                            QLatin1String("That collection is locked"))
                : Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                            QLatin1String("No collection with that name exists"));
    }

    Sailfish::Secrets::Daemon::Sqlite::DatabaseLocker locker(db);

    const QString selectSecretsCountQuery = QStringLiteral(
                 "SELECT"
                    " Count(*)"
                  " FROM Secrets"
                  " WHERE HashedSecretName = ?;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query sq = db->prepare(selectSecretsCountQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare select secrets query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(hashedSecretName);
    sq.bindValues(values);

    if (!db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to begin transaction"));
    }

    if (!db->execute(sq, &errorText)) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to execute select secrets query: %1").arg(errorText));
    }

    bool found = false;
    if (sq.next()) {
        found = sq.value(0).value<int>() > 0;
    }

    const QString updateSecretQuery = QStringLiteral(
                 "UPDATE Secrets"
                 " SET Secret = ?"
                 "   , Timestamp = date('now')"
                 " WHERE HashedSecretName = ?;"
             );
    const QString insertSecretQuery = QStringLiteral(
                "INSERT INTO Secrets ("
                  "HashedSecretName,"
                  "SecretName,"
                  "Secret,"
                  "Timestamp"
                ")"
                " VALUES ("
                  "?,?,?,date('now')"
                ");");

    Sailfish::Secrets::Daemon::Sqlite::Database::Query iq = db->prepare(found ? updateSecretQuery : insertSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare insert secret query: %1").arg(errorText));
    }

    QVariantList ivalues;
    if (found) {
        ivalues << QVariant::fromValue<QByteArray>(secret);
        ivalues << QVariant::fromValue<QString>(hashedSecretName);
    } else {
        ivalues << QVariant::fromValue<QString>(hashedSecretName);
        ivalues << QVariant::fromValue<QString>(secretName);
        ivalues << QVariant::fromValue<QByteArray>(secret);
    }
    iq.bindValues(ivalues);

    if (!db->execute(iq, &errorText)) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to execute insert secret query: %1").arg(errorText));
    }

    const QString deleteSecretsFilterDataQuery = QStringLiteral(
                 "DELETE FROM SecretsFilterData"
                 " WHERE HashedSecretName = ?;"
             );

    Sailfish::Secrets::Daemon::Sqlite::Database::Query dq = db->prepare(deleteSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare delete secrets filter data query: %1").arg(errorText));
    }

    QVariantList dvalues;
    dvalues << QVariant::fromValue<QString>(hashedSecretName);
    dq.bindValues(dvalues);

    if (!db->execute(dq, &errorText)) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to execute delete secrets filter data query: %1").arg(errorText));
    }

    const QString insertSecretsFilterDataQuery = QStringLiteral(
                "INSERT INTO SecretsFilterData ("
                  "HashedSecretName,"
                  "Field,"
                  "Value"
                ")"
                " VALUES ("
                  "?,?,?"
                ");");

    Sailfish::Secrets::Daemon::Sqlite::Database::Query ifdq = db->prepare(insertSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare insert secrets filter data query: %1").arg(errorText));
    }

    for (Sailfish::Secrets::Secret::FilterData::const_iterator it = filterData.constBegin(); it != filterData.constEnd(); it++) {
        ivalues.clear();
        ivalues << QVariant::fromValue<QString>(hashedSecretName);
        ivalues << QVariant::fromValue<QString>(it.key());
        ivalues << QVariant::fromValue<QString>(it.value());
        ifdq.bindValues(ivalues);
        if (!db->execute(ifdq, &errorText)) {
            db->rollbackTransaction();
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("SQLCipher plugin unable to execute insert secrets filter data query: %1").arg(errorText));
        }
    }

    if (!db->commitTransaction()) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to commit insert secret transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::getSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        QString *secretName,
        QByteArray *secret,
        Sailfish::Secrets::Secret::FilterData *filterData)
{
    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (hashedSecretName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    }

    Sailfish::Secrets::Daemon::Sqlite::Database *db = m_collectionDatabases.value(collectionName);
    if (!db) {
        const QString collectionPath = m_databaseDirPath + collectionName + QLatin1String(".db");
        return QFile::exists(collectionPath)
                ? Sailfish::Secrets::Result(Sailfish::Secrets::Result::CollectionIsLockedError,
                                            QLatin1String("That collection is locked"))
                : Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                            QLatin1String("No collection with that name exists"));
    }

    Sailfish::Secrets::Daemon::Sqlite::DatabaseLocker locker(db);

    const QString selectSecretQuery = QStringLiteral(
                 "SELECT"
                    " SecretName,"
                    " Secret"
                  " FROM Secrets"
                  " WHERE HashedSecretName = ?;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query sq = db->prepare(selectSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare select secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(hashedSecretName);
    sq.bindValues(values);

    if (!db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to begin transaction"));
    }

    if (!db->execute(sq, &errorText)) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to execute select secret query: %1").arg(errorText));
    }

    bool found = false;
    QByteArray secretNameData;
    QByteArray secretData;
    if (sq.next()) {
        found = true;
        secretNameData = sq.value(0).value<QByteArray>();
        secretData = sq.value(1).value<QByteArray>();
    }

    Sailfish::Secrets::Secret::FilterData secretFilterData;
    if (found) {
        const QString selectSecretFilterDataQuery = QStringLiteral(
                     "SELECT"
                        " Field,"
                        " Value"
                      " FROM SecretsFilterData"
                      " WHERE HashedSecretName = ?;"
                 );

        Sailfish::Secrets::Daemon::Sqlite::Database::Query sfdq = db->prepare(selectSecretFilterDataQuery, &errorText);
        if (!errorText.isEmpty()) {
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("SQLCipher plugin unable to prepare select secret filter data query: %1").arg(errorText));
        }
        sfdq.bindValues(values);

        if (!db->execute(sfdq, &errorText)) {
            db->rollbackTransaction();
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("SQLCipher plugin unable to execute select secret filter data query: %1").arg(errorText));
        }

        while (sfdq.next()) {
            secretFilterData.insert(sfdq.value(0).value<QString>(), sfdq.value(1).value<QString>());
        }
    }

    if (!db->commitTransaction()) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to commit select secret transaction"));
    }

    if (!found) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("No such secret stored"));
    }

    *secretName = secretNameData;
    *secret = secretData;
    *filterData = secretFilterData;
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::findSecrets(
        const QString &collectionName,
        const Sailfish::Secrets::Secret::FilterData &filter,
        Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator,
        QVector<Sailfish::Secrets::Secret::Identifier> *identifiers)
{
    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (filter.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidFilterError,
                                         QString::fromUtf8("Empty filter given"));
    }

    Sailfish::Secrets::Daemon::Sqlite::Database *db = m_collectionDatabases.value(collectionName);
    if (!db) {
        const QString collectionPath = m_databaseDirPath + collectionName + QLatin1String(".db");
        return QFile::exists(collectionPath)
                ? Sailfish::Secrets::Result(Sailfish::Secrets::Result::CollectionIsLockedError,
                                            QLatin1String("That collection is locked"))
                : Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                            QLatin1String("No collection with that name exists"));
    }

    Sailfish::Secrets::Daemon::Sqlite::DatabaseLocker locker(db);

    // very naive implementation.
    // first, select all of the field/value filter data for the secret
    // second, filter in-memory.
    // third, return the encrypted secret names associated with the matches.

    const QString selectSecretsFilterDataQuery = QStringLiteral(
                 "SELECT"
                    " HashedSecretName,"
                    " Field,"
                    " Value"
                 " FROM SecretsFilterData;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query sq = db->prepare(selectSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare select secrets filter data query: %1").arg(errorText));
    }

    if (!db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to begin find secrets transaction"));
    }

    if (!db->execute(sq, &errorText)) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to execute select secrets filter data query: %1").arg(errorText));
    }

    QMap<QString, Sailfish::Secrets::Secret::FilterData > hashedSecretNameToFilterData;
    while (sq.next()) {
        hashedSecretNameToFilterData[sq.value(0).value<QString>()].insert(sq.value(1).value<QString>(), sq.value(2).value<QString>());
    }

    // perform in-memory filtering.
    QSet<QString> matchingHashedSecretNames;
    for (QMap<QString, Sailfish::Secrets::Secret::FilterData >::const_iterator it = hashedSecretNameToFilterData.constBegin(); it != hashedSecretNameToFilterData.constEnd(); it++) {
        const Sailfish::Secrets::Secret::FilterData &currFilterData(it.value());
        bool matches = filterOperator == Sailfish::Secrets::StoragePlugin::OperatorOr ? false : true;
        for (Sailfish::Secrets::Secret::FilterData::const_iterator fit = filter.constBegin(); fit != filter.constEnd(); fit++) {
            bool found = false;
            for (Sailfish::Secrets::Secret::FilterData::const_iterator mit = currFilterData.constBegin(); mit != currFilterData.constEnd(); mit++) {
                if (fit.key().compare(mit.key(), Qt::CaseInsensitive) == 0) {
                    found = true; // found a matching metadata field for this filter field
                    if (fit.value().compare(mit.value(), Qt::CaseInsensitive) == 0) {
                        // the metadata value matches the filter value
                        if (filterOperator == Sailfish::Secrets::StoragePlugin::OperatorOr) {
                            // we have a match!
                            matches = true;
                        }
                    } else {
                        if (filterOperator == Sailfish::Secrets::StoragePlugin::OperatorAnd) {
                            // we know that this one doesn't match.
                            matches = false;
                        }
                    }
                    break; // mit
                }
            }
            if (!found && filterOperator == Sailfish::Secrets::StoragePlugin::OperatorAnd) {
                // the metadata is missing a required filter field.
                matches = false;
                break; // fit
            }
        }
        if (matches) {
            matchingHashedSecretNames.insert(it.key());
        }
    }

    // now select all of the secret names associated with the hashed names and return them.
    const QString selectSecretName = QStringLiteral(
                 "SELECT"
                    " SecretName"
                 " FROM Secrets"
                 " WHERE HashedSecretName = ?;"
             );

    Sailfish::Secrets::Daemon::Sqlite::Database::Query seq = db->prepare(selectSecretName, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare select secret name query: %1").arg(errorText));
    }

    QVector<Sailfish::Secrets::Secret::Identifier> retn;
    for (const QString &hashedSecretName : matchingHashedSecretNames) {
        QVariantList values;
        values << QVariant::fromValue<QString>(hashedSecretName);
        seq.bindValues(values);

        if (!db->execute(seq, &errorText)) {
            db->rollbackTransaction();
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("SQLCipher plugin unable to execute select secret name query: %1").arg(errorText));
        }

        if (seq.next()) {
            retn.append(Sailfish::Secrets::Secret::Identifier(seq.value(0).value<QString>(), collectionName));
        }
    }

    if (!db->commitTransaction()) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to commit find secrets transaction"));
    }

    *identifiers = retn;
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::removeSecret(
        const QString &collectionName,
        const QString &hashedSecretName)
{
    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (hashedSecretName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    }

    Sailfish::Secrets::Daemon::Sqlite::Database *db = m_collectionDatabases.value(collectionName);
    if (!db) {
        const QString collectionPath = m_databaseDirPath + collectionName + QLatin1String(".db");
        return QFile::exists(collectionPath)
                ? Sailfish::Secrets::Result(Sailfish::Secrets::Result::CollectionIsLockedError,
                                            QLatin1String("That collection is locked"))
                : Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                            QLatin1String("No collection with that name exists"));
    }

    Sailfish::Secrets::Daemon::Sqlite::DatabaseLocker locker(db);

    const QString deleteSecretQuery = QStringLiteral(
                "DELETE FROM Secrets"
                " WHERE HashedSecretName = ?;");

    QString errorText;
    Sailfish::Secrets::Daemon::Sqlite::Database::Query dq = db->prepare(deleteSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to prepare delete secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(hashedSecretName);
    dq.bindValues(values);

    if (!db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to begin transaction"));
    }

    if (!db->execute(dq, &errorText)) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("SQLCipher plugin unable to execute delete secret query: %1").arg(errorText));
    }

    if (!db->commitTransaction()) {
        db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("SQLCipher plugin unable to commit delete secret transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}


Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::setSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QString &secretName,
        const QByteArray &secret,
        const Sailfish::Secrets::Secret::FilterData &filterData,
        const QByteArray &key)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(hashedSecretName);
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    Q_UNUSED(key);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                     QLatin1String("SQLCipher plugin doesn't support standalone secret operations"));
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::accessSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QByteArray &key,
        QString *secretName,
        QByteArray *secret,
        Sailfish::Secrets::Secret::FilterData *filterData)
{
    Q_UNUSED(collectionName);
    Q_UNUSED(hashedSecretName);
    Q_UNUSED(secretName);
    Q_UNUSED(secret);
    Q_UNUSED(filterData);
    Q_UNUSED(key);
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::OperationNotSupportedError,
                                     QLatin1String("SQLCipher plugin doesn't support standalone secret operations"));
}

