/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"
#include "sqlitedatabase_p.h"

Q_PLUGIN_METADATA(IID Sailfish_Secrets_StoragePlugin_IID)

Q_LOGGING_CATEGORY(lcSailfishSecretsPluginSqlite, "org.sailfishos.secrets.plugin.storage.sqlite", QtWarningMsg)

using namespace Sailfish::Secrets;

Daemon::Plugins::SqlitePlugin::SqlitePlugin(QObject *parent)
    : StoragePlugin(parent)
{
}

void Daemon::Plugins::SqlitePlugin::openDatabaseIfNecessary()
{
    if (m_db.isOpen()) {
        return;
    }

#ifdef SAILFISHSECRETS_TESTPLUGIN
    bool autotestMode = true;
#else
    bool autotestMode = false;
#endif
    if (!m_db.open(QLatin1String("QSQLITE"),
                   QLatin1String("sqliteplugin"),
                   QLatin1String("secrets.db"),
                   setupStatements,
                   createStatements,
                   upgradeVersions,
                   currentSchemaVersion,
                   QLatin1String("sqliteplugin"),
                   autotestMode)) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Secrets sqlite plugin: failed to open database!";
        return;
    }

    // Add the "standalone" collection.
    // Note that it is a "notional" collection,
    // existing only to satisfy the database constraints.
    const QString insertCollectionQuery = QStringLiteral(
                "INSERT INTO Collections ("
                  "CollectionName"
                ")"
                " VALUES ("
                  "?"
                ");");

    QString errorText;
    Daemon::Sqlite::Database::Query iq = m_db.prepare(insertCollectionQuery, &errorText);

    QVariantList ivalues;
    ivalues << QVariant::fromValue<QString>(QLatin1String("standalone"));;
    iq.bindValues(ivalues);

    if (m_db.beginTransaction()) {
        if (m_db.execute(iq, &errorText)) {
            m_db.commitTransaction();
        } else {
            m_db.rollbackTransaction();
        }
    }
}

Daemon::Plugins::SqlitePlugin::~SqlitePlugin()
{
}

Result
Daemon::Plugins::SqlitePlugin::createCollection(
        const QString &collectionName)
{
    openDatabaseIfNecessary();
    Daemon::Sqlite::DatabaseLocker locker(&m_db);

    if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Reserved collection name given"));
    }

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
                                         QString::fromUtf8("Sqlite plugin unable to prepare select collections query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db.execute(sq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select collections query: %1").arg(errorText));
    }

    bool found = false;
    if (sq.next()) {
        found = sq.value(0).value<int>() > 0;
    }

    if (found) {
        m_db.rollbackTransaction();
        return Result(Result::CollectionAlreadyExistsError,
                                         QString::fromUtf8("Collection already exists: %1").arg(collectionName));
    }

    const QString insertCollectionQuery = QStringLiteral(
                "INSERT INTO Collections ("
                  "CollectionName"
                ")"
                " VALUES ("
                  "?"
                ");");

    Daemon::Sqlite::Database::Query iq = m_db.prepare(insertCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare insert collection query: %1").arg(errorText));
    }

    QVariantList ivalues;
    ivalues << QVariant::fromValue<QString>(collectionName);
    iq.bindValues(ivalues);

    if (!m_db.execute(iq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute insert collection query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit insert collection transaction"));
    }

    return Result(Result::Succeeded);
}


Result
Daemon::Plugins::SqlitePlugin::removeCollection(
        const QString &collectionName)
{
    openDatabaseIfNecessary();
    Daemon::Sqlite::DatabaseLocker locker(&m_db);

    if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Reserved collection name given"));
    }

    const QString deleteCollectionQuery = QStringLiteral(
                "DELETE FROM Collections"
                " WHERE CollectionName = ?;");

    QString errorText;
    Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare delete collection query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    dq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db.execute(dq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute delete collection query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit delete collection transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::SqlitePlugin::setSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QByteArray &encryptedSecretName,
        const QByteArray &secret,
        const Secret::FilterData &filterData)
{
    openDatabaseIfNecessary();
    Daemon::Sqlite::DatabaseLocker locker(&m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (hashedSecretName.isEmpty()) {
        return Result(Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    }

    const QString selectSecretsCountQuery = QStringLiteral(
                 "SELECT"
                    " Count(*)"
                  " FROM Secrets"
                  " WHERE CollectionName = ?"
                  " AND HashedSecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectSecretsCountQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secrets query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(hashedSecretName);
    sq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db.execute(sq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select secrets query: %1").arg(errorText));
    }

    bool found = false;
    if (sq.next()) {
        found = sq.value(0).value<int>() > 0;
    }

    const QString updateSecretQuery = QStringLiteral(
                 "UPDATE Secrets"
                 " SET Secret = ?"
                 "   , Timestamp = date('now')"
                 " WHERE CollectionName = ?"
                 " AND HashedSecretName = ?;"
             );
    const QString insertSecretQuery = QStringLiteral(
                "INSERT INTO Secrets ("
                  "CollectionName,"
                  "HashedSecretName,"
                  "EncryptedSecretName,"
                  "Secret,"
                  "Timestamp"
                ")"
                " VALUES ("
                  "?,?,?,?,date('now')"
                ");");

    Daemon::Sqlite::Database::Query iq = m_db.prepare(found ? updateSecretQuery : insertSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare insert secret query: %1").arg(errorText));
    }

    QVariantList ivalues;
    if (found) {
        ivalues << QVariant::fromValue<QByteArray>(secret);
        ivalues << QVariant::fromValue<QString>(collectionName);
        ivalues << QVariant::fromValue<QString>(hashedSecretName);
    } else {
        ivalues << QVariant::fromValue<QString>(collectionName);
        ivalues << QVariant::fromValue<QString>(hashedSecretName);
        ivalues << QVariant::fromValue<QByteArray>(encryptedSecretName);
        ivalues << QVariant::fromValue<QByteArray>(secret);
    }
    iq.bindValues(ivalues);

    if (!m_db.execute(iq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute insert secret query: %1").arg(errorText));
    }

    const QString deleteSecretsFilterDataQuery = QStringLiteral(
                 "DELETE FROM SecretsFilterData"
                 " WHERE CollectionName = ?"
                 " AND HashedSecretName = ?;"
             );

    Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare delete secrets filter data query: %1").arg(errorText));
    }

    QVariantList dvalues;
    dvalues << QVariant::fromValue<QString>(collectionName);
    dvalues << QVariant::fromValue<QString>(hashedSecretName);
    dq.bindValues(dvalues);

    if (!m_db.execute(dq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute delete secrets filter data query: %1").arg(errorText));
    }

    const QString insertSecretsFilterDataQuery = QStringLiteral(
                "INSERT INTO SecretsFilterData ("
                  "CollectionName,"
                  "HashedSecretName,"
                  "Field,"
                  "Value"
                ")"
                " VALUES ("
                  "?,?,?,?"
                ");");

    Daemon::Sqlite::Database::Query ifdq = m_db.prepare(insertSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare insert secrets filter data query: %1").arg(errorText));
    }

    for (Secret::FilterData::const_iterator it = filterData.constBegin(); it != filterData.constEnd(); it++) {
        ivalues.clear();
        ivalues << QVariant::fromValue<QString>(collectionName);
        ivalues << QVariant::fromValue<QString>(hashedSecretName);
        ivalues << QVariant::fromValue<QString>(it.key());
        ivalues << QVariant::fromValue<QString>(it.value());
        ifdq.bindValues(ivalues);
        if (!m_db.execute(ifdq, &errorText)) {
            m_db.rollbackTransaction();
            return Result(Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to execute insert secrets filter data query: %1").arg(errorText));
        }
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit insert secret transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::SqlitePlugin::getSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        QByteArray *encryptedSecretName,
        QByteArray *secret,
        Secret::FilterData *filterData)
{
    openDatabaseIfNecessary();
    Daemon::Sqlite::DatabaseLocker locker(&m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (hashedSecretName.isEmpty()) {
        return Result(Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    }

    const QString selectSecretQuery = QStringLiteral(
                 "SELECT"
                    " EncryptedSecretName,"
                    " Secret"
                  " FROM Secrets"
                  " WHERE CollectionName = ?"
                  " AND HashedSecretName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(hashedSecretName);
    sq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db.execute(sq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select secret query: %1").arg(errorText));
    }

    bool found = false;
    QByteArray secretName;
    QByteArray secretData;
    if (sq.next()) {
        found = true;
        secretName = sq.value(0).value<QByteArray>();
        secretData = sq.value(1).value<QByteArray>();
    }

    Secret::FilterData secretFilterData;
    if (found) {
        const QString selectSecretFilterDataQuery = QStringLiteral(
                     "SELECT"
                        " Field,"
                        " Value"
                      " FROM SecretsFilterData"
                      " WHERE CollectionName = ?"
                      " AND HashedSecretName = ?;"
                 );

        Daemon::Sqlite::Database::Query sfdq = m_db.prepare(selectSecretFilterDataQuery, &errorText);
        if (!errorText.isEmpty()) {
            return Result(Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to prepare select secret filter data query: %1").arg(errorText));
        }
        sfdq.bindValues(values);

        if (!m_db.execute(sfdq, &errorText)) {
            m_db.rollbackTransaction();
            return Result(Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to execute select secret filter data query: %1").arg(errorText));
        }

        while (sfdq.next()) {
            secretFilterData.insert(sfdq.value(0).value<QString>(), sfdq.value(1).value<QString>());
        }
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit select secret transaction"));
    }

    if (!found) {
        return Result(Result::InvalidSecretError,
                                         QString::fromUtf8("No such secret stored"));
    }

    *encryptedSecretName = secretName;
    *secret = secretData;
    *filterData = secretFilterData;
    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::SqlitePlugin::findSecrets(
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator,
        QVector<QByteArray> *encryptedSecretNames)
{
    openDatabaseIfNecessary();
    Daemon::Sqlite::DatabaseLocker locker(&m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (filter.isEmpty()) {
        return Result(Result::InvalidFilterError,
                                         QString::fromUtf8("Empty filter given"));
    }

    // very naive implementation.
    // first, select all of the field/value filter data for the secret
    // second, filter in-memory.
    // third, return the encrypted secret names associated with the matches.

    const QString selectSecretsFilterDataQuery = QStringLiteral(
                 "SELECT"
                    " HashedSecretName,"
                    " Field,"
                    " Value"
                 " FROM SecretsFilterData"
                 " WHERE CollectionName = ?;"
             );

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secrets filter data query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin find secrets transaction"));
    }

    if (!m_db.execute(sq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select secrets filter data query: %1").arg(errorText));
    }

    QMap<QString, Secret::FilterData > hashedSecretNameToFilterData;
    while (sq.next()) {
        hashedSecretNameToFilterData[sq.value(0).value<QString>()].insert(sq.value(1).value<QString>(), sq.value(2).value<QString>());
    }

    // perform in-memory filtering.
    QSet<QString> matchingHashedSecretNames;
    for (QMap<QString, Secret::FilterData >::const_iterator it = hashedSecretNameToFilterData.constBegin(); it != hashedSecretNameToFilterData.constEnd(); it++) {
        const Secret::FilterData &currFilterData(it.value());
        bool matches = filterOperator == StoragePlugin::OperatorOr ? false : true;
        for (Secret::FilterData::const_iterator fit = filter.constBegin(); fit != filter.constEnd(); fit++) {
            bool found = false;
            for (Secret::FilterData::const_iterator mit = currFilterData.constBegin(); mit != currFilterData.constEnd(); mit++) {
                if (fit.key().compare(mit.key(), Qt::CaseInsensitive) == 0) {
                    found = true; // found a matching metadata field for this filter field
                    if (fit.value().compare(mit.value(), Qt::CaseInsensitive) == 0) {
                        // the metadata value matches the filter value
                        if (filterOperator == StoragePlugin::OperatorOr) {
                            // we have a match!
                            matches = true;
                        }
                    } else {
                        if (filterOperator == StoragePlugin::OperatorAnd) {
                            // we know that this one doesn't match.
                            matches = false;
                        }
                    }
                    break; // mit
                }
            }
            if (!found && filterOperator == StoragePlugin::OperatorAnd) {
                // the metadata is missing a required filter field.
                matches = false;
                break; // fit
            }
        }
        if (matches) {
            matchingHashedSecretNames.insert(it.key());
        }
    }

    // now select all of the encrypted secret names associated with the hashed names and return them.
    const QString selectEncryptedSecretName = QStringLiteral(
                 "SELECT"
                    " EncryptedSecretName"
                 " FROM Secrets"
                 " WHERE CollectionName = ?"
                 " AND HashedSecretName = ?;"
             );

    Daemon::Sqlite::Database::Query seq = m_db.prepare(selectEncryptedSecretName, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select encrypted secret name query: %1").arg(errorText));
    }

    QVector<QByteArray> retn;
    for (const QString &hashedSecretName : matchingHashedSecretNames) {
        values.clear();
        values << QVariant::fromValue<QString>(collectionName);
        values << QVariant::fromValue<QString>(hashedSecretName);
        seq.bindValues(values);

        if (!m_db.execute(seq, &errorText)) {
            m_db.rollbackTransaction();
            return Result(Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to execute select encrypted secret name query: %1").arg(errorText));
        }

        if (seq.next()) {
            retn.append(seq.value(0).value<QByteArray>());
        }
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit find secrets transaction"));
    }

    *encryptedSecretNames = retn;
    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::SqlitePlugin::removeSecret(
        const QString &collectionName,
        const QString &secretName)
{
    openDatabaseIfNecessary();
    Daemon::Sqlite::DatabaseLocker locker(&m_db);

    // Note: don't disallow collectionName=standalone, since that's how we delete standalone secrets.
    if (secretName.isEmpty()) {
        return Result(Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Result(Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    }

    const QString deleteSecretQuery = QStringLiteral(
                "DELETE FROM Secrets"
                " WHERE CollectionName = ?"
                " AND HashedSecretName = ?;");

    QString errorText;
    Daemon::Sqlite::Database::Query dq = m_db.prepare(deleteSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare delete secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(secretName);
    dq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db.execute(dq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute delete secret query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit delete secret transaction"));
    }

    return Result(Result::Succeeded);
}

Result
Daemon::Plugins::SqlitePlugin::reencryptSecrets(
        const QString &collectionName,          // non-empty, all secrets in this collection will be re-encrypted
        const QVector<QString> &secretNames,    // if collectionName is empty, these standalone secrets will be re-encrypted.
        const QByteArray &oldkey,
        const QByteArray &newkey,
        EncryptionPlugin *plugin)
{
    openDatabaseIfNecessary();
    Daemon::Sqlite::DatabaseLocker locker(&m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (collectionName.isEmpty() && secretNames.isEmpty()) {
        return Result(Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret names given and empty collection name given"));
    }

    QString selectSecretsQuery;
    QVariantList values;
    if (collectionName.isEmpty()) {
        for (const QString &secretName : secretNames) {
            if (!secretName.isEmpty()) {
                values.append(QVariant::fromValue<QString>(secretName));
            }
        }
        if (values.isEmpty()) {
            return Result(Result::InvalidSecretError,
                                             QString::fromUtf8("Empty secret names given"));
        }
        selectSecretsQuery = QStringLiteral(
                     "SELECT"
                        " CollectionName,"
                        " HashedSecretName,"
                        " Secret"
                      " FROM Secrets"
                      " WHERE CollectionName = 'standalone'"
                      " AND HashedSecretName IN ("
                 );
        for (int i = 0; i < values.size(); ++i) {
            selectSecretsQuery.append(QStringLiteral("?,"));
        }
        selectSecretsQuery.chop(1);
        selectSecretsQuery.append(QStringLiteral(");"));
    } else {
        selectSecretsQuery = QStringLiteral(
                     "SELECT"
                        " CollectionName,"
                        " HashedSecretName,"
                        " Secret"
                      " FROM Secrets"
                      " WHERE CollectionName = ?;"
                 );
        values.append(QVariant::fromValue<QString>(collectionName));
    }

    QString errorText;
    Daemon::Sqlite::Database::Query sq = m_db.prepare(selectSecretsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secrets query: %1").arg(errorText));
    }

    sq.bindValues(values);

    if (!m_db.beginTransaction()) {
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db.execute(sq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select secrets query: %1").arg(errorText));
    }

    // decrypt each value, re-encrypt it with the new key, and write it back to the database.
    Result reencryptionResult;
    QVariantList vcollectionNames, vsecretNames, vsecrets;
    while (sq.next()) {
        vcollectionNames.append(sq.value(0));
        vsecretNames.append(sq.value(1));
        QByteArray oldEncrypted = sq.value(2).value<QByteArray>();
        QByteArray plaintext;
        reencryptionResult = plugin->decryptSecret(oldEncrypted, oldkey, &plaintext);
        if (reencryptionResult.code() != Result::Succeeded) {
            m_db.rollbackTransaction();
            return reencryptionResult;
        }
        QByteArray newEncrypted;
        reencryptionResult = plugin->encryptSecret(plaintext, newkey, &newEncrypted);
        if (reencryptionResult.code() != Result::Succeeded) {
            m_db.rollbackTransaction();
            return reencryptionResult;
        }
        vsecrets.append(QVariant::fromValue<QByteArray>(newEncrypted));
    }

    const QString updateSecretQuery = QStringLiteral(
                 "UPDATE Secrets"
                 " SET Secret = ?"
                 "   , Timestamp = date('now')"
                 " WHERE CollectionName = ?"
                 " AND HashedSecretName = ?;"
             );

    Daemon::Sqlite::Database::Query uq = m_db.prepare(updateSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare update secret query: %1").arg(errorText));
    }

    uq.addBindValue(vsecrets);
    uq.addBindValue(vcollectionNames);
    uq.addBindValue(vsecretNames);

    if (!m_db.execute(uq, &errorText)) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute update secret query: %1").arg(errorText));
    }

    if (!m_db.commitTransaction()) {
        m_db.rollbackTransaction();
        return Result(Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit update secret transaction"));
    }

    return Result(Result::Succeeded);
}
