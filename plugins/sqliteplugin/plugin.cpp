/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

Q_PLUGIN_METADATA(IID Sailfish_Secrets_StoragePlugin_IID)

Q_LOGGING_CATEGORY(lcSailfishSecretsPluginSqlite, "org.sailfishos.secrets.plugin.storage.sqlite")

Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::DatabaseLocker::~DatabaseLocker()
{
    if (mutex()) {
        // The database was not already within a transaction when we were constructed
        // and thus should not be in a transaction when we destruct.
        // That is, check that the beginTransaction()/commitTransaction()/rollbackTransaction()
        // calls are balanced within a given locker scope.
        if (m_db->withinTransaction()) {
            qCWarning(lcSailfishSecretsPluginSqlite) << "Locker: transaction not balanced!  None -> Within!";
        }
    } else {
        // The database was already within a transaction when we were constructed
        // and thus should still be in that transaction when we destruct.
        if (!m_db->withinTransaction()) {
            if (m_db->withinTransaction()) {
                qCWarning(lcSailfishSecretsPluginSqlite) << "Locker: transaction not balanced!  Within -> None!";
            }
        }
    }
}

Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::SqlitePlugin(QObject *parent)
    : Sailfish::Secrets::StoragePlugin(parent)
    , m_db(new Sailfish::Secrets::Daemon::Plugins::Sqlite::Database)
{
#ifdef SAILFISH_SECRETS_BUILD_TEST_PLUGIN
    bool autotestMode = true;
#else
    bool autotestMode = false;
#endif
    if (!m_db->open(QLatin1String("sqliteplugin"), autotestMode)) {
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
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query iq = m_db->prepare(insertCollectionQuery, &errorText);

    QVariantList ivalues;
    ivalues << QVariant::fromValue<QString>(QLatin1String("standalone"));;
    iq.bindValues(ivalues);

    if (m_db->beginTransaction()) {
        if (m_db->execute(iq, &errorText)) {
            m_db->commitTransaction();
        } else {
            m_db->rollbackTransaction();
        }
    }
}

Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::~SqlitePlugin()
{
    delete m_db;
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::createCollection(
        const QString &collectionName)
{
    DatabaseLocker locker(m_db);

    if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Reserved collection name given"));
    }

    const QString selectCollectionsCountQuery = QStringLiteral(
                 "SELECT"
                    " Count(*)"
                  " FROM Collections"
                  " WHERE CollectionName = ?;"
             );

    QString errorText;
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query sq = m_db->prepare(selectCollectionsCountQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select collections query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db->execute(sq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select collections query: %1").arg(errorText));
    }

    bool found = false;
    if (sq.next()) {
        found = sq.value(0).value<int>() > 0;
    }

    if (found) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::CollectionAlreadyExistsError,
                                         QString::fromUtf8("Collection already exists: %1").arg(collectionName));
    }

    const QString insertCollectionQuery = QStringLiteral(
                "INSERT INTO Collections ("
                  "CollectionName"
                ")"
                " VALUES ("
                  "?"
                ");");

    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query iq = m_db->prepare(insertCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare insert collection query: %1").arg(errorText));
    }

    QVariantList ivalues;
    ivalues << QVariant::fromValue<QString>(collectionName);
    iq.bindValues(ivalues);

    if (!m_db->execute(iq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute insert collection query: %1").arg(errorText));
    }

    if (!m_db->commitTransaction()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit insert collection transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}


Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::removeCollection(
        const QString &collectionName)
{
    DatabaseLocker locker(m_db);

    if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (collectionName.compare(QStringLiteral("standalone"), Qt::CaseInsensitive) == 0) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Reserved collection name given"));
    }

    const QString deleteCollectionQuery = QStringLiteral(
                "DELETE FROM Collections"
                " WHERE CollectionName = ?;");

    QString errorText;
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query dq = m_db->prepare(deleteCollectionQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare delete collection query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    dq.bindValues(values);

    if (!m_db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db->execute(dq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute delete collection query: %1").arg(errorText));
    }

    if (!m_db->commitTransaction()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit delete collection transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::setSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        const QByteArray &encryptedSecretName,
        const QByteArray &secret,
        const Sailfish::Secrets::Secret::FilterData &filterData)
{
    DatabaseLocker locker(m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (hashedSecretName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
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
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query sq = m_db->prepare(selectSecretsCountQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secrets query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(hashedSecretName);
    sq.bindValues(values);

    if (!m_db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db->execute(sq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
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

    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query iq = m_db->prepare(found ? updateSecretQuery : insertSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
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

    if (!m_db->execute(iq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute insert secret query: %1").arg(errorText));
    }

    const QString deleteSecretsFilterDataQuery = QStringLiteral(
                 "DELETE FROM SecretsFilterData"
                 " WHERE CollectionName = ?"
                 " AND HashedSecretName = ?;"
             );

    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query dq = m_db->prepare(deleteSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare delete secrets filter data query: %1").arg(errorText));
    }

    QVariantList dvalues;
    dvalues << QVariant::fromValue<QString>(collectionName);
    dvalues << QVariant::fromValue<QString>(hashedSecretName);
    dq.bindValues(dvalues);

    if (!m_db->execute(dq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
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

    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query ifdq = m_db->prepare(insertSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare insert secrets filter data query: %1").arg(errorText));
    }

    for (Sailfish::Secrets::Secret::FilterData::const_iterator it = filterData.constBegin(); it != filterData.constEnd(); it++) {
        ivalues.clear();
        ivalues << QVariant::fromValue<QString>(collectionName);
        ivalues << QVariant::fromValue<QString>(hashedSecretName);
        ivalues << QVariant::fromValue<QString>(it.key());
        ivalues << QVariant::fromValue<QString>(it.value());
        ifdq.bindValues(ivalues);
        if (!m_db->execute(ifdq, &errorText)) {
            m_db->rollbackTransaction();
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to execute insert secrets filter data query: %1").arg(errorText));
        }
    }

    if (!m_db->commitTransaction()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit insert secret transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::getSecret(
        const QString &collectionName,
        const QString &hashedSecretName,
        QByteArray *encryptedSecretName,
        QByteArray *secret,
        Sailfish::Secrets::Secret::FilterData *filterData)
{
    DatabaseLocker locker(m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (hashedSecretName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
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
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query sq = m_db->prepare(selectSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(hashedSecretName);
    sq.bindValues(values);

    if (!m_db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db->execute(sq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
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

    Sailfish::Secrets::Secret::FilterData secretFilterData;
    if (found) {
        const QString selectSecretFilterDataQuery = QStringLiteral(
                     "SELECT"
                        " Field,"
                        " Value"
                      " FROM SecretsFilterData"
                      " WHERE CollectionName = ?"
                      " AND HashedSecretName = ?;"
                 );

        Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query sfdq = m_db->prepare(selectSecretFilterDataQuery, &errorText);
        if (!errorText.isEmpty()) {
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to prepare select secret filter data query: %1").arg(errorText));
        }
        sfdq.bindValues(values);

        if (!m_db->execute(sfdq, &errorText)) {
            m_db->rollbackTransaction();
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to execute select secret filter data query: %1").arg(errorText));
        }

        while (sfdq.next()) {
            secretFilterData.insert(sfdq.value(0).value<QString>(), sfdq.value(1).value<QString>());
        }
    }

    if (!m_db->commitTransaction()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit select secret transaction"));
    }

    if (!found) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("No such secret stored"));
    }

    *encryptedSecretName = secretName;
    *secret = secretData;
    *filterData = secretFilterData;
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::findSecrets(
        const QString &collectionName,
        const Sailfish::Secrets::Secret::FilterData &filter,
        Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator,
        QVector<QByteArray> *encryptedSecretNames)
{
    DatabaseLocker locker(m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (filter.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidFilterError,
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
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query sq = m_db->prepare(selectSecretsFilterDataQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secrets filter data query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    sq.bindValues(values);

    if (!m_db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin find secrets transaction"));
    }

    if (!m_db->execute(sq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select secrets filter data query: %1").arg(errorText));
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

    // now select all of the encrypted secret names associated with the hashed names and return them.
    const QString selectEncryptedSecretName = QStringLiteral(
                 "SELECT"
                    " EncryptedSecretName"
                 " FROM Secrets"
                 " WHERE CollectionName = ?"
                 " AND HashedSecretName = ?;"
             );

    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query seq = m_db->prepare(selectEncryptedSecretName, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select encrypted secret name query: %1").arg(errorText));
    }

    QVector<QByteArray> retn;
    for (const QString &hashedSecretName : matchingHashedSecretNames) {
        values.clear();
        values << QVariant::fromValue<QString>(collectionName);
        values << QVariant::fromValue<QString>(hashedSecretName);
        seq.bindValues(values);

        if (!m_db->execute(seq, &errorText)) {
            m_db->rollbackTransaction();
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                             QString::fromUtf8("Sqlite plugin unable to execute select encrypted secret name query: %1").arg(errorText));
        }

        if (seq.next()) {
            retn.append(seq.value(0).value<QByteArray>());
        }
    }

    if (!m_db->commitTransaction()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit find secrets transaction"));
    }

    *encryptedSecretNames = retn;
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::removeSecret(
        const QString &collectionName,
        const QString &secretName)
{
    DatabaseLocker locker(m_db);

    // Note: don't disallow collectionName=standalone, since that's how we delete standalone secrets.
    if (secretName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
                                         QString::fromUtf8("Empty secret name given"));
    } else if (collectionName.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidCollectionError,
                                         QString::fromUtf8("Empty collection name given"));
    }

    const QString deleteSecretQuery = QStringLiteral(
                "DELETE FROM Secrets"
                " WHERE CollectionName = ?"
                " AND HashedSecretName = ?;");

    QString errorText;
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query dq = m_db->prepare(deleteSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare delete secret query: %1").arg(errorText));
    }

    QVariantList values;
    values << QVariant::fromValue<QString>(collectionName);
    values << QVariant::fromValue<QString>(secretName);
    dq.bindValues(values);

    if (!m_db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db->execute(dq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute delete secret query: %1").arg(errorText));
    }

    if (!m_db->commitTransaction()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit delete secret transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

Sailfish::Secrets::Result
Sailfish::Secrets::Daemon::Plugins::SqlitePlugin::reencryptSecrets(
        const QString &collectionName,          // non-empty, all secrets in this collection will be re-encrypted
        const QVector<QString> &secretNames,    // if collectionName is empty, these standalone secrets will be re-encrypted.
        const QByteArray &oldkey,
        const QByteArray &newkey,
        Sailfish::Secrets::EncryptionPlugin *plugin)
{
    DatabaseLocker locker(m_db);

    // Note: don't disallow collectionName=standalone, since that's how we store standalone secrets.
    if (collectionName.isEmpty() && secretNames.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
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
            return Sailfish::Secrets::Result(Sailfish::Secrets::Result::InvalidSecretError,
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
    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query sq = m_db->prepare(selectSecretsQuery, &errorText);
    if (!errorText.isEmpty()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare select secrets query: %1").arg(errorText));
    }

    sq.bindValues(values);

    if (!m_db->beginTransaction()) {
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to begin transaction"));
    }

    if (!m_db->execute(sq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute select secrets query: %1").arg(errorText));
    }

    // decrypt each value, re-encrypt it with the new key, and write it back to the database.
    Sailfish::Secrets::Result reencryptionResult;
    QVariantList vcollectionNames, vsecretNames, vsecrets;
    while (sq.next()) {
        vcollectionNames.append(sq.value(0));
        vsecretNames.append(sq.value(1));
        QByteArray oldEncrypted = sq.value(2).value<QByteArray>();
        QByteArray plaintext;
        reencryptionResult = plugin->decryptSecret(oldEncrypted, oldkey, &plaintext);
        if (reencryptionResult.code() != Sailfish::Secrets::Result::Succeeded) {
            m_db->rollbackTransaction();
            return reencryptionResult;
        }
        QByteArray newEncrypted;
        reencryptionResult = plugin->encryptSecret(plaintext, newkey, &newEncrypted);
        if (reencryptionResult.code() != Sailfish::Secrets::Result::Succeeded) {
            m_db->rollbackTransaction();
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

    Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query uq = m_db->prepare(updateSecretQuery, &errorText);
    if (!errorText.isEmpty()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to prepare update secret query: %1").arg(errorText));
    }

    uq.addBindValue(vsecrets);
    uq.addBindValue(vcollectionNames);
    uq.addBindValue(vsecretNames);

    if (!m_db->execute(uq, &errorText)) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseQueryError,
                                         QString::fromUtf8("Sqlite plugin unable to execute update secret query: %1").arg(errorText));
    }

    if (!m_db->commitTransaction()) {
        m_db->rollbackTransaction();
        return Sailfish::Secrets::Result(Sailfish::Secrets::Result::DatabaseTransactionError,
                                         QString::fromUtf8("Sqlite plugin unable to commit update secret transaction"));
    }

    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}
