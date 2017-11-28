/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "database_p.h"

#include <QtCore/QElapsedTimer>
#include <QtCore/QStandardPaths>
#include <QtCore/QDateTime>
#include <QtCore/QDate>
#include <QtCore/QTime>
#include <QtCore/QDir>
#include <QtCore/QFile>
#include <QtCore/QFileInfo>
#include <QtCore/QLoggingCategory>

#include <QtSql/QSqlError>
#include <QtSql/QSqlQuery>

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
        "   CollectionName TEXT NOT NULL,"
        "   PRIMARY KEY (CollectionName));";

static const char *createSecretsTable =
        "\n CREATE TABLE Secrets ("
        "   CollectionName TEXT NOT NULL,"
        "   HashedSecretName TEXT NOT NULL,"
        "   EncryptedSecretName BLOB NOT NULL,"
        "   Secret BLOB,"
        "   Timestamp DATE,"
        "   FOREIGN KEY (CollectionName) REFERENCES Collections(CollectionName) ON DELETE CASCADE,"
        "   PRIMARY KEY (CollectionName, HashedSecretName));";

static const char *createStatements[] =
{
    createCollectionsTable,
    createSecretsTable,
};

typedef bool (*UpgradeFunction)(QSqlDatabase &database);

struct UpgradeOperation {
    UpgradeFunction fn;
    const char **statements;
};

static UpgradeOperation upgradeVersions[] = {
    { 0, 0 },
};

static const int currentSchemaVersion = 1;

static bool execute(QSqlDatabase &database, const QString &statement)
{
    QSqlQuery query(database);
    if (!query.exec(statement)) {
        qCWarning(lcSailfishSecretsPluginSqlite) << QString::fromLatin1("Query failed: %1\n%2")
                .arg(query.lastError().text())
                .arg(statement);
        return false;
    } else {
        return true;
    }
}

static bool beginTransaction(QSqlDatabase &database)
{
    // Use immediate lock acquisition; we should already have an IPC lock, so
    // there will be no lock contention with other writing processes
    return execute(database, QString::fromLatin1("BEGIN IMMEDIATE TRANSACTION"));
}

static bool commitTransaction(QSqlDatabase &database)
{
    return execute(database, QString::fromLatin1("COMMIT TRANSACTION"));
}

static bool rollbackTransaction(QSqlDatabase &database)
{
    return execute(database, QString::fromLatin1("ROLLBACK TRANSACTION"));
}

static bool finalizeTransaction(QSqlDatabase &database, bool success)
{
    if (success) {
        return commitTransaction(database);
    }

    rollbackTransaction(database);
    return false;
}

template <typename T> static int lengthOf(T) { return 0; }
template <typename T, int N> static int lengthOf(const T(&)[N]) { return N; }

static bool executeUpgradeStatements(QSqlDatabase &database)
{
    // Check that the defined schema matches the array of upgrade scripts
    if (currentSchemaVersion != lengthOf(upgradeVersions)) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Invalid schema version:" << currentSchemaVersion;
        return false;
    }

    QSqlQuery versionQuery(database);
    versionQuery.prepare("PRAGMA user_version");
    if (!versionQuery.exec() || !versionQuery.next()) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "User version query failed:" << versionQuery.lastError();
        return false;
    }

    int schemaVersion = versionQuery.value(0).toInt();
    versionQuery.finish();

    while (schemaVersion < currentSchemaVersion) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Upgrading secrets sqlite plugin database from schema version" << schemaVersion;

        if (upgradeVersions[schemaVersion].fn) {
            if (!(*upgradeVersions[schemaVersion].fn)(database)) {
                qCWarning(lcSailfishSecretsPluginSqlite) << "Unable to update data for schema version" << schemaVersion;
                return false;
            }
        }
        if (upgradeVersions[schemaVersion].statements) {
            for (unsigned i = 0; upgradeVersions[schemaVersion].statements[i]; i++) {
                if (!execute(database, QLatin1String(upgradeVersions[schemaVersion].statements[i])))
                    return false;
            }
        }

        if (!versionQuery.exec() || !versionQuery.next()) {
            qCWarning(lcSailfishSecretsPluginSqlite) << "User version query failed:" << versionQuery.lastError();
            return false;
        }

        int version = versionQuery.value(0).toInt();
        versionQuery.finish();

        if (version <= schemaVersion) {
            qCWarning(lcSailfishSecretsPluginSqlite) << "Secrets sqlite plugin database schema upgrade cycle detected - aborting";
            return false;
        } else {
            schemaVersion = version;
            if (schemaVersion == currentSchemaVersion) {
                qCWarning(lcSailfishSecretsPluginSqlite) << "Secrets sqlite plugin database upgraded to version" << schemaVersion;
            }
        }
    }

    if (schemaVersion > currentSchemaVersion) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Secrets sqlite plugin database schema is newer than expected - this may result in failures or corruption";
    }

    return true;
}

static bool checkDatabase(QSqlDatabase &database)
{
    QSqlQuery query(database);
    if (query.exec(QLatin1String("PRAGMA quick_check"))) {
        while (query.next()) {
            const QString result(query.value(0).toString());
            if (result == QLatin1String("ok")) {
                return true;
            }
            qCWarning(lcSailfishSecretsPluginSqlite) << "Integrity problem:" << result;
        }
    }

    return false;
}

static bool upgradeDatabase(QSqlDatabase &database)
{
    if (!beginTransaction(database))
        return false;

    bool success = executeUpgradeStatements(database);

    return finalizeTransaction(database, success);
}

static bool configureDatabase(QSqlDatabase &database, QString &localeName)
{
    if (!execute(database,QLatin1String(setupEnforceForeignKeys))
        || !execute(database, QLatin1String(setupEncoding))
        || !execute(database, QLatin1String(setupTempStore))
        || !execute(database, QLatin1String(setupJournal))
        || !execute(database, QLatin1String(setupSynchronous))) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Failed to configure secrets sqlite plugin database:" << database.lastError().text();
        return false;
    } else {
        const QString cLocaleName(QString::fromLatin1("C"));
        if (localeName != cLocaleName) {
            // Create a collation for sorting by the current locale
            const QString statement(QString::fromLatin1("SELECT icu_load_collation('%1', 'localeCollation')"));
            if (!execute(database, statement.arg(localeName))) {
                qCWarning(lcSailfishSecretsPluginSqlite) << "Failed to configure collation for locale" << localeName
                                                  << ":" << database.lastError().text();
                // Revert to using C locale for sorting
                localeName = cLocaleName;
            }
        }
    }

    return true;
}

static bool executeCreationStatements(QSqlDatabase &database)
{
    for (int i = 0; i < lengthOf(createStatements); ++i) {
        QSqlQuery query(database);

        if (!query.exec(QLatin1String(createStatements[i]))) {
            qCWarning(lcSailfishSecretsPluginSqlite) << QString::fromLatin1("Database creation failed: %1\n%2")
                    .arg(query.lastError().text())
                    .arg(createStatements[i]);
            return false;
        }
    }

    if (!execute(database, QString::fromLatin1("PRAGMA user_version=%1").arg(currentSchemaVersion))) {
        return false;
    }

    return true;
}

static bool prepareDatabase(QSqlDatabase &database, QString &localeName)
{
    if (!configureDatabase(database, localeName))
        return false;

    if (!beginTransaction(database))
        return false;

    bool success = executeCreationStatements(database);
    return finalizeTransaction(database, success);
}

Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query::Query(const QSqlQuery &query)
    : m_query(query)
{
}

void Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query::reportError(const QString &text) const
{
    QString output(text + QString::fromLatin1("\n%1").arg(m_query.lastError().text()));
    qCWarning(lcSailfishSecretsPluginSqlite) << output;
}

void Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query::reportError(const char *text) const
{
    reportError(QString::fromLatin1(text));
}

Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Database()
    : m_mutex(QMutex::Recursive)
    , m_localeName(QLocale().name())
{
}

Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::~Database()
{
    m_database.close();
}

QMutex *Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::accessMutex() const
{
    return const_cast<QMutex *>(&m_mutex);
}

// QDir::isReadable() doesn't support group permissions, only user permissions.
bool directoryIsRW(const QString &dirPath)
{
  QFileInfo databaseDirInfo(dirPath);
  return (databaseDirInfo.permission(QFile::ReadGroup | QFile::WriteGroup)
       || databaseDirInfo.permission(QFile::ReadUser  | QFile::WriteUser));
}

bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::open(const QString &connectionName, bool autoTest)
{
    QMutexLocker locker(accessMutex());

    if (m_database.isOpen()) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Unable to open database when already open:" << connectionName;
        return false;
    }

    const QString systemDataDirPath(QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) + "/system/");
    const QString privilegedDataDirPath(systemDataDirPath + QLatin1String("privileged") + "/");

    QString databaseSubdir(QLatin1String("Secrets/sqliteplugin"));
    if (autoTest) {
        databaseSubdir.append(QLatin1String("-test"));
    }

    const QString databasePath = privilegedDataDirPath + databaseSubdir;
    QDir databaseDir(databasePath);
    if (!databaseDir.mkpath(databasePath)) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Permissions error: unable to create database directory:" << databasePath;
        return false;
    }

    const QString databaseFile = databaseDir.absoluteFilePath(QLatin1String("secrets.db"));
    const bool databasePreexisting = QFile::exists(databaseFile);

    m_database = QSqlDatabase::addDatabase(QString::fromLatin1("QSQLITE"), connectionName);
    m_database.setDatabaseName(databaseFile);

    if (!m_database.open()) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Failed to open secrets sqlite plugin database:" << m_database.lastError().text();
        return false;
    }

    if (!databasePreexisting && !prepareDatabase(m_database, m_localeName)) {
        qCWarning(lcSailfishSecretsPluginSqlite) << "Failed to prepare secrets sqlite plugin database - removing:" << m_database.lastError().text();

        m_database.close();
        QFile::remove(databaseFile);
        return false;
    } else if (databasePreexisting && !configureDatabase(m_database, m_localeName)) {
        m_database.close();
        return false;
    }

    if (databasePreexisting) {
        // Perform an integrity check
        if (!checkDatabase(m_database)) {
            qCWarning(lcSailfishSecretsPluginSqlite) << "Failed to check integrity of secrets sqlite plugin database:" << m_database.lastError().text();
            m_database.close();
            return false;
        }
        // Try to upgrade, if necessary
        if (!upgradeDatabase(m_database)) {
            qCWarning(lcSailfishSecretsPluginSqlite) << "Failed to upgrade secrets sqlite plugin database:" << m_database.lastError().text();
            m_database.close();
            return false;
        }
    }

    qCDebug(lcSailfishSecretsPluginSqlite) << "Opened secrets sqlite plugin database:" << databaseFile << "Locale:" << m_localeName;
    return true;
}

Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::operator QSqlDatabase &()
{
    return m_database;
}

Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::operator QSqlDatabase const &() const
{
    return m_database;
}

QSqlError Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::lastError() const
{
    return m_database.lastError();
}

bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::isOpen() const
{
    return m_database.isOpen();
}

bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::localized() const
{
    return (m_localeName != QLatin1String("C"));
}

// No need for process mutex, as only one process (sailfishsecretsd)
// should ever access the secrets database.
bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::beginTransaction()
{
    int oldSemaphoreValue = m_transactionSemaphore.fetchAndAddAcquire(1);
    if (oldSemaphoreValue == 0) {
        // start a new "outer" transaction.
        return ::beginTransaction(m_database);
    } else if (oldSemaphoreValue == 1) {
        // already in an "outer" transaction.  This is fine, and is
        // done within loadPlugins() code to minimise transactions on startup.
        return true;
    } else {
        // this is always an error, we don't allow recursive transactions.
        qCWarning(lcSailfishSecretsPluginSqlite) << "Invalid semaphore value - beginTransaction() called too many times";
        return false;
    }
}

bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::commitTransaction()
{
    int oldSemaphoreValue = m_transactionSemaphore.fetchAndAddAcquire(-1);
    if (oldSemaphoreValue == 1) {
        return ::commitTransaction(m_database);
    } else if (oldSemaphoreValue == 0) {
        // this is always an error in sailfishsecretsd code.
        qCWarning(lcSailfishSecretsPluginSqlite) << "Invalid semaphore value - commitTransaction called without beginTransaction!";
        return false;
    } else {
        // already in an "outer" transaction.  assume that its commit will succeed.
        return true;
    }
}

bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::rollbackTransaction()
{
    int oldSemaphoreValue = m_transactionSemaphore.fetchAndAddAcquire(-1);
    if (oldSemaphoreValue == 1) {
        return ::rollbackTransaction(m_database);
    } else if (oldSemaphoreValue == 0) {
        // this is always an error in sailfishsecretsd code.
        qCWarning(lcSailfishSecretsPluginSqlite) << "Invalid semaphore value - rollbackTransaction called without beginTransaction!";
        return false;
    } else {
        // already in an outer transaction.  assume that its rollback will succeed.
        return true;
    }
}

Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::prepare(const char *statement, QString *errorText)
{
    return prepare(QString::fromLatin1(statement), errorText);
}

Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::Query Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::prepare(const QString &statement, QString *errorText)
{
    QMutexLocker locker(accessMutex());

    QHash<QString, QSqlQuery>::const_iterator it = m_preparedQueries.constFind(statement);
    if (it == m_preparedQueries.constEnd()) {
        QSqlQuery query(m_database);
        query.setForwardOnly(true);
        if (!query.prepare(statement)) {
            qCWarning(lcSailfishSecretsPluginSqlite) << QString::fromLatin1("Failed to prepare query: %1\n%2")
                    .arg(query.lastError().text())
                    .arg(statement);
            *errorText = query.lastError().text();
            return Query(QSqlQuery());
        }
        it = m_preparedQueries.insert(statement, query);
    }

    return Query(*it);
}

bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::execute(QSqlQuery &query, QString *errorText)
{
    static const bool debugSql = !qgetenv("SFOSSECRETSD_DEBUG_SQL").isEmpty();

    QElapsedTimer t;
    t.start();

    bool rv = query.exec();
    if (rv) {
        if (debugSql) {
            const int n = query.isSelect() ? query.size() : query.numRowsAffected();
            const QString s(expandQuery(query));
            qCDebug(lcSailfishSecretsPluginSqlite).nospace() << "Query in " << t.elapsed() << "ms " << n << ": " << qPrintable(s);
        }
    } else {
        *errorText = query.lastError().text();
    }

    return rv;
}

bool Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::executeBatch(QSqlQuery &query, QString *errorText, QSqlQuery::BatchExecutionMode mode)
{
    static const bool debugSql = !qgetenv("SFOSSECRETSD_DEBUG_SQL").isEmpty();

    QElapsedTimer t;
    t.start();

    bool rv = query.execBatch(mode);
    if (rv) {
        if (debugSql) {
            const int n = query.isSelect() ? query.size() : query.numRowsAffected();
            const QString s(expandQuery(query));
            qCDebug(lcSailfishSecretsPluginSqlite).nospace() << "Batch query in " << t.elapsed() << "ms " << n << ": " << qPrintable(s);
        }
    } else {
        *errorText = query.lastError().text();
    }

    return rv;
}

QString Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::expandQuery(const QString &queryString, const QVariantList &bindings)
{
    QString query(queryString);

    int index = 0;
    for (int i = 0; i < bindings.count(); ++i) {
        static const QChar marker = QChar::fromLatin1('?');

        QString value = bindings.at(i).toString();
        index = query.indexOf(marker, index);
        if (index == -1)
            break;

        query.replace(index, 1, value);
        index += value.length();
    }

    return query;
}

QString Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::expandQuery(const QString &queryString, const QMap<QString, QVariant> &bindings)
{
    QString query(queryString);

    int index = 0;

    while (true) {
        static const QChar marker = QChar::fromLatin1(':');

        index = query.indexOf(marker, index);
        if (index == -1)
            break;

        int remaining = query.length() - index;
        int len = 1;
        for ( ; (len < remaining) && query.at(index + len).isLetter(); ) {
            ++len;
        }

        const QString key(query.mid(index, len));
        QVariant value = bindings.value(key);

        QString valueText;
        if (value.type() == QVariant::String) {
            valueText = QString::fromLatin1("'%1'").arg(value.toString());
        } else {
            valueText = value.toString();
        }

        query.replace(index, len, valueText);
        index += valueText.length();
    }

    return query;
}

QString Sailfish::Secrets::Daemon::Plugins::Sqlite::Database::expandQuery(const QSqlQuery &query)
{
    return expandQuery(query.lastQuery(), query.boundValues());
}
