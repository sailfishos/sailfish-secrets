/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_COMMON_SQLITE_DATABASE_P_H
#define SAILFISHSECRETS_COMMON_SQLITE_DATABASE_P_H

#include <QtSql/QSqlDatabase>
#include <QtSql/QSqlQuery>
#include <QtSql/QSqlError>

#include <QtCore/QObject>
#include <QtCore/QList>
#include <QtCore/QVariant>
#include <QtCore/QString>
#include <QtCore/QHash>
#include <QtCore/QMutex>
#include <QtCore/QMutexLocker>
#include <QtCore/QAtomicInt>
#include <QtCore/QScopedPointer>
#include <QtCore/QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(lcSailfishSecretsDaemonSqlite)

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Sqlite {

typedef bool (*UpgradeFunction)(QSqlDatabase &database);
struct UpgradeOperation {
    UpgradeFunction fn;
    const char **statements;
};

class Database
{
public:
    // This class is required to finish() each query at destruction
    class Query
    {
        friend class Database;
        QSqlQuery m_query;
        Query(const QSqlQuery &query);

    public:
        ~Query() { finish(); }

        void bindValue(const QString &id, const QVariant &value) { m_query.bindValue(id, value); }
        void bindValue(int pos, const QVariant &value) { m_query.bindValue(pos, value); }
        void addBindValue(const QVariant &value) { m_query.addBindValue(value); }
        void bindValues(const QVariantList &values) {
            for (int i = 0; i < values.count(); ++i) {
                m_query.bindValue(i, values[i]);
            }
        }

        bool next() { return m_query.next(); }
        bool isValid() { return m_query.isValid(); }
        void finish() { return m_query.finish(); }
        void setForwardOnly(bool forwardOnly) { m_query.setForwardOnly(forwardOnly); }

        QVariant lastInsertId() const { return m_query.lastInsertId(); }

        QVariant value(int index) { return m_query.value(index); }

        template<typename T>
        T value(int index) { return m_query.value(index).value<T>(); }

        operator QSqlQuery &() { return m_query; }
        operator QSqlQuery const &() const { return m_query; }

        void reportError(const QString &text) const;
        void reportError(const char *text) const;

        QString executedQuery() const { return m_query.executedQuery(); }
    };

    Database();
    ~Database();

    QMutex *accessMutex() const;

    bool open(const QString &databaseSubdir,
              const QString &databaseFilename,
              const char *createStatements[],
              const Sailfish::Secrets::Daemon::Sqlite::UpgradeOperation upgradeVersions[],
              int currentSchemaVersion,
              const QString &connectionName,
              bool autoTest);

    operator QSqlDatabase &();
    operator QSqlDatabase const &() const;

    QSqlError lastError() const;

    bool isOpen() const;
    bool localized() const;
    bool beginTransaction();
    bool commitTransaction();
    bool rollbackTransaction();
    bool withinTransaction() const { return m_transactionSemaphore.loadAcquire(); }

    Query prepare(const char *statement, QString *errorText);
    Query prepare(const QString &statement, QString *errorText);

    static bool execute(QSqlQuery &query, QString *errorText);
    static bool executeBatch(QSqlQuery &query, QString *errorText, QSqlQuery::BatchExecutionMode mode = QSqlQuery::ValuesAsRows);

    static QString expandQuery(const QString &queryString, const QVariantList &bindings);
    static QString expandQuery(const QString &queryString, const QMap<QString, QVariant> &bindings);
    static QString expandQuery(const QSqlQuery &query);

private:
    QSqlDatabase m_database;
    QMutex m_mutex;
    QString m_localeName;
    QHash<QString, QSqlQuery> m_preparedQueries;
    QAtomicInt m_transactionSemaphore;
};

class DatabaseLocker : public QMutexLocker
{
public:
    DatabaseLocker(Sailfish::Secrets::Daemon::Sqlite::Database *db)
        : QMutexLocker(db->withinTransaction() ? Q_NULLPTR : db->accessMutex())
        , m_db(db) {}
    ~DatabaseLocker();
private:
    Sailfish::Secrets::Daemon::Sqlite::Database *m_db;
};

} // namespace Sqlite

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHSECRETS_COMMON_SQLITE_DATABASE_P_H
