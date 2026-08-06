/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APPSUPPORTKEYSTORE_P_H
#define SAILFISHSECRETS_APPSUPPORTKEYSTORE_P_H

#include "database_p.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVector>

namespace Sailfish {
namespace Secrets {
namespace Daemon {
namespace ApiImpl {

class AppSupportKeyReference
{
public:
    enum { SerializedSize = 36, IdentifierSize = 32 };

    QByteArray identifier;

    bool isValid() const;
    QByteArray serialize() const;
    static bool deserialize(const QByteArray &serialized,
                            AppSupportKeyReference *reference);
    static AppSupportKeyReference create();
};

class AppSupportKeyStore
{
public:
    struct Record {
        QByteArray opaqueReference;
        quint32 ownerUid = 0;
        QString ownerApplicationId;
        QString instanceId;
        quint32 backendVersion = 0;
        QByteArray keyMintBlob;
        QByteArray authorizationPolicy;
    };

    explicit AppSupportKeyStore(bool autotestMode = false);
    ~AppSupportKeyStore();

    bool open(const QByteArray &bookkeepingDatabaseKey,
              quint32 ownerUid,
              const QString &ownerApplicationId,
              const QString &instanceId,
              QString *errorMessage);
    void close();
    bool isOpen() const;
    bool bindIdentity(const QString &ownerApplicationId,
                      const QString &instanceId,
                      QString *errorMessage);
    bool insert(quint32 backendVersion,
                const QByteArray &keyMintBlob,
                const QByteArray &authorizationPolicy,
                QByteArray *opaqueReference,
                QString *errorMessage);
    bool read(const QByteArray &opaqueReference,
              Record *record,
              QString *errorMessage) const;
    bool updateKeyMintBlob(const QByteArray &opaqueReference,
                           quint32 backendVersion,
                           const QByteArray &keyMintBlob,
                           QString *errorMessage);
    bool remove(const QByteArray &opaqueReference,
                Record *removedRecord,
                QString *errorMessage);
    bool records(QVector<Record> *records,
                 QString *errorMessage) const;
    bool removeAll(QVector<Record> *removedRecords,
                   QString *errorMessage);

private:
    Sailfish::Secrets::Daemon::Sqlite::Database m_database;
    quint32 m_ownerUid;
    QString m_ownerApplicationId;
    QString m_instanceId;
    bool m_autotestMode;

    bool validateReference(const QByteArray &opaqueReference,
                           AppSupportKeyReference *reference,
                           QString *errorMessage) const;
};

} // namespace ApiImpl
} // namespace Daemon
} // namespace Secrets
} // namespace Sailfish

#endif // SAILFISHSECRETS_APPSUPPORTKEYSTORE_P_H
