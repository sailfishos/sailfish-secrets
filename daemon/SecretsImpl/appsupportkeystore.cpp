/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "appsupportkeystore_p.h"

#include <QtCore/QDataStream>
#include <QtCore/QFile>
#include <QtSql/QSqlDatabase>

namespace {

const QByteArray ReferenceMagic("AKR1", 4);

const char *SetupCompatibilityTo3 = "PRAGMA cipher_compatibility = 3;";
const char *SetupJournal = "PRAGMA journal_mode = WAL;";
const char *SetupSynchronous = "PRAGMA synchronous = FULL;";
const char *CreateKeysTable =
        "CREATE TABLE AppSupportKeys ("
        " OpaqueReference BLOB PRIMARY KEY NOT NULL,"
        " OwnerUid INTEGER NOT NULL,"
        " OwnerApplicationId TEXT NOT NULL,"
        " InstanceId TEXT NOT NULL,"
        " BackendVersion INTEGER NOT NULL,"
        " KeyMintBlob BLOB NOT NULL,"
        " AuthorizationPolicy BLOB NOT NULL"
        ");";
const char *CreateOwnerIndex =
        "CREATE INDEX AppSupportKeysOwnerIndex "
        "ON AppSupportKeys (OwnerUid, OwnerApplicationId, InstanceId);";
const char *CreateStatements[] = {
    CreateKeysTable,
    CreateOwnerIndex,
    Q_NULLPTR
};
const Sailfish::Secrets::Daemon::Sqlite::UpgradeOperation UpgradeVersions[] = {
    { Q_NULLPTR, Q_NULLPTR }
};
const int CurrentSchemaVersion = 1;

bool readRandom(QByteArray *output, int size)
{
    QFile random(QStringLiteral("/dev/urandom"));
    if (!random.open(QIODevice::ReadOnly)) {
        return false;
    }
    *output = random.read(size);
    return output->size() == size;
}

} // namespace

using namespace Sailfish::Secrets::Daemon;
using namespace Sailfish::Secrets::Daemon::ApiImpl;

bool AppSupportKeyReference::isValid() const
{
    return identifier.size() == IdentifierSize;
}

QByteArray AppSupportKeyReference::serialize() const
{
    if (!isValid()) {
        return QByteArray();
    }
    QByteArray serialized;
    QDataStream stream(&serialized, QIODevice::WriteOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    stream.writeRawData(ReferenceMagic.constData(), ReferenceMagic.size());
    stream.writeRawData(identifier.constData(), identifier.size());
    return stream.status() == QDataStream::Ok
            && serialized.size() == SerializedSize ? serialized : QByteArray();
}

bool AppSupportKeyReference::deserialize(
        const QByteArray &serialized,
        AppSupportKeyReference *reference)
{
    if (!reference || serialized.size() != SerializedSize) {
        return false;
    }
    QByteArray input(serialized);
    QDataStream stream(&input, QIODevice::ReadOnly);
    stream.setByteOrder(QDataStream::LittleEndian);
    stream.setVersion(QDataStream::Qt_5_6);
    char magic[4];
    AppSupportKeyReference parsed;
    if (stream.readRawData(magic, sizeof(magic)) != sizeof(magic)
            || QByteArray(magic, sizeof(magic)) != ReferenceMagic) {
        return false;
    }
    parsed.identifier.resize(IdentifierSize);
    if (stream.readRawData(parsed.identifier.data(), IdentifierSize) != IdentifierSize
            || stream.status() != QDataStream::Ok || !stream.atEnd()
            || !parsed.isValid()) {
        return false;
    }
    *reference = parsed;
    return true;
}

AppSupportKeyReference AppSupportKeyReference::create()
{
    AppSupportKeyReference reference;
    if (!readRandom(&reference.identifier, IdentifierSize)) {
        return AppSupportKeyReference();
    }
    return reference;
}

AppSupportKeyStore::AppSupportKeyStore(bool autotestMode)
    : m_ownerUid(0)
    , m_autotestMode(autotestMode)
{
}

AppSupportKeyStore::~AppSupportKeyStore()
{
    close();
}

bool AppSupportKeyStore::open(
        const QByteArray &bookkeepingDatabaseKey,
        quint32 ownerUid,
        const QString &ownerApplicationId,
        const QString &instanceId,
        QString *errorMessage)
{
    if (bookkeepingDatabaseKey.size() != 64 || ownerUid == 0
            || ownerApplicationId.isEmpty() || instanceId.isEmpty()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid AppSupport key-store identity or database key");
        }
        return false;
    }

    const QByteArray keyStatement = QString::fromLatin1(
                "PRAGMA key = \"x'%1'\";")
            .arg(QString::fromLatin1(bookkeepingDatabaseKey)).toLatin1();
    const char *setupStatements[] = {
        keyStatement.constData(),
        SetupCompatibilityTo3,
        SetupJournal,
        SetupSynchronous,
        Q_NULLPTR
    };
    if (!m_database.open(QStringLiteral("QSQLCIPHER"),
                         QStringLiteral("org.sailfishos.appsupport.keystore.v1"),
                         QStringLiteral("keystore.db"),
                         setupStatements,
                         CreateStatements,
                         UpgradeVersions,
                         CurrentSchemaVersion,
                         QStringLiteral("appsupport-keystore-v1"),
                         m_autotestMode)) {
        if (errorMessage) {
            *errorMessage = m_database.lastError().text();
        }
        return false;
    }
    m_ownerUid = ownerUid;
    m_ownerApplicationId = ownerApplicationId;
    m_instanceId = instanceId;
    return true;
}

void AppSupportKeyStore::close()
{
    if (m_database.isOpen()) {
        m_database.close();
        QSqlDatabase::removeDatabase(QStringLiteral("appsupport-keystore-v1"));
    }
    m_ownerUid = 0;
    m_ownerApplicationId.clear();
    m_instanceId.clear();
}

bool AppSupportKeyStore::isOpen() const
{
    return m_database.isOpen();
}

bool AppSupportKeyStore::bindIdentity(
        const QString &ownerApplicationId,
        const QString &instanceId,
        QString *errorMessage)
{
    if (!isOpen() || ownerApplicationId.isEmpty()
            || instanceId.isEmpty() || instanceId.size() > 128
            || instanceId.contains(QChar::Null)) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid AppSupport instance identity");
        }
        return false;
    }
    if (m_ownerApplicationId == QStringLiteral("pending")
            && m_instanceId == QStringLiteral("pending")) {
        m_ownerApplicationId = ownerApplicationId;
        m_instanceId = instanceId;
        return true;
    }
    if (m_ownerApplicationId != ownerApplicationId || m_instanceId != instanceId) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("AppSupport instance identity changed");
        }
        return false;
    }
    return true;
}

bool AppSupportKeyStore::insert(
        quint32 backendVersion,
        const QByteArray &keyMintBlob,
        const QByteArray &authorizationPolicy,
        QByteArray *opaqueReference,
        QString *errorMessage)
{
    if (!isOpen() || backendVersion == 0 || keyMintBlob.isEmpty()
            || authorizationPolicy.isEmpty() || !opaqueReference) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid AppSupport key record");
        }
        return false;
    }

    for (int attempt = 0; attempt < 4; ++attempt) {
        const AppSupportKeyReference reference = AppSupportKeyReference::create();
        const QByteArray serializedReference = reference.serialize();
        if (serializedReference.isEmpty()) {
            if (errorMessage) {
                *errorMessage = QStringLiteral("Unable to generate an opaque key reference");
            }
            return false;
        }

        QString sqlError;
        Sqlite::Database::Query query = m_database.prepare(
                    QStringLiteral("INSERT INTO AppSupportKeys "
                                   "(OpaqueReference,OwnerUid,OwnerApplicationId,InstanceId,"
                                   "BackendVersion,KeyMintBlob,AuthorizationPolicy) "
                                   "VALUES (?,?,?,?,?,?,?)"), &sqlError);
        if (!sqlError.isEmpty()) {
            if (errorMessage) {
                *errorMessage = sqlError;
            }
            return false;
        }
        query.bindValues(QVariantList()
                         << serializedReference << m_ownerUid
                         << m_ownerApplicationId << m_instanceId
                         << backendVersion << keyMintBlob << authorizationPolicy);
        if (m_database.execute(query, &sqlError)) {
            *opaqueReference = serializedReference;
            return true;
        }
        if (attempt == 3 && errorMessage) {
            *errorMessage = sqlError;
        }
    }
    return false;
}

bool AppSupportKeyStore::read(
        const QByteArray &opaqueReference,
        Record *record,
        QString *errorMessage) const
{
    AppSupportKeyReference reference;
    if (!record || !validateReference(opaqueReference, &reference, errorMessage)) {
        return false;
    }
    QString sqlError;
    Sqlite::Database::Query query = m_database.prepare(
                QStringLiteral("SELECT OwnerUid,OwnerApplicationId,InstanceId,BackendVersion,"
                               "KeyMintBlob,AuthorizationPolicy FROM AppSupportKeys "
                               "WHERE OpaqueReference=? AND OwnerUid=? AND "
                               "OwnerApplicationId=? AND InstanceId=?"), &sqlError);
    if (!sqlError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = sqlError;
        }
        return false;
    }
    query.bindValues(QVariantList() << opaqueReference << m_ownerUid
                     << m_ownerApplicationId << m_instanceId);
    if (!m_database.execute(query, &sqlError) || !query.next()) {
        if (errorMessage) {
            *errorMessage = sqlError.isEmpty()
                    ? QStringLiteral("Unknown opaque AppSupport key reference") : sqlError;
        }
        return false;
    }
    record->opaqueReference = opaqueReference;
    record->ownerUid = query.value(0).toUInt();
    record->ownerApplicationId = query.value(1).toString();
    record->instanceId = query.value(2).toString();
    record->backendVersion = query.value(3).toUInt();
    record->keyMintBlob = query.value(4).toByteArray();
    record->authorizationPolicy = query.value(5).toByteArray();
    return record->ownerUid == m_ownerUid;
}

bool AppSupportKeyStore::updateKeyMintBlob(
        const QByteArray &opaqueReference,
        quint32 backendVersion,
        const QByteArray &keyMintBlob,
        QString *errorMessage)
{
    AppSupportKeyReference reference;
    if (!validateReference(opaqueReference, &reference, errorMessage)
            || backendVersion == 0 || keyMintBlob.isEmpty()) {
        return false;
    }
    QString sqlError;
    Sqlite::Database::Query query = m_database.prepare(
                QStringLiteral("UPDATE AppSupportKeys SET BackendVersion=?, KeyMintBlob=? "
                               "WHERE OpaqueReference=? AND OwnerUid=? AND "
                               "OwnerApplicationId=? AND InstanceId=?"), &sqlError);
    if (!sqlError.isEmpty()) {
        if (errorMessage) {
            *errorMessage = sqlError;
        }
        return false;
    }
    query.bindValues(QVariantList() << backendVersion << keyMintBlob
                     << opaqueReference << m_ownerUid
                     << m_ownerApplicationId << m_instanceId);
    if (!m_database.execute(query, &sqlError)) {
        if (errorMessage) {
            *errorMessage = sqlError;
        }
        return false;
    }
    return true;
}

bool AppSupportKeyStore::remove(
        const QByteArray &opaqueReference,
        Record *removedRecord,
        QString *errorMessage)
{
    Record record;
    if (!read(opaqueReference, &record, errorMessage)) {
        return false;
    }
    if (!m_database.beginTransaction()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to begin AppSupport key deletion");
        }
        return false;
    }
    QString sqlError;
    Sqlite::Database::Query query = m_database.prepare(
                QStringLiteral("DELETE FROM AppSupportKeys WHERE OpaqueReference=? "
                               "AND OwnerUid=? AND OwnerApplicationId=? AND InstanceId=?"),
                &sqlError);
    query.bindValues(QVariantList() << opaqueReference << m_ownerUid
                     << m_ownerApplicationId << m_instanceId);
    if (!sqlError.isEmpty() || !m_database.execute(query, &sqlError)) {
        m_database.rollbackTransaction();
        if (errorMessage) {
            *errorMessage = sqlError;
        }
        return false;
    }
    if (!m_database.commitTransaction()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to commit AppSupport key deletion");
        }
        return false;
    }
    if (removedRecord) {
        *removedRecord = record;
    }
    return true;
}

bool AppSupportKeyStore::removeAll(
        QVector<Record> *removedRecords,
        QString *errorMessage)
{
    QVector<Record> recordList;
    if (!records(&recordList, errorMessage)) {
        return false;
    }
    if (!m_database.beginTransaction()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to begin AppSupport key-store reset");
        }
        return false;
    }
    QString sqlError;
    Sqlite::Database::Query removeQuery = m_database.prepare(
                QStringLiteral("DELETE FROM AppSupportKeys WHERE OwnerUid=? AND "
                               "OwnerApplicationId=? AND InstanceId=?"), &sqlError);
    removeQuery.bindValues(QVariantList()
                           << m_ownerUid << m_ownerApplicationId << m_instanceId);
    if (!sqlError.isEmpty() || !m_database.execute(removeQuery, &sqlError)) {
        m_database.rollbackTransaction();
        if (errorMessage) {
            *errorMessage = sqlError;
        }
        return false;
    }
    if (!m_database.commitTransaction()) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Unable to commit AppSupport key-store reset");
        }
        return false;
    }
    if (removedRecords) {
        *removedRecords = recordList;
    }
    return true;
}

bool AppSupportKeyStore::records(
        QVector<Record> *records,
        QString *errorMessage) const
{
    if (!isOpen() || !records) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("AppSupport key store is locked");
        }
        return false;
    }
    records->clear();
    QString sqlError;
    Sqlite::Database::Query select = m_database.prepare(
                QStringLiteral("SELECT OpaqueReference,OwnerUid,OwnerApplicationId,InstanceId,"
                               "BackendVersion,KeyMintBlob,AuthorizationPolicy "
                               "FROM AppSupportKeys WHERE OwnerUid=? AND "
                               "OwnerApplicationId=? AND InstanceId=?"), &sqlError);
    select.bindValues(QVariantList() << m_ownerUid << m_ownerApplicationId << m_instanceId);
    if (!sqlError.isEmpty() || !m_database.execute(select, &sqlError)) {
        if (errorMessage) {
            *errorMessage = sqlError;
        }
        return false;
    }
    while (select.next()) {
        Record record;
        record.opaqueReference = select.value(0).toByteArray();
        record.ownerUid = select.value(1).toUInt();
        record.ownerApplicationId = select.value(2).toString();
        record.instanceId = select.value(3).toString();
        record.backendVersion = select.value(4).toUInt();
        record.keyMintBlob = select.value(5).toByteArray();
        record.authorizationPolicy = select.value(6).toByteArray();
        records->append(record);
    }
    return true;
}

bool AppSupportKeyStore::validateReference(
        const QByteArray &opaqueReference,
        AppSupportKeyReference *reference,
        QString *errorMessage) const
{
    if (!isOpen() || !AppSupportKeyReference::deserialize(opaqueReference, reference)
            || m_ownerUid == 0) {
        if (errorMessage) {
            *errorMessage = QStringLiteral("Invalid opaque AppSupport key reference");
        }
        return false;
    }
    return true;
}
