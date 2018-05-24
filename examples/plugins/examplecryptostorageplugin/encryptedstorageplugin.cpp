/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

#include <QDir>
#include <QFile>
#include <QSet>
#include <QMap>
#include <QCryptographicHash>

using namespace Sailfish::Secrets::Daemon::Plugins;
using namespace Sailfish::Secrets;

Result
ExampleCryptoStoragePlugin::collectionNames(QStringList *names)
{
    names->clear();
    names->append(QStringLiteral("Default"));
    return Result(Result::Succeeded);
}

Result
ExampleCryptoStoragePlugin::createCollection(
        const QString & /* collectionName */,
        const QByteArray & /* encryptionKey */)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support creating collections"));
}

Result
ExampleCryptoStoragePlugin::removeCollection(
        const QString & /* collectionName */)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support removing collections"));
}

Result
ExampleCryptoStoragePlugin::isCollectionLocked(
        const QString &collectionName,
        bool *locked)
{
    if (collectionName != QStringLiteral("Default")) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("No collection with that name exists"));
    }

    // if the plugin itself is unlocked, the Default collection is unlocked.
    *locked = false;
    return Result(Result::Succeeded);
}

Result
ExampleCryptoStoragePlugin::deriveKeyFromCode(
        const QByteArray &authenticationCode,
        const QByteArray &salt,
        QByteArray *key)
{
    // we don't support encrypting collections.
    // the plugin itself will be unlocked if the correct code is supplied to unlock().
    // we always return success from this method.
    Q_UNUSED(salt);
    *key = authenticationCode;
    return Result(Result::Succeeded);
}

Result
ExampleCryptoStoragePlugin::setEncryptionKey(
        const QString & /* collectionName */,
        const QByteArray & /* key */)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support per-collection encryption"));
}

Result
ExampleCryptoStoragePlugin::reencrypt(
        const QString & /* collectionName */,
        const QByteArray & /* oldkey */,
        const QByteArray & /* newkey */)
{
    // we don't support encrypting collections.
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support per-collection encryption"));
}

Result
ExampleCryptoStoragePlugin::setSecret(
        const QString & /* collectionName */,
        const QString & /* secretName */,
        const QByteArray & /* secret */,
        const Secret::FilterData & /* filterData */)
{
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("The ExampleCryptoStoragePlugin doesn't support storing new secrets"));
}

Result
ExampleCryptoStoragePlugin::getSecret(
        const QString &collectionName,
        const QString &secretName,
        QByteArray *secret,
        Secret::FilterData *filterData)
{
    if (collectionName != QStringLiteral("Default")) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("No collection with that name exists"));
    } else if (secretName != QStringLiteral("Default")) {
        return Result(Result::InvalidSecretError,
                      QStringLiteral("No secret with that name exists"));
    }

    Sailfish::Crypto::Key key;
    Sailfish::Crypto::Result cresult = storedKey(
                Sailfish::Crypto::Key::Identifier(secretName, collectionName, name()),
                Sailfish::Crypto::Key::MetaData | Sailfish::Crypto::Key::PublicKeyData,
                QVariantMap(),
                &key);
    if (cresult.code() != Sailfish::Crypto::Result::Succeeded) {
        return Result(Result::UnknownError, // internal error, a bug in this plugin's code
                      QStringLiteral("Unable to read stored key for getSecret"));
    }

    *secret = Sailfish::Crypto::Key::serialize(key);
    QMap<QString,QString> fd = key.filterData();
    *filterData = fd;
    return Result(Result::Succeeded);
}

Result
ExampleCryptoStoragePlugin::secretNames(
        const QString &collectionName,
        QStringList *secretNames)
{
    if (collectionName != QStringLiteral("Default")) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("No collection with that name exists"));
    }

    secretNames->clear();
    secretNames->append(QStringLiteral("Default"));
    return Result(Result::Succeeded);
}

Result
ExampleCryptoStoragePlugin::findSecrets(
        const QString &collectionName,
        const Secret::FilterData &filter,
        StoragePlugin::FilterOperator filterOperator,
        QVector<Secret::Identifier> *identifiers)
{
    if (collectionName != QStringLiteral("Default")) {
        return Result(Result::InvalidCollectionError,
                      QLatin1String("No collection with that name exists"));
    }

    Sailfish::Crypto::Key key;
    Sailfish::Crypto::Result cresult = storedKey(
                Sailfish::Crypto::Key::Identifier(QStringLiteral("Default"), collectionName, name()),
                Sailfish::Crypto::Key::MetaData | Sailfish::Crypto::Key::PublicKeyData,
                QVariantMap(),
                &key);
    if (cresult.code() != Sailfish::Crypto::Result::Succeeded) {
        return Result(Result::UnknownError, // internal error, a bug in this plugin's code
                      QStringLiteral("Unable to read stored key for findSecrets"));
    }
    QMap<QString,QString> fd = key.filterData();
    QMap<QString, Secret::FilterData> secretNameToFilterData;
    secretNameToFilterData.insert(QStringLiteral("Default"), fd);

    // perform in-memory filtering.
    QSet<QString> matchingSecretNames;
    for (QMap<QString, Secret::FilterData >::const_iterator it = secretNameToFilterData.constBegin(); it != secretNameToFilterData.constEnd(); it++) {
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
            matchingSecretNames.insert(it.key());
        }
    }

    QVector<Secret::Identifier> retn;
    for (const QString &secretName : matchingSecretNames) {
        retn.append(Secret::Identifier(secretName, collectionName, name()));
    }

    *identifiers = retn;
    return Result(Result::Succeeded);
}

Result
ExampleCryptoStoragePlugin::removeSecret(
        const QString & /* collectionName */,
        const QString & /* secretName */)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support removing secrets"));
}


Result
ExampleCryptoStoragePlugin::setSecret(
        const QString & /* secretName */,
        const QByteArray & /* secret */,
        const Secret::FilterData & /* filterData */,
        const QByteArray & /* key */)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support standalone secret operations"));
}

Result
ExampleCryptoStoragePlugin::accessSecret(
        const QString & /* secretName */,
        const QByteArray & /* key */,
        QByteArray * /* secret */,
        Secret::FilterData * /* filterData */)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support standalone secret operations"));
}

Result
ExampleCryptoStoragePlugin::removeSecret(
        const QString & /* secretName */)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support standalone secret operations"));
}



Result
ExampleCryptoStoragePlugin::reencryptSecret(
        const QString &,
        const QByteArray &,
        const QByteArray &)
{
    return Result(Result::OperationNotSupportedError,
                  QLatin1String("The ExampleCryptoStoragePlugin doesn't support standalone secret operations"));
}
