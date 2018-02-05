/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "sqlcipherplugin.h"
#include "../opensslcryptoplugin/evp_p.h"

#include "util_p.h"

#include "Crypto/key.h"
#include "Crypto/certificate.h"

#include <QtCore/QByteArray>
#include <QtCore/QMap>
#include <QtCore/QVector>
#include <QtCore/QString>
#include <QtCore/QUuid>
#include <QtCore/QCryptographicHash>

namespace {
    void nullifyKeyFields(Sailfish::Crypto::Key *key, Sailfish::Crypto::StoredKeyRequest::KeyComponents keep) {
        // Null-out fields if the client hasn't specified that they be kept.
        // Note that by default we treat CustomParameters as PublicKeyData.
        if (!(keep & Sailfish::Crypto::StoredKeyRequest::MetaData)) {
            key->setIdentifier(Sailfish::Crypto::Key::Identifier());
            key->setOrigin(Sailfish::Crypto::Key::OriginUnknown);
            key->setAlgorithm(Sailfish::Crypto::Key::AlgorithmUnknown);
            key->setBlockModes(Sailfish::Crypto::Key::BlockModeUnknown);
            key->setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddingUnknown);
            key->setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddingUnknown);
            key->setDigests(Sailfish::Crypto::Key::DigestUnknown);
            key->setOperations(Sailfish::Crypto::Key::OperationUnknown);
            key->setFilterData(Sailfish::Crypto::Key::FilterData());
        }

        if (!(keep & Sailfish::Crypto::StoredKeyRequest::PublicKeyData)) {
            key->setCustomParameters(QVector<QByteArray>());
            key->setPublicKey(QByteArray());
        }

        if (!(keep & Sailfish::Crypto::StoredKeyRequest::SecretKeyData)) {
            key->setPrivateKey(QByteArray());
            key->setSecretKey(QByteArray());
        }
    }
}

void Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::init_aes_encryption()
{
    osslevp_init();
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::generateAndStoreKey(
        const Sailfish::Crypto::Key &keyTemplate,
        Sailfish::Crypto::Key *keyMetadata)
{
    if (keyTemplate.identifier().name().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty key name given"));
    } else if (keyTemplate.identifier().collectionName().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (keyTemplate.identifier().collectionName().compare(QLatin1String("standalone"), Qt::CaseInsensitive) == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Invalid collection name given"));
    }

    Sailfish::Crypto::Key fullKey(keyTemplate);
    Sailfish::Crypto::Result retn = generateKey(keyTemplate, &fullKey);
    if (retn.code() == Sailfish::Crypto::Result::Failed) {
        return retn;
    }

    // store the key as a secret.
    const QString hashedSecretName = Sailfish::Secrets::Daemon::Util::generateHashedSecretName(fullKey.identifier().collectionName(), fullKey.identifier().name());
    const QMap<QString, QString> filterData(fullKey.filterData());
    Sailfish::Secrets::Result storeResult = setSecret(
                fullKey.identifier().collectionName(),
                hashedSecretName,
                fullKey.identifier().name(),
                Sailfish::Crypto::Key::serialise(fullKey, Sailfish::Crypto::Key::LossySerialisationMode),
                filterData);
    if (storeResult.code() == Sailfish::Secrets::Result::Failed) {
        retn.setCode(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(storeResult.errorCode());
        retn.setErrorMessage(storeResult.errorMessage());
        return retn;
    }

    Sailfish::Crypto::Key partialKey(fullKey);
    partialKey.setSecretKey(QByteArray());
    partialKey.setPrivateKey(QByteArray());
    *keyMetadata = partialKey;
    return retn;
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        Sailfish::Crypto::StoredKeyRequest::KeyComponents keyComponents,
        Sailfish::Crypto::Key *key)
{
    if (identifier.name().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty key name given"));
    } else if (identifier.collectionName().isEmpty()) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Empty collection name given"));
    } else if (identifier.collectionName().compare(QLatin1String("standalone"), Qt::CaseInsensitive) == 0) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::InvalidKeyIdentifier,
                                         QString::fromUtf8("Invalid collection name given"));
    }

    QString secretName;
    QByteArray secret;
    Sailfish::Secrets::Secret::FilterData sfd;

    const QString hashedSecretName = Sailfish::Secrets::Daemon::Util::generateHashedSecretName(identifier.collectionName(), identifier.name());
    Sailfish::Secrets::Result storageResult = getSecret(
                identifier.collectionName(),
                hashedSecretName,
                &secretName,
                &secret,
                &sfd);
    if (storageResult.code() == Sailfish::Secrets::Result::Failed) {
        Sailfish::Crypto::Result retn(Sailfish::Crypto::Result::Failed);
        retn.setErrorCode(Sailfish::Crypto::Result::StorageError);
        retn.setStorageErrorCode(storageResult.errorCode());
        retn.setErrorMessage(storageResult.errorMessage());
        return retn;
    }

    QMap<QString, QString> filterData = sfd;

    bool ok = true;
    Sailfish::Crypto::Key fullKey = Sailfish::Crypto::Key::deserialise(secret, &ok);
    if (!ok) {
        return Sailfish::Crypto::Result(Sailfish::Crypto::Result::SerialisationError,
                                        QLatin1String("Unable to deserialise key from secret blob"));
    }

    fullKey.setIdentifier(Sailfish::Crypto::Key::Identifier(identifier.name(), identifier.collectionName()));
    fullKey.setFilterData(filterData);
    *key = fullKey;
    nullifyKeyFields(key, keyComponents);
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::Succeeded);
}

Sailfish::Crypto::Result
Sailfish::Secrets::Daemon::Plugins::SqlCipherPlugin::storedKeyIdentifiers(
        QVector<Sailfish::Crypto::Key::Identifier> *identifiers)
{
    Q_UNUSED(identifiers);
    // We could only return those identifiers from unlocked collections,
    // and in any case the main keyentries bookkeeping table will have this information.
    return Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnsupportedOperation,
                                    QLatin1String("This operation is deliberately not supported"));
}

#define CRYPTOPLUGINCOMMON_NAMESPACE Sailfish::Secrets::Daemon::Plugins
#define CRYPTOPLUGINCOMMON_CLASS SqlCipherPlugin
#include "../opensslcryptoplugin/cryptoplugin_common.cpp"
