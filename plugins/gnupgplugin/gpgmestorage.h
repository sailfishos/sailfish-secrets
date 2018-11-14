/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef GPGME_STORAGE_H
#define GPGME_STORAGE_H

#include "Secrets/Plugins/extensionplugins.h"

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include "gpgme.h"

namespace Sailfish {

namespace Secrets {

namespace Daemon {

namespace Plugins {

class Q_DECL_EXPORT GnuPGStoragePlugin
    : public Sailfish::Secrets::EncryptedStoragePlugin
{
public:
    GnuPGStoragePlugin(gpgme_protocol_t protocol);
    ~GnuPGStoragePlugin();

    Sailfish::Secrets::StoragePlugin::StorageType storageType() const Q_DECL_OVERRIDE {
        return Sailfish::Secrets::StoragePlugin::FileSystemStorage;
    }

    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const Q_DECL_OVERRIDE {
        return Sailfish::Secrets::EncryptionPlugin::TrustedExecutionSoftwareEncryption;
    }

    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const Q_DECL_OVERRIDE {
        return Sailfish::Secrets::EncryptionPlugin::NoAlgorithm;
    }

    Sailfish::Secrets::Result collectionNames(QStringList *names) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result createCollection(const QString &collectionName,
                                               const QByteArray &key) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result removeCollection(const QString &collectionName) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result isCollectionLocked(const QString &collectionName,
                                                 bool *locked) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result deriveKeyFromCode(const QByteArray &authenticationCode,
                                                const QByteArray &salt,
                                                QByteArray *key) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName,
                                               const QByteArray &key) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result reencrypt(const QString &collectionName,
                                        const QByteArray &oldkey,
                                        const QByteArray &newkey) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result setSecret(const QString &collectionName,
                                        const QString &secretName,
                                        const QByteArray &secret,
                                        const Sailfish::Secrets::Secret::FilterData &filterData) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result getSecret(const QString &collectionName,
                                        const QString &secretName,
                                        QByteArray *secret,
                                        Sailfish::Secrets::Secret::FilterData *filterData) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result secretNames(const QString &collectionName,
                                          QStringList *secretNames) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result findSecrets(const QString &collectionName,
                                          const Sailfish::Secrets::Secret::FilterData &filter,
                                          Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator,
                                          QVector<Sailfish::Secrets::Secret::Identifier> *identifiers) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result removeSecret(const QString &collectionName,
                                           const QString &secretName) Q_DECL_OVERRIDE;

    // standalone secret operations.
    Sailfish::Secrets::Result setSecret(const QString &secretName,
                                        const QByteArray &secret,
                                        const Sailfish::Secrets::Secret::FilterData &filterData,
                                        const QByteArray &key) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result accessSecret(const QString &secretName,
                                           const QByteArray &key,
                                           QByteArray *secret,
                                           Sailfish::Secrets::Secret::FilterData *filterData) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result removeSecret(const QString &secretName) Q_DECL_OVERRIDE;

    Sailfish::Secrets::Result reencryptSecret(const QString &secretName,
                                              const QByteArray &oldkey,
                                              const QByteArray &newkey) Q_DECL_OVERRIDE;

private:
    gpgme_protocol_t m_protocol;
};

} // namespace Plugins

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // GPGME_STORAGE_H
