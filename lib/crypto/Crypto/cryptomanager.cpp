/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/key.h"
#include "Crypto/certificate.h"

#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusReply>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

#include <QtCore/QPointer>
#include <QtCore/QLoggingCategory>
#include <QtCore/QStandardPaths>
#include <QtCore/QDir>

Q_LOGGING_CATEGORY(lcSailfishCrypto, "org.sailfishos.crypto")

Sailfish::Crypto::CryptoManagerPrivate::CryptoManagerPrivate(CryptoManager *parent)
    : QObject(parent)
    , m_parent(parent)
    , m_crypto(Sailfish::Crypto::CryptoDaemonConnection::instance())
    , m_interface(m_crypto->connect()
                  ? m_crypto->createApiInterface(QLatin1String("/Sailfish/Crypto"), QLatin1String("org.sailfishos.crypto"), this)
                  : Q_NULLPTR)
{
}

Sailfish::Crypto::CryptoManagerPrivate::~CryptoManagerPrivate()
{
    Sailfish::Crypto::CryptoDaemonConnection::releaseInstance();
}

/*!
  \brief Constructs a new CryptoManager instance with the given \a parent.
 */
Sailfish::Crypto::CryptoManager::CryptoManager(QObject *parent)
    : QObject(parent)
    , m_data(new Sailfish::Crypto::CryptoManagerPrivate(this))
{
    if (!m_data->m_interface) {
        qCWarning(lcSailfishCrypto) << "Unable to connect to the crypto daemon!  No functionality will be available!";
        return;
    }
}

/*!
  \brief Returns true if the DBus connection to the crypto daemon has been established, otherwise false
 */
bool Sailfish::Crypto::CryptoManager::isInitialised() const
{
    return m_data->m_interface;
}

/*!
 * \brief Returns information about crypto plugins as well as the names of storage plugins
 */
QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::CryptoPluginInfo>, QStringList>
Sailfish::Crypto::CryptoManager::getPluginInfo()
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::CryptoPluginInfo>, QStringList>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::CryptoPluginInfo>, QStringList> reply
            = m_data->m_interface->asyncCall("getPluginInfo");

    return reply;
}

/*!
 * \brief Attempts to verify the validity of the first certificate in the given certificate chain
 *
 * The cryptosystem provider identified by the given \a cryptosystemProviderName will perform
 * any cryptographic operations required to validate the authenticity of the certificate.
 */
QDBusPendingReply<Sailfish::Crypto::Result, bool>
Sailfish::Crypto::CryptoManager::validateCertificateChain(
        const QVector<Sailfish::Crypto::Certificate> &chain,
        const QString &cryptosystemProviderName)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, bool>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, bool> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "validateCertificateChain",
                QVariantList() << QVariant::fromValue<QVector<Sailfish::Crypto::Certificate> >(chain)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

/*!
 * \brief Uses the cryptosystem provider identified by \a cryptosystemProviderName to generate a key according to the specified \a keyTemplate.
 *
 * This key will not be stored securely by the crypto daemon, but instead will
 * be returned in its complete form to the caller.
 */
QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key>
Sailfish::Crypto::CryptoManager::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const QString &cryptosystemProviderName)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "generateKey",
                QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}


/*!
 * \brief Uses the cryptosystem provider identified by \a cryptosystemProviderName to generate a key according to the specified \a keyTemplate.
 *
 * This key will be stored securely by the crypto daemon via the storage
 * plugin identified by the given \a storageProviderName, and the returned
 * key will not contain any private or secret key data.
 *
 * Available storage providers can be enumerated from the Sailfish Secrets API.
 *
 * If the \a cryptosystemProviderName and \a storageProviderName are the
 * same, then the key will be stored in storage managed by the
 * cryptosystem provider plugin, if that plugin supports storing keys.
 */
QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key>
Sailfish::Crypto::CryptoManager::generateStoredKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "generateStoredKey",
                QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate)
                               << QVariant::fromValue<QString>(cryptosystemProviderName)
                               << QVariant::fromValue<QString>(storageProviderName));
    return reply;
}

/*!
 * \brief Returns the full stored key identified by the given \a identifier.
 *
 * This may trigger a system access control dialog if the calling application
 * has not previously been granted permission by the user to access the key data.
 */
QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key>
Sailfish::Crypto::CryptoManager::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier) // TODO: do we need parameter: just get metadata/public vs get private data, etc?
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "storedKey",
                QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key::Identifier>(identifier));
    // TODO: does this also need collectionName ? or is name a combo of secretName+collectionName somehow?
    // I think the crypto daemon can handle that:
    //    when storing, specify name + crypto + storage
    //    create row in secrets database: name -> SailfishCryptoCollection_storage, storage, crypto
    //    We should also prevent random apps from creating any collection with name starting with SailfishCrypto
    // That way we have a unique mapping from name to collection+name, etc.
    // Hrm.  I dunno, maybe collection name is a good idea...
    return reply;
}

/*!
 * \brief Deletes the stored key identified by the given \a identifier.
 *
 * This may trigger a system access control dialog if the calling application
 * has not previously been granted permission by the user to access the key data.
 */
QDBusPendingReply<Sailfish::Crypto::Result>
Sailfish::Crypto::CryptoManager::deleteStoredKey(
        const Sailfish::Crypto::Key::Identifier &identifier)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "deleteStoredKey",
                QVariantList() << QVariant::fromValue<Sailfish::Crypto::Key::Identifier>(identifier));
    return reply;
}

/*!
 * \brief Returns the names of stored keys which the application is permitted to enumerate.
 *
 * This may trigger a system access control UI flow within which the user
 * will be asked which keys the application should be permitted to enumerate.
 *
 * Note that the application may not have permission to use or read these
 * keys, and any future operations (e.g., to use one of the keys to sign data)
 * may trigger further access control UI flows.
 */
QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::Key::Identifier> >
Sailfish::Crypto::CryptoManager::storedKeyIdentifiers() // TODO: UI interaction mode param, if NoUserInteraction then just show the keys already permitted?
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::Key::Identifier> >(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::Key::Identifier> > reply
            = m_data->m_interface->asyncCall("storedKeyIdentifiers");
    return reply;
}

/*!
 * \brief Attempt to sign the given \a data with the provided \a key with padding mode \a padding and hash function \a digest.
 *
 * The \a key may be a key reference (that is, a key containing just an identifier)
 * which references a securely stored key managed by the crypto daemon,
 * or a sign-capable key (that is a key which also contains the key data
 * required to sign data).
 */
QDBusPendingReply<Sailfish::Crypto::Result, QByteArray>
Sailfish::Crypto::CryptoManager::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, QByteArray>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "sign",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Sailfish::Crypto::Key>(key)
                               << QVariant::fromValue<Sailfish::Crypto::Key::SignaturePadding>(padding)
                               << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

/*!
 * \brief Attempt to verify the given signed \a data with the provided \a key assuming padding mode \a padding and hash function \a digest.
 *
 * The \a key may be a key reference (that is, a key containing just an identifier)
 * which references a securely stored key managed by the crypto daemon,
 * or a verify-capable key (that is a key which also contains the key data
 * required to verify signed data).
 */
QDBusPendingReply<Sailfish::Crypto::Result, bool>
Sailfish::Crypto::CryptoManager::verify(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result, bool>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, bool> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "verify",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Sailfish::Crypto::Key>(key)
                               << QVariant::fromValue<Sailfish::Crypto::Key::SignaturePadding>(padding)
                               << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

/*!
 * \brief Attempt to encrypt the given \a data with the provided \a key with
 *        block mode \a blockMode, padding mode \a padding, and hash function \a digest.
 *
 * The \a key may be a key reference (that is, a key containing just an identifier)
 * which references a securely stored key managed by the crypto daemon,
 * or an encrypt-capable key (that is a key which also contains the key data
 * required to encrypt data).
 */
QDBusPendingReply<Sailfish::Crypto::Result, QByteArray>
Sailfish::Crypto::CryptoManager::encrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "encrypt",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Sailfish::Crypto::Key>(key)
                               << QVariant::fromValue<Sailfish::Crypto::Key::BlockMode>(blockMode)
                               << QVariant::fromValue<Sailfish::Crypto::Key::EncryptionPadding>(padding)
                               << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

/*!
 * \brief Attempt to decrypt the given \a data with the provided \a key assuming
 *        block mode \a blockMode, padding mode \a padding, and hash function \a digest.
 *
 * The \a key may be a key reference (that is, a key containing just an identifier)
 * which references a securely stored key managed by the crypto daemon,
 * or a decrypt-capable key (that is a key which also contains the key data
 * required to decrypt data).
 */
QDBusPendingReply<Sailfish::Crypto::Result, QByteArray>
Sailfish::Crypto::CryptoManager::decrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Crypto::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "decrypt",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Sailfish::Crypto::Key>(key)
                               << QVariant::fromValue<Sailfish::Crypto::Key::BlockMode>(blockMode)
                               << QVariant::fromValue<Sailfish::Crypto::Key::EncryptionPadding>(padding)
                               << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

