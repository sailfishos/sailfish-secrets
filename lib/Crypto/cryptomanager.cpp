/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"
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

Q_LOGGING_CATEGORY(lcSailfishCrypto, "org.sailfishos.crypto", QtWarningMsg)

using namespace Sailfish::Crypto;

const QString CryptoManager::DefaultCryptoPluginName = QStringLiteral("org.sailfishos.crypto.plugin.crypto.openssl");
const QString CryptoManager::DefaultCryptoStoragePluginName = QStringLiteral("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher");

CryptoManagerPrivate::CryptoManagerPrivate(CryptoManager *parent)
    : m_parent(parent)
    , m_crypto(CryptoDaemonConnection::instance())
    , m_interface(m_crypto->connect()
                  ? m_crypto->createInterface(QLatin1String("/Sailfish/Crypto"), QLatin1String("org.sailfishos.crypto"), parent)
                  : Q_NULLPTR)
{
}

CryptoManagerPrivate::~CryptoManagerPrivate()
{
    CryptoDaemonConnection::releaseInstance();
}

/*!
 * \brief Returns information about crypto plugins as well as the names of storage plugins
 */
QDBusPendingReply<Result, QVector<CryptoPluginInfo>, QStringList>
CryptoManagerPrivate::getPluginInfo()
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QVector<CryptoPluginInfo>, QStringList>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QVector<CryptoPluginInfo>, QStringList> reply
            = m_interface->asyncCall("getPluginInfo");

    return reply;
}

/*!
 * \brief Attempts to verify the validity of the first certificate in the given certificate chain
 *
 * The cryptosystem provider identified by the given \a cryptosystemProviderName will perform
 * any cryptographic operations required to validate the authenticity of the certificate.
 */
QDBusPendingReply<Result, bool>
CryptoManagerPrivate::validateCertificateChain(
        const QVector<Certificate> &chain,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, bool>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, bool> reply
            = m_interface->asyncCallWithArgumentList(
                "validateCertificateChain",
                QVariantList() << QVariant::fromValue<QVector<Certificate> >(chain)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

/*!
 * \brief Uses the cryptosystem provider identified by \a cryptosystemProviderName to generate a key according to the specified \a keyTemplate.
 *
 * This key will not be stored securely by the crypto daemon, but instead will
 * be returned in its complete form to the caller.
 */
QDBusPendingReply<Result, Key>
CryptoManagerPrivate::generateKey(
        const Key &keyTemplate,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, Key>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, Key> reply
            = m_interface->asyncCallWithArgumentList(
                "generateKey",
                QVariantList() << QVariant::fromValue<Key>(keyTemplate)
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
QDBusPendingReply<Result, Key>
CryptoManagerPrivate::generateStoredKey(
        const Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, Key>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, Key> reply
            = m_interface->asyncCallWithArgumentList(
                "generateStoredKey",
                QVariantList() << QVariant::fromValue<Key>(keyTemplate)
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
QDBusPendingReply<Result, Key>
CryptoManagerPrivate::storedKey(
        const Key::Identifier &identifier) // TODO: do we need parameter: just get metadata/public vs get private data, etc?
{
    if (!m_interface) {
        return QDBusPendingReply<Result, Key>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, Key> reply
            = m_interface->asyncCallWithArgumentList(
                "storedKey",
                QVariantList() << QVariant::fromValue<Key::Identifier>(identifier));
    return reply;
}

/*!
 * \brief Deletes the stored key identified by the given \a identifier.
 *
 * This may trigger a system access control dialog if the calling application
 * has not previously been granted permission by the user to access the key data.
 */
QDBusPendingReply<Result>
CryptoManagerPrivate::deleteStoredKey(
        const Key::Identifier &identifier)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "deleteStoredKey",
                QVariantList() << QVariant::fromValue<Key::Identifier>(identifier));
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
QDBusPendingReply<Result, QVector<Key::Identifier> >
CryptoManagerPrivate::storedKeyIdentifiers() // TODO: UI interaction mode param, if NoUserInteraction then just show the keys already permitted?
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QVector<Key::Identifier> >(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QVector<Key::Identifier> > reply
            = m_interface->asyncCall("storedKeyIdentifiers");
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
QDBusPendingReply<Result, QByteArray>
CryptoManagerPrivate::sign(
        const QByteArray &data,
        const Key &key,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QByteArray>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                "sign",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::SignaturePadding>(padding)
                               << QVariant::fromValue<Key::Digest>(digest)
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
QDBusPendingReply<Result, bool>
CryptoManagerPrivate::verify(
        const QByteArray &data,
        const Key &key,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, bool>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, bool> reply
            = m_interface->asyncCallWithArgumentList(
                "verify",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::SignaturePadding>(padding)
                               << QVariant::fromValue<Key::Digest>(digest)
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
QDBusPendingReply<Result, QByteArray>
CryptoManagerPrivate::encrypt(
        const QByteArray &data,
        const Key &key, // or keyreference, i.e. Key(keyName)
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                "encrypt",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::BlockMode>(blockMode)
                               << QVariant::fromValue<Key::EncryptionPadding>(padding)
                               << QVariant::fromValue<Key::Digest>(digest)
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
QDBusPendingReply<Result, QByteArray>
CryptoManagerPrivate::decrypt(
        const QByteArray &data,
        const Key &key, // or keyreference, i.e. Key(keyName)
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                "decrypt",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::BlockMode>(blockMode)
                               << QVariant::fromValue<Key::EncryptionPadding>(padding)
                               << QVariant::fromValue<Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

/*!
  \brief Constructs a new CryptoManager instance with the given \a parent.
 */
CryptoManager::CryptoManager(QObject *parent)
    : QObject(parent)
    , d_ptr(new CryptoManagerPrivate(this))
{
    if (!d_ptr->m_interface) {
        qCWarning(lcSailfishCrypto) << "Unable to connect to the crypto daemon!  No functionality will be available!";
        return;
    }
}

/*!
  \brief Destroys the CryptoManager.
 */
CryptoManager::~CryptoManager()
{
}

/*!
  \brief Returns true if the manager is initialised and can be used to perform requests.
 */
bool CryptoManager::isInitialised() const
{
    Q_D(const CryptoManager);
    return d->m_interface;
}
