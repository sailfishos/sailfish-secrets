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

/*!
 * \internal
 * \class CryptoManagerPrivate
 * \brief Performs DBus calls to the system crypto service
 */

/*!
 * \internal
 */
CryptoManagerPrivate::CryptoManagerPrivate(CryptoManager *parent)
    : m_parent(parent)
    , m_crypto(CryptoDaemonConnection::instance())
    , m_interface(m_crypto->connect()
                  ? m_crypto->createInterface(QLatin1String("/Sailfish/Crypto"), QLatin1String("org.sailfishos.crypto"), parent)
                  : Q_NULLPTR)
{
}

/*!
 * \internal
 */
CryptoManagerPrivate::~CryptoManagerPrivate()
{
    CryptoDaemonConnection::releaseInstance();
}

/*!
 * \internal
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

QDBusPendingReply<Sailfish::Crypto::Result, QByteArray>
CryptoManagerPrivate::generateRandomData(
        quint64 numberBytes,
        const QString &csprngEngineName,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QByteArray>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                QStringLiteral("generateRandomData"),
                QVariantList() << QVariant::fromValue<quint64>(numberBytes)
                               << QVariant::fromValue<QString>(csprngEngineName)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

QDBusPendingReply<Sailfish::Crypto::Result>
CryptoManagerPrivate::seedRandomDataGenerator(
        const QByteArray &seedData,
        double entropyEstimate,
        const QString &csprngEngineName,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QByteArray>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                QStringLiteral("seedRandomDataGenerator"),
                QVariantList() << QVariant::fromValue<QByteArray>(seedData)
                               << QVariant::fromValue<double>(entropyEstimate)
                               << QVariant::fromValue<QString>(csprngEngineName)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

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
                QStringLiteral("validateCertificateChain"),
                QVariantList() << QVariant::fromValue<QVector<Certificate> >(chain)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

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
                QStringLiteral("generateKey"),
                QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

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
                QStringLiteral("generateStoredKey"),
                QVariantList() << QVariant::fromValue<Key>(keyTemplate)
                               << QVariant::fromValue<QString>(cryptosystemProviderName)
                               << QVariant::fromValue<QString>(storageProviderName));
    return reply;
}

QDBusPendingReply<Result, Key>
CryptoManagerPrivate::storedKey(
        const Key::Identifier &identifier,
        StoredKeyRequest::KeyComponents keyComponents)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, Key>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, Key> reply
            = m_interface->asyncCallWithArgumentList(
                QStringLiteral("storedKey"),
                QVariantList() << QVariant::fromValue<Key::Identifier>(identifier)
                               << QVariant::fromValue<StoredKeyRequest::KeyComponents>(keyComponents));
    return reply;
}

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
                QStringLiteral("deleteStoredKey"),
                QVariantList() << QVariant::fromValue<Key::Identifier>(identifier));
    return reply;
}

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
                QStringLiteral("sign"),
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::SignaturePadding>(padding)
                               << QVariant::fromValue<Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

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
                QStringLiteral("verify"),
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::SignaturePadding>(padding)
                               << QVariant::fromValue<Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

QDBusPendingReply<Result, QByteArray>
CryptoManagerPrivate::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                QStringLiteral("encrypt"),
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<QByteArray>(iv)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::BlockMode>(blockMode)
                               << QVariant::fromValue<Key::EncryptionPadding>(padding)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

QDBusPendingReply<Result, QByteArray>
CryptoManagerPrivate::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key, // or keyreference, i.e. Key(keyName)
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                QStringLiteral("decrypt"),
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<QByteArray>(iv)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::BlockMode>(blockMode)
                               << QVariant::fromValue<Key::EncryptionPadding>(padding)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

QDBusPendingReply<Sailfish::Crypto::Result, quint32, QByteArray>
CryptoManagerPrivate::initialiseCipherSession(
        const QByteArray &initialisationVector,
        const Sailfish::Crypto::Key &key, // or keyreference
        const Sailfish::Crypto::Key::Operation operation,
        const Sailfish::Crypto::Key::BlockMode blockMode,
        const Sailfish::Crypto::Key::EncryptionPadding encryptionPadding,
        const Sailfish::Crypto::Key::SignaturePadding signaturePadding,
        const Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, quint32, QByteArray>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, quint32, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                "initialiseCipherSession",
                QVariantList() << QVariant::fromValue<QByteArray>(initialisationVector)
                               << QVariant::fromValue<Key>(key)
                               << QVariant::fromValue<Key::Operation>(operation)
                               << QVariant::fromValue<Key::BlockMode>(blockMode)
                               << QVariant::fromValue<Key::EncryptionPadding>(encryptionPadding)
                               << QVariant::fromValue<Key::SignaturePadding>(signaturePadding)
                               << QVariant::fromValue<Key::Digest>(digest)
                               << QVariant::fromValue<QString>(cryptosystemProviderName));
    return reply;
}

QDBusPendingReply<Sailfish::Crypto::Result>
CryptoManagerPrivate::updateCipherSessionAuthentication(
        const QByteArray &authenticationData,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "updateCipherSessionAuthentication",
                QVariantList() << QVariant::fromValue<QByteArray>(authenticationData)
                               << QVariant::fromValue<QString>(cryptosystemProviderName)
                               << QVariant::fromValue<quint32>(cipherSessionToken));
    return reply;
}

QDBusPendingReply<Sailfish::Crypto::Result, QByteArray>
CryptoManagerPrivate::updateCipherSession(
        const QByteArray &data,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QByteArray>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray> reply
            = m_interface->asyncCallWithArgumentList(
                "updateCipherSession",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<QString>(cryptosystemProviderName)
                               << QVariant::fromValue<quint32>(cipherSessionToken));
    return reply;
}

QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, bool>
CryptoManagerPrivate::finaliseCipherSession(
        const QByteArray &data,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QByteArray, bool>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result, QByteArray, bool> reply
            = m_interface->asyncCallWithArgumentList(
                "finaliseCipherSession",
                QVariantList() << QVariant::fromValue<QByteArray>(data)
                               << QVariant::fromValue<QString>(cryptosystemProviderName)
                               << QVariant::fromValue<quint32>(cipherSessionToken));
    return reply;
}

/*!
  \class CryptoManager
  \brief Allows clients to make requests of the system crypto service.

  The CryptoManager class provides an interface to the system crypto service.
  In order to perform requests, clients should use the \l Request
  type specific for their needs:

  \list
  \li \l{PluginInfoRequest} to retrieve information about crypto plugins
  \li \l{SeedRandomDataGeneratorRequest} to seed a crypto plugin's random number generator
  \li \l{GenerateRandomDataRequest} to generate random data
  \li \l{ValidateCertificateChainRequest} to validate certificates
  \li \l{GenerateKeyRequest} to generate a \l{Key}
  \li \l{GenerateStoredKeyRequest} to generate a securely-stored \l{Key}
  \li \l{StoredKeyRequest} to retrieve a securely-stored \l{Key}
  \li \l{StoredKeyIdentifiersRequest} to retrieve the identifiers of securely-stored \l{Key}{Keys}
  \li \l{DeleteStoredKeyRequest} to delete a securely-stored \l{Key}
  \li \l{EncryptRequest} to encrypt data with a given \l{Key}
  \li \l{DecryptRequest} to decrypt data with a given \l{Key}
  \li \l{SignRequest} to generate a signature for some data with a given \l{Key}
  \li \l{VerifyRequest} to verify if a signature was generated with a given \l{Key}
  \li \l{CipherRequest} to start a cipher session with which to encrypt, decrypt, sign or verify a stream of data
  \endlist
 */

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
