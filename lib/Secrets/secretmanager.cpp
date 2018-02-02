/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"
#include "Secrets/secret.h"
#include "Secrets/extensionplugins.h"

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

Q_LOGGING_CATEGORY(lcSailfishSecrets, "org.sailfishos.secrets", QtWarningMsg)

using namespace Sailfish::Secrets;

const QString Secret::FilterDataFieldType = QStringLiteral("Type");
const QString Secret::TypeUnknown = QStringLiteral("Unknown");
const QString Secret::TypeBlob = QStringLiteral("Blob");
const QString Secret::TypeCryptoKey = QStringLiteral("CryptoKey"); // Do not change this without updating Crypto::Key.cpp
const QString Secret::TypeCryptoCertificate = QStringLiteral("CryptoCertificate");
const QString Secret::TypeUsernamePassword = QStringLiteral("UsernamePassword");

const QString SecretManager::InAppAuthenticationPluginName = QStringLiteral("org.sailfishos.secrets.plugin.authentication.inapp");
//const QString SecretManager::DefaultAuthenticationPluginName = QStringLiteral("org.sailfishos.secrets.plugin.authentication.system");
/* TODO: delete this once we implement the system/devicelock auth plugin! */ const QString SecretManager::DefaultAuthenticationPluginName = SecretManager::InAppAuthenticationPluginName;
const QString SecretManager::DefaultStoragePluginName = QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite");
const QString SecretManager::DefaultEncryptionPluginName = QStringLiteral("org.sailfishos.secrets.plugin.encryption.openssl");
const QString SecretManager::DefaultEncryptedStoragePluginName = QStringLiteral("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher");

/*!
 * \class SecretManagerPrivate
 * \internal
 * \brief Encapsulates DBus communication with the system secrets service
 */

/*!
 * \internal
 */
SecretManagerPrivate::SecretManagerPrivate(SecretManager *parent)
    : QObject(parent)
    , m_parent(parent)
    , m_uiService(Q_NULLPTR)
    , m_interactionView(Q_NULLPTR)
    , m_secrets(SecretsDaemonConnection::instance())
    , m_interface(m_secrets->connect()
                  ? m_secrets->createInterface(QLatin1String("/Sailfish/Secrets"), QLatin1String("org.sailfishos.secrets"), this)
                  : Q_NULLPTR)
{
}

SecretManagerPrivate::~SecretManagerPrivate()
{
    SecretsDaemonConnection::releaseInstance();
}

Result
SecretManagerPrivate::registerInteractionService(
        SecretManager::UserInteractionMode mode,
        QString *address)
{
    if (mode == SecretManager::ApplicationInteraction) {
        if (!m_uiService) {
            m_uiService = new InteractionService(this);
        }
        if (!m_uiService->registerServer()) {
            Result result(Result::InteractionServiceUnavailableError,
                                             QStringLiteral("Unable to start in-process ui service"));
            return result;
        }
        *address = m_uiService->address();
    } else {
        *address = QString();
    }
    return Result(Result::Succeeded);
}

QDBusPendingReply<Result>
SecretManagerPrivate::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "createCollection",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode));
    return reply;
}

QDBusPendingReply<Result>
SecretManagerPrivate::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString interactionServiceAddress;
    Result uiServiceResult = registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Result::Failed) {
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(uiServiceResult)));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "createCollection",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<QString>(authenticationPluginName)
                               << QVariant::fromValue<SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<int>(customLockTimeoutMs)
                               << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

QDBusPendingReply<Result>
SecretManagerPrivate::deleteCollection(
        const QString &collectionName,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "deleteCollection",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode));
    return reply;
}

QDBusPendingReply<Result>
SecretManagerPrivate::setSecret(
        const Secret &secret,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!secret.identifier().isValid() || secret.identifier().identifiesStandaloneSecret()) {
        Result identifierError(Result::InvalidSecretIdentifierError,
                               QLatin1String("This method cannot be invoked with a standalone secret"));
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Result uiServiceResult = registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Result::Failed) {
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(uiServiceResult)));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<Secret>(secret)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

QDBusPendingReply<Result>
SecretManagerPrivate::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const Secret &secret,
        SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!secret.identifier().isValid() || !secret.identifier().identifiesStandaloneSecret()) {
        Result identifierError(Result::InvalidSecretIdentifierError,
                               QLatin1String("This method cannot be invoked with a collection secret"));
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(identifierError)));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<Secret>(secret)
                               << QVariant::fromValue<SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode));
    return reply;
}

QDBusPendingReply<Result>
SecretManagerPrivate::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        const Secret &secret,
        SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        SecretManager::AccessControlMode accessControlMode,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!secret.identifier().isValid() || !secret.identifier().identifiesStandaloneSecret()) {
        Result identifierError(Result::InvalidSecretIdentifierError,
                               QLatin1String("This method cannot be invoked with a collection secret"));
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Result uiServiceResult = registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Result::Failed) {
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(uiServiceResult)));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<QString>(authenticationPluginName)
                               << QVariant::fromValue<Secret>(secret)
                               << QVariant::fromValue<SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<int>(customLockTimeoutMs)
                               << QVariant::fromValue<SecretManager::AccessControlMode>(accessControlMode)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

QDBusPendingReply<Result, Secret>
SecretManagerPrivate::getSecret(
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!identifier.isValid()) {
        Result identifierError(Result::InvalidSecretIdentifierError,
                               QLatin1String("The given identifier is invalid"));
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Result uiServiceResult = registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Result::Failed) {
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(uiServiceResult)));
    }

    QDBusPendingReply<Result, Secret> reply
            = m_interface->asyncCallWithArgumentList(
                "getSecret",
                QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

QDBusPendingReply<Result, QVector<Secret::Identifier> >
SecretManagerPrivate::findSecrets(
        const QString &collectionName,
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result, QVector<Secret::Identifier> >(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (collectionName.isEmpty()) {
        Result collectionError(Result::InvalidCollectionError,
                               QLatin1String("The given collection name is invalid"));
        return QDBusPendingReply<Result, QVector<Secret::Identifier> >(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(collectionError)
                                       << QVariant::fromValue<QVector<Secret::Identifier> >(QVector<Secret::Identifier>())));
    }

    QString interactionServiceAddress;
    Result uiServiceResult = registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Result::Failed) {
        return QDBusPendingReply<Result, QVector<Secret::Identifier> >(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(uiServiceResult)
                                       << QVariant::fromValue<QVector<Secret::Identifier> >(QVector<Secret::Identifier>())));
    }

    QDBusPendingReply<Result, QVector<Secret::Identifier> > reply
            = m_interface->asyncCallWithArgumentList(
                "findSecrets",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<Secret::FilterData>(filter)
                               << QVariant::fromValue<SecretManager::FilterOperator>(filterOperator)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

QDBusPendingReply<Result, QVector<Secret::Identifier> >
SecretManagerPrivate::findSecrets(
        const Secret::FilterData &filter,
        SecretManager::FilterOperator filterOperator,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString interactionServiceAddress;
    Result uiServiceResult = registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Result::Failed) {
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(uiServiceResult)));
    }

    QDBusPendingReply<Result, Secret> reply
            = m_interface->asyncCallWithArgumentList(
                "findSecrets",
                QVariantList() << QVariant::fromValue<QString>(QString())
                               << QVariant::fromValue<Secret::FilterData>(filter)
                               << QVariant::fromValue<SecretManager::FilterOperator>(filterOperator)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

QDBusPendingReply<Result>
SecretManagerPrivate::deleteSecret(
        const Secret::Identifier &identifier,
        SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_interface) {
        return QDBusPendingReply<Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!identifier.isValid()) {
        Result identifierError(Result::InvalidSecretIdentifierError,
                               QLatin1String("The given identifier is invalid"));
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Result uiServiceResult = registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Result::Failed) {
        return QDBusPendingReply<Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Result>(uiServiceResult)));
    }

    QDBusPendingReply<Result> reply
            = m_interface->asyncCallWithArgumentList(
                "deleteSecret",
                QVariantList() << QVariant::fromValue<Secret::Identifier>(identifier)
                               << QVariant::fromValue<SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

/*!
 * \internal
 */
SecretManagerPrivate *SecretManager::pimpl() const
{
    return d_ptr.data();
}



/*!
  \class SecretManager
  \brief Allows clients to make requests of the system secrets service.

  The SecretManager class provides an interface to the system secrets service.
  In order to perform requests, clients should use the \l Request
  type specific for their needs:

  \list
  \li \l{Sailfish::Secrets::CreateCollectionRequest} to create a collection in which to store secrets
  \li \l{Sailfish::Secrets::DeleteCollectionRequest} to delete a collection of secrets
  \li \l{Sailfish::Secrets::StoreSecretRequest} to store a secret either in a collection or standalone
  \li \l{Sailfish::Secrets::StoredSecretRequest} to retrieve a secret
  \li \l{Sailfish::Secrets::FindSecretsRequest} to search a collection for secrets matching a filter
  \li \l{Sailfish::Secrets::DeleteSecretRequest} to delete a secret
  \endlist
 */


/*!
  \brief Constructs a new SecretManager instance with the given \a parent.
 */
SecretManager::SecretManager(SecretManager::InitialisationMode mode, QObject *parent)
    : QObject(parent)
    , d_ptr(new SecretManagerPrivate(this))
{
    if (!d_ptr->m_interface) {
        qCWarning(lcSailfishSecrets) << "Unable to connect to the secrets daemon!  No functionality will be available!";
        return;
    }

    if (mode == SecretManager::MinimalInitialisationMode) {
        // no cache initialisation required = we're already initialised.
        d_ptr->m_initialised = true;
        QMetaObject::invokeMethod(this, "isInitialisedChanged", Qt::QueuedConnection);
    } else if (mode == SecretManager::SynchronousInitialisationMode) {
        QDBusPendingReply<Result,
                          QVector<StoragePluginInfo>,
                          QVector<EncryptionPluginInfo>,
                          QVector<EncryptedStoragePluginInfo>,
                          QVector<AuthenticationPluginInfo> > reply
                = d_ptr->m_interface->call("getPluginInfo");
        reply.waitForFinished();
        if (reply.isValid()) {
            Result result = reply.argumentAt<0>();
            if (result.code() == Result::Succeeded) {
                QVector<StoragePluginInfo> storagePlugins = reply.argumentAt<1>();
                QVector<EncryptionPluginInfo> encryptionPlugins = reply.argumentAt<2>();
                QVector<EncryptedStoragePluginInfo> encryptedStoragePlugins = reply.argumentAt<3>();
                QVector<AuthenticationPluginInfo> authenticationPlugins = reply.argumentAt<4>();
                for (auto p : storagePlugins) {
                    d_ptr->m_storagePluginInfo.insert(p.name(), p);
                }
                for (auto p : encryptionPlugins) {
                    d_ptr->m_encryptionPluginInfo.insert(p.name(), p);
                }
                for (auto p : encryptedStoragePlugins) {
                    d_ptr->m_encryptedStoragePluginInfo.insert(p.name(), p);
                }
                for (auto p : authenticationPlugins) {
                    d_ptr->m_authenticationPluginInfo.insert(p.name(), p);
                }
                d_ptr->m_initialised = true;
                QMetaObject::invokeMethod(this, "isInitialisedChanged", Qt::QueuedConnection);
            } else {
                qCWarning(lcSailfishSecrets) << "Unable to initialise plugin info due to error:"
                                             << result.errorCode() << ":" << result.errorMessage();
            }
        } else {
            qCWarning(lcSailfishSecrets) << "Unable to initialise plugin info due to DBus error:"
                                         << reply.error().message();
        }
    } else {
        // TODO : asynchronous initialisation
        qCWarning(lcSailfishSecrets) << "Asynchronous initialisation not currently supported!";
    }
}

/*!
 * Destroys the SecretManager
 */
SecretManager::~SecretManager()
{
}

/*!
  \brief Returns true if the DBus connection has been established and the local cache of plugin info has been populated, otherwise false.
 */
bool SecretManager::isInitialised() const
{
    Q_D(const SecretManager);
    return d->m_interface && d->m_initialised;
}

/*!
  \brief Registers the given \a view with the SecretManager.
  The \a view the InteractionView instance which will display any UI required during secret request
  if the authentication plugin for the secret or collection supports \c ApplicationSpecificAuthentication
  in-process UI flows.

  Note that the InteractionView type does not extend QObject and thus no smart pointer (QPointer, etc)
  is used to track the lifetime of the view object.  The client must ensure that the view isn't
  destroyed prior to or during a request performed via the SecretManager, to avoid undefined behaviour.
 */
void SecretManager::registerInteractionView(InteractionView *view)
{
    Q_D(SecretManager);
    // Note: InteractionView is not QObject-derived, so we cannot use QPointer etc.
    d->m_interactionView = view;
}

/*!
 * \brief Returns information about available storage plugins.
 *
 * Storage plugins provide storage for secrets.  Different plugins
 * may be better for different use cases (e.g., some may be backed
 * by a secure hardware peripheral, or a Trusted Execution Environment
 * application, whereas others may simply run "normal" application code
 * to store data to an SQL database on the device's filesystem).
 *
 * These storage plugins don't perform any encryption; the Secrets
 * service will use a specific encryption plugin to perform encryption
 * and decryption operations.
 */
QMap<QString, StoragePluginInfo>
SecretManager::storagePluginInfo()
{
    Q_D(const SecretManager);
    return d->m_storagePluginInfo;
}

/*!
 * \brief Returns information about available encryption plugins.
 *
 * Encryption plugins provide crypto operations for secrets.
 * Different plugisn may be better for different use cases (e.g.,
 * some may be backed by a secure hardware peripheral, or a
 * Trusted Execution Environment application, whereas others may
 * simply run "normal" application code to perform cryptographic
 * operations).
 */
QMap<QString, EncryptionPluginInfo>
SecretManager::encryptionPluginInfo()
{
    Q_D(const SecretManager);
    return d->m_encryptionPluginInfo;
}

/*!
 * \brief Returns information about available encrypted storage plugins.
 *
 * Encrypted storage plugins provide all-in-one encryption and
 * storage for secrets.  They generally use block-mode encryption
 * algorithms such as AES256 to encrypt or decrypt entire pages
 * of data when writing to or reading from a database, which makes
 * them ideally suited to implement device-lock protected secret
 * collection stores.
 */
QMap<QString, EncryptedStoragePluginInfo>
SecretManager::encryptedStoragePluginInfo()
{
    Q_D(const SecretManager);
    return d->m_encryptedStoragePluginInfo;
}

/*!
 * \brief Returns information about available authentication plugins.
 *
 * Authentication plugins provide UI flows which request the user
 * to provide an authentication key (e.g. lock code, password,
 * fingerprint, iris scan or voice recognition template) which
 * can be used to generate an encryption or decryption key.
 *
 * If your application intends to store only application-specific
 * secrets, then when creating the collection or secret you
 * can specify an authentication plugin which supports
 * the \c ApplicationSpecificAuthentication authentication type,
 * and register a \l InteractionView with the manager
 * which will then be used to provide the UI interaction with the
 * user, in-process.  (Note that if you do not wish any UI interaction,
 * the InteractionView implementation can return a precalculated key directly.)
 *
 * Alternatively, other plugins provide various system-mediated
 * UI flows which ensure that the integrity of the user's authentication
 * data is maintained.
 */
QMap<QString, AuthenticationPluginInfo>
SecretManager::authenticationPluginInfo()
{
    Q_D(const SecretManager);
    return d->m_authenticationPluginInfo;
}
