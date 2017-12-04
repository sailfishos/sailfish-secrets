/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
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

const QString Sailfish::Secrets::Secret::FilterDataFieldType = QStringLiteral("Type");
const QString Sailfish::Secrets::Secret::TypeUnknown = QStringLiteral("Unknown");
const QString Sailfish::Secrets::Secret::TypeBlob = QStringLiteral("Blob");
const QString Sailfish::Secrets::Secret::TypeCryptoKey = QStringLiteral("CryptoKey"); // Do not change this without updating Crypto::Key.cpp
const QString Sailfish::Secrets::Secret::TypeCryptoCertificate = QStringLiteral("CryptoCertificate");
const QString Sailfish::Secrets::Secret::TypeUsernamePassword = QStringLiteral("UsernamePassword");

const QString Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName = QStringLiteral("org.sailfishos.secrets.plugin.authentication.inapp");
//const QString Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName = QStringLiteral("org.sailfishos.secrets.plugin.authentication.system");
/* TODO: delete this once we implement the system/devicelock auth plugin! */ const QString Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName = Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName;
const QString Sailfish::Secrets::SecretManager::DefaultStoragePluginName = QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite");
const QString Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName = QStringLiteral("org.sailfishos.secrets.plugin.encryption.openssl");
const QString Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName = QStringLiteral("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher");

Sailfish::Secrets::SecretManagerPrivate::SecretManagerPrivate(SecretManager *parent)
    : QObject(parent)
    , m_parent(parent)
    , m_uiService(Q_NULLPTR)
    , m_interactionView(Q_NULLPTR)
    , m_secrets(Sailfish::Secrets::SecretsDaemonConnection::instance())
    , m_interface(m_secrets->connect()
                  ? m_secrets->createInterface(QLatin1String("/Sailfish/Secrets"), QLatin1String("org.sailfishos.secrets"), this)
                  : Q_NULLPTR)
{
}

Sailfish::Secrets::SecretManagerPrivate::~SecretManagerPrivate()
{
    Sailfish::Secrets::SecretsDaemonConnection::releaseInstance();
}

Sailfish::Secrets::Result
Sailfish::Secrets::SecretManagerPrivate::registerInteractionService(
        Sailfish::Secrets::SecretManager::UserInteractionMode mode,
        QString *address)
{
    if (mode == Sailfish::Secrets::SecretManager::ApplicationInteraction) {
        if (!m_uiService) {
            m_uiService = new Sailfish::Secrets::InteractionService(this);
        }
        if (!m_uiService->registerServer()) {
            Sailfish::Secrets::Result result(Sailfish::Secrets::Result::InteractionServiceUnavailableError,
                                             QStringLiteral("Unable to start in-process ui service"));
            return result;
        }
        *address = m_uiService->address();
    } else {
        *address = QString();
    }
    return Sailfish::Secrets::Result(Sailfish::Secrets::Result::Succeeded);
}

/*!
  \brief Constructs a new SecretManager instance with the given \a parent.
 */
Sailfish::Secrets::SecretManager::SecretManager(Sailfish::Secrets::SecretManager::InitialisationMode mode, QObject *parent)
    : QObject(parent)
    , m_data(new Sailfish::Secrets::SecretManagerPrivate(this))
{
    if (!m_data->m_interface) {
        qCWarning(lcSailfishSecrets) << "Unable to connect to the secrets daemon!  No functionality will be available!";
        return;
    }

    if (mode == Sailfish::Secrets::SecretManager::MinimalInitialisationMode) {
        // no cache initialisation required = we're already initialised.
        m_data->m_initialised = true;
        QMetaObject::invokeMethod(this, "isInitialisedChanged", Qt::QueuedConnection);
    } else if (mode == Sailfish::Secrets::SecretManager::SynchronousInitialisationMode) {
        QDBusPendingReply<Sailfish::Secrets::Result,
                          QVector<Sailfish::Secrets::StoragePluginInfo>,
                          QVector<Sailfish::Secrets::EncryptionPluginInfo>,
                          QVector<Sailfish::Secrets::EncryptedStoragePluginInfo>,
                          QVector<Sailfish::Secrets::AuthenticationPluginInfo> > reply
                = m_data->m_interface->call("getPluginInfo");
        reply.waitForFinished();
        if (reply.isValid()) {
            Sailfish::Secrets::Result result = reply.argumentAt<0>();
            if (result.code() == Sailfish::Secrets::Result::Succeeded) {
                QVector<Sailfish::Secrets::StoragePluginInfo> storagePlugins = reply.argumentAt<1>();
                QVector<Sailfish::Secrets::EncryptionPluginInfo> encryptionPlugins = reply.argumentAt<2>();
                QVector<Sailfish::Secrets::EncryptedStoragePluginInfo> encryptedStoragePlugins = reply.argumentAt<3>();
                QVector<Sailfish::Secrets::AuthenticationPluginInfo> authenticationPlugins = reply.argumentAt<4>();
                for (auto p : storagePlugins) {
                    m_data->m_storagePluginInfo.insert(p.name(), p);
                }
                for (auto p : encryptionPlugins) {
                    m_data->m_encryptionPluginInfo.insert(p.name(), p);
                }
                for (auto p : encryptedStoragePlugins) {
                    m_data->m_encryptedStoragePluginInfo.insert(p.name(), p);
                }
                for (auto p : authenticationPlugins) {
                    m_data->m_authenticationPluginInfo.insert(p.name(), p);
                }
                m_data->m_initialised = true;
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
    }
}

/*!
  \brief Returns true if the DBus connection has been established and the local cache of plugin info has been populated, otherwise false.
 */
bool Sailfish::Secrets::SecretManager::isInitialised() const
{
    return m_data->m_interface && m_data->m_initialised;
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
void Sailfish::Secrets::SecretManager::registerInteractionView(Sailfish::Secrets::InteractionView *view)
{
    // Note: InteractionView is not QObject-derived, so we cannot use QPointer etc.
    m_data->m_interactionView = view;
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
QMap<QString, Sailfish::Secrets::StoragePluginInfo>
Sailfish::Secrets::SecretManager::storagePluginInfo()
{
    return m_data->m_storagePluginInfo;
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
QMap<QString, Sailfish::Secrets::EncryptionPluginInfo>
Sailfish::Secrets::SecretManager::encryptionPluginInfo()
{
    return m_data->m_encryptionPluginInfo;
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
QMap<QString, Sailfish::Secrets::EncryptedStoragePluginInfo>
Sailfish::Secrets::SecretManager::encryptedStoragePluginInfo()
{
    return m_data->m_encryptedStoragePluginInfo;
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
 * and register a \l Sailfish::Secrets::InteractionView with the manager
 * which will then be used to provide the UI interaction with the
 * user, in-process.  (Note that if you do not wish any UI interaction,
 * the InteractionView implementation can return a precalculated key directly.)
 *
 * Alternatively, other plugins provide various system-mediated
 * UI flows which ensure that the integrity of the user's authentication
 * data is maintained.
 */
QMap<QString, Sailfish::Secrets::AuthenticationPluginInfo>
Sailfish::Secrets::SecretManager::authenticationPluginInfo()
{
    return m_data->m_authenticationPluginInfo;
}

/*!
 * \brief Request the Secrets service create a collection with the given
 * \a collectionName which will be stored by the storage plugin
 * identified by the given \a storagePluginName, and whose secrets will
 * be encrypted and decrypted with an encryption key derived from the system
 * device lock key by the encryption plugin identified by the given
 * \a encryptionPluginName according to the specified \a unlockSemantic,
 * to which access will be controlled according to the given \a accessControlMode.
 *
 * If the \a storagePluginName is the same as the \a encryptionPluginName
 * then the plugin is assumed to be a Sailfish::Secrets::EncryptedStoragePlugin.
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "createCollection",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode));
    return reply;
}

/*!
 * \brief Request the Secrets service create a collection with the given
 * \a collectionName which will be stored by the storage plugin
 * identified by the given \a storagePluginName, and whose secrets will
 * be encrypted and decrypted by the encryption plugin identified by the given
 * \a encryptionPluginName according to the specified \a unlockSemantic,
 * with an encryption key derived from a custom lock key which will be obtained
 * from the user via the authentication plugin identified by the given
 * \a authenticationPluginName, to which access will be controlled according
 * to the given \a accessControlMode.
 *
 * If the \a storagePluginName is the same as the \a encryptionPluginName
 * then the plugin is assumed to be a Sailfish::Secrets::EncryptedStoragePlugin.
 *
 * If the \a unlockSemantic specified is \c CustomLockTimoutRelock then the
 * given \a customLockTimeoutMs will be used as the timeout (in milliseconds)
 * after the collection is unlocked which will trigger it to be relocked.
 *
 * If the \a userInteractionMode specified is \c ApplicationInteraction
 * and the specified authentication plugin supports
 * \c ApplicationSpecificAuthentication flows, then the authentication key
 * will be obtained from the user via an in-process authentication flow (see
 * the documentation for \l registerInteractionView() for more information); otherwise,
 * a system-mediated authentication flow will be triggered to obtain the
 * authentication key from the user.
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::createCollection(
        const QString &collectionName,
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString interactionServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "createCollection",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<QString>(authenticationPluginName)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<int>(customLockTimeoutMs)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to delete the collection with the given \a collectionName.
 *
 * If the calling application is the creator of the collection, or alternatively
 * if the user has granted the application permission to delete the collection,
 * then the Secrets service will instruct the storage plugin to delete the
 * collection and any secrets it contains.
 *
 * If the application is not the creator of the collection and the user has not yet
 * been asked if the application should have permission to delete the collection,
 * a system-mediated access control UI flow may be triggered to obtain the user's
 * permission (unless the given \a userInteractionMode is \a PreventInteraction
 * in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::deleteCollection(
        const QString &collectionName,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "deleteCollection",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode));
    return reply;
}

/*!
 * \brief Requests the Secrets service to store the given \a secret into a particular collection.
 *
 * Note that the filter data defined in the secret will be encrypted
 * prior to storage only if the collection is stored by an EncryptedStoragePlugin;
 * otherwise, only the identifier and data will be stored in encrypted form.
 *
 * If the calling application is the creator of the collection specified in the
 * secret's identifier, or alternatively if the user has granted the application
 * permission to modify that collection and either there are no special access controls
 * associated with the particular secret or the secret does not yet exist, then the
 * Secrets service will instruct the storage plugin to store the secret into the collection.
 *
 * If the application is not the creator of the collection and the user has not yet
 * been asked if the application should have permission to modify the collection,
 * or if the secret already exists and has specific access controls associated with
 * it but the user has not yet been asked whether the application should have permission
 * to modify the secret, then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given \a userInteractionMode is
 * \a PreventInteraction in which case the request will fail).
 *
 * If the collection uses an encryption key derived from the system device-lock,
 * then the value will be able to be stored without any other UI flow being required;
 * however, if the collection uses an encryption key derived from a custom lock,
 * then the custom lock authentication key will be obtained from the user via
 * an authentication flow determined by the authentication plugin used for that
 * collection (which may support \c ApplicationInteraction if the collection
 * is an application-specific collection using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventInteraction in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::setSecret(
        const Sailfish::Secrets::Secret &secret,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!secret.identifier().isValid() || secret.identifier().identifiesStandaloneSecret()) {
        Sailfish::Secrets::Result identifierError(Sailfish::Secrets::Result::InvalidSecretIdentifierError,
                                                  QLatin1String("This method cannot be invoked with a standalone secret"));
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<Sailfish::Secrets::Secret>(secret)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to store the given \a secret with the given
 * \a secretName which is a standalone secret (not associated with a collection)
 * encrypted with an encryption key derived from the system device lock, which
 * will be locked and unlocked according to the given \a unlockSemantic.
 *
 * Note that the filter data defined in the secret will not be encrypted
 * prior to storage; only the identifier and data will be stored in encrypted form.
 *
 * If the standalone secret already exists and was created by another application,
 * but the \a accessControlMode is \c OwnerOnlyMode, the request will fail,
 * as applications are not able to steal ownership from other applications.
 *
 * If the standalone secret does not already exist, or alternatively if it has
 * already been created by the calling application, or alternatively if it has
 * been created by a different application but the user has previously granted the
 * calling application permission to modify the secret, then the Secrets service
 * will instruct the storage plugin to store the secret.
 *
 * If the standalone secret was previously created by a different application
 * and the user has not yet been asked if the calling application should have
 * permission to modify the secret, then a system-mediated access control UI flow
 * may be triggered to obtain the user's permission (unless the given
 * \a userInteractionMode is \a PreventInteraction in which case the request
 * will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const Sailfish::Secrets::Secret &secret,
        Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!secret.identifier().isValid() || !secret.identifier().identifiesStandaloneSecret()) {
        Sailfish::Secrets::Result identifierError(Sailfish::Secrets::Result::InvalidSecretIdentifierError,
                                                  QLatin1String("This method cannot be invoked with a collection secret"));
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(identifierError)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<Sailfish::Secrets::Secret>(secret)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode));
    return reply;
}

/*!
 * \brief Requests the Secrets service to store the given \a secret with the given
 * \a secretName which is a standalone secret (not associated with a collection)
 * encrypted with an encryption key derived from a custom lock key which is obtained
 * from the user by the authentication plugin identified by the \a authenticationPluginName,
 * into the storage plugin identified by the given \a storagePluginName after ensuring
 * the secret is encrypted by the encryption plugin identified by the given
 * \a encryptionPluginName.
 *
 * Note that the filter data defined in the secret will not be encrypted
 * prior to storage; only the identifier and data will be stored in encrypted form.
 *
 * If the standalone secret already exists and was created by another application,
 * but the \a accessControlMode is \c OwnerOnlyMode, the request will fail,
 * as applications are not able to steal ownership from other applications.
 *
 * If the standalone secret does not already exist, or alternatively if it has
 * already been created by the calling application, or alternatively if it has
 * been created by a different application but the user has previously granted the
 * calling application permission to modify the secret, then the Secrets service
 * will instruct the storage plugin to store the secret.
 *
 * If the standalone secret was previously created by a different application
 * and the user has not yet been asked if the calling application should have
 * permission to modify the secret, then a system-mediated access control UI flow
 * may be triggered to obtain the user's permission (unless the given
 * \a userInteractionMode is \a PreventInteraction in which case the request
 * will fail).
 *
 * The custom lock authentication key will be obtained from the user via an
 * authentication flow determined by the authentication plugin (which may support
 * \c ApplicationInteraction for \c ApplicationSpecificAuthentication, but
 * otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventInteraction in which case the request will fail).
 *
 * If the \a unlockSemantic specified is \c CustomLockTimoutRelock then the
 * given \a customLockTimeoutMs will be used as the timeout (in milliseconds)
 * after the secret is unlocked which will trigger it to be relocked.
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &authenticationPluginName,
        const Sailfish::Secrets::Secret &secret,
        Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
        int customLockTimeoutMs,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!secret.identifier().isValid() || !secret.identifier().identifiesStandaloneSecret()) {
        Sailfish::Secrets::Result identifierError(Sailfish::Secrets::Result::InvalidSecretIdentifierError,
                                                  QLatin1String("This method cannot be invoked with a collection secret"));
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<QString>(authenticationPluginName)
                               << QVariant::fromValue<Sailfish::Secrets::Secret>(secret)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<int>(customLockTimeoutMs)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to retrieve the secret identified by the
 * given \a identifier from the plugin in which it is stored.
 *
 * If the secret belongs to a collection, the following semantics apply:
 *
 * If the calling application is the creator of the collection, or alternatively
 * if the user has granted the application permission to read from the collection
 * and either there are no special access controls associated with the particular
 * secret or the given application has permission to read the specific secret,
 * then the Secrets service will instruct the storage plugin to retrieve the secret
 * from the collection.
 *
 * If the application is not the creator of the collection and the user has not yet
 * been asked if the application should have permission to read the collection,
 * or if the secret already exists and has specific access controls associated with
 * it but the user has not yet been asked whether the application should have permission
 * to read the secret, then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given \a userInteractionMode is
 * \a PreventInteraction in which case the request will fail).
 *
 * If the collection uses an encryption key derived from the system device-lock,
 * then the value will be able to be retrieved without any other UI flow being required
 * if the collection is currently unlocked; however, if the collection uses an encryption
 * key derived from a custom lock, then the custom lock authentication key will be obtained
 * from the user via an authentication flow determined by the authentication plugin used for that
 * collection (which may support \c ApplicationInteraction if the collection
 * is an application-specific collection using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventInteraction in which case the request will fail).
 *
 * Otherwise, if the secret is a standalone secret, the following semantics apply:
 *
 * If the calling application is the creator of the secret, or alternatively
 * if the user has granted the application permission to read the specific secret,
 * then the Secrets service will instruct the storage plugin to retrieve the secret.
 *
 * If the application is not the creator of the secret and the user has not yet
 * been asked if the application should have permission to read the secret, then a
 * system-mediated access control UI flow may be triggered to obtain the user's
 * permission (unless the given \a userInteractionMode is \a PreventInteraction
 * in which case the request will fail).
 *
 * If the secret uses an encryption key derived from the system device-lock,
 * then the value will be able to be retrieved without any other UI flow being required
 * if the secret is currently unlocked; however, if the collection uses an encryption
 * key derived from a custom lock, then the custom lock authentication key will be obtained
 * from the user via an authentication flow determined by the authentication plugin used for that
 * secret (which may support \c ApplicationInteraction if the secret
 * is an application-specific secret using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventInteraction in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret>
Sailfish::Secrets::SecretManager::getSecret(
        const Sailfish::Secrets::Secret::Identifier &identifier,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!identifier.isValid()) {
        Sailfish::Secrets::Result identifierError(Sailfish::Secrets::Result::InvalidSecretIdentifierError,
                                                  QLatin1String("The given identifier is invalid"));
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "getSecret",
                QVariantList() << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(identifier)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

/*!
 * \brief Returns a list of identifiers of secrets belonging to the collection identified
 *        by the given \a collectionName which match the metadata field and value
 *        requirements specified in the given \a filter.
 *
 * The filter specifies metadata field/value pairs, and will be matched against
 * secrets in the storage according to the given \a filterOperator.
 *
 * For example, a Secret which has metadata which includes the following two entries:
 * "website"="sailfishos.org","type"="CryptoCertificate" will match the following
 * \a filter if the \a filterOperator is \c OperatorOr (since the secret metadata does
 * match one of the filter values) but not if it is either
 * \c OperatorAnd (since the secret metadata doesn't match both filter values)
 * or \c OperatorNot (since the secret metadata does match one of the filter values):
 * "website"="sailfishos.org","type"="UsernamePassword".
 *
 * If the calling application is the creator of the collection, or alternatively
 * if the user has granted the application permission to read from the collection
 * then the Secrets service will instruct the storage plugin to retrieve the list
 * of secret identifiers from the collection.
 *
 * If the application is not the creator of the collection and the user has not yet
 * been asked if the application should have permission to read the collection,
 * then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given \a userInteractionMode is
 * \a PreventInteraction in which case the request will fail).
 *
 * If the collection uses an encryption key derived from the system device-lock,
 * then the value will be able to be retrieved without any other UI flow being required
 * if the collection is currently unlocked; however, if the collection uses an encryption
 * key derived from a custom lock, then the custom lock authentication key will be obtained
 * from the user via an authentication flow determined by the authentication plugin used for that
 * collection (which may support \c ApplicationInteraction if the collection
 * is an application-specific collection using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventInteraction in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> >
Sailfish::Secrets::SecretManager::findSecrets(
        const QString &collectionName,
        const Sailfish::Secrets::Secret::FilterData &filter,
        Sailfish::Secrets::SecretManager::FilterOperator filterOperator,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> >(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (collectionName.isEmpty()) {
        Sailfish::Secrets::Result collectionError(Sailfish::Secrets::Result::InvalidCollectionError,
                                                  QLatin1String("The given collection name is invalid"));
        return QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> >(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(collectionError)
                                       << QVariant::fromValue<QVector<Sailfish::Secrets::Secret::Identifier> >(QVector<Sailfish::Secrets::Secret::Identifier>())));
    }

    QString interactionServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> >(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)
                                       << QVariant::fromValue<QVector<Sailfish::Secrets::Secret::Identifier> >(QVector<Sailfish::Secrets::Secret::Identifier>())));
    }

    QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> > reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "findSecrets",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<Sailfish::Secrets::Secret::FilterData>(filter)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::FilterOperator>(filterOperator)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

/*!
 * \brief Returns a list of identifiers of standalone secrets which match the metadata
 *        field and value requirements specified in the given \a filter.
 *
 * The filter specifies metadata field/value pairs, and will be matched against
 * secrets in the storage according to the given \a filterOperator.
 *
 * For example, a Secret which has metadata which includes the following two entries:
 * "website"="sailfishos.org","type"="CryptoCertificate" will match the following
 * \a filter if the \a filterOperator is \c OperatorOr (since the secret metadata does
 * match one of the filter values) but not if it is either
 * \c OperatorAnd (since the secret metadata doesn't match both filter values)
 * or \c OperatorNot (since the secret metadata does match one of the filter values):
 * "website"="sailfishos.org","type"="UsernamePassword".
 *
 * TODO: do I need to worry about access control here?  Or should I only do such
 * access control stuff on getSecret() instead of findSecrets()?  After all, the
 * filter metadata is not encrypted in the standalone secrets case...
 *
 * If the calling application is the creator of every matching secret, or alternatively
 * if the user has granted the application permission to read each matching secret,
 * then the Secrets service will instruct the storage plugin to retrieve the secrets.
 *
 * If the application is not the creator of a matching secret and the user has not yet
 * been asked if the application should have permission to read the secret, then a
 * system-mediated access control UI flow may be triggered to obtain the user's
 * permission (unless the given \a userInteractionMode is \a PreventInteraction
 * in which case the request will fail).
 *
 * If the secret uses an encryption key derived from the system device-lock,
 * then the value will be able to be retrieved without any other UI flow being required
 * if the secret is currently unlocked; however, if the secret uses an encryption
 * key derived from a custom lock, then the custom lock authentication key will be obtained
 * from the user via an authentication flow determined by the authentication plugin used for that
 * secret (which may support \c ApplicationInteraction if the secret
 * is an application-specific secret using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventInteraction in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result, QVector<Sailfish::Secrets::Secret::Identifier> >
Sailfish::Secrets::SecretManager::findSecrets(
        const Sailfish::Secrets::Secret::FilterData &filter,
        Sailfish::Secrets::SecretManager::FilterOperator filterOperator,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString interactionServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "findSecrets",
                QVariantList() << QVariant::fromValue<QString>(QString())
                               << QVariant::fromValue<Sailfish::Secrets::Secret::FilterData>(filter)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::FilterOperator>(filterOperator)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to delete the secret identified by the
 * given \a identifier from the plugin in which it is stored.
 *
 * If the secret belongs to a collection, the following semantics apply:
 *
 * If the calling application is the creator of the collection, or alternatively
 * if the user has granted the application permission to modify the collection
 * and either there are no special access controls associated with the particular
 * secret or the given application has permission to delete the specific secret,
 * then the Secrets service will instruct the storage plugin to delete the secret
 * from the collection.
 *
 * If the application is not the creator of the collection and the user has not yet
 * been asked if the application should have permission to modify the collection,
 * or if the secret already exists and has specific access controls associated with
 * it but the user has not yet been asked whether the application should have permission
 * to delete the secret, then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given \a userInteractionMode is
 * \a PreventInteraction in which case the request will fail).
 *
 * Otherwise, if the secret is a standalone secret, the following semantics apply:
 *
 * If the calling application is the creator of the secret, or alternatively
 * if the user has granted the application permission to delete the secret,
 * then the Secrets service will instruct the storage plugin to delete the secret.
 *
 * If the application is not the creator of the secret and the user has not yet
 * been asked if the application should have permission to delete the secret,
 * then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given \a userInteractionMode is
 * \a PreventInteraction in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::deleteSecret(
        const Sailfish::Secrets::Secret::Identifier &identifier,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    if (!identifier.isValid()) {
        Sailfish::Secrets::Result identifierError(Sailfish::Secrets::Result::InvalidSecretIdentifierError,
                                                  QLatin1String("The given identifier is invalid"));
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(identifierError)));
    }

    QString interactionServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerInteractionService(userInteractionMode, &interactionServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "deleteSecret",
                QVariantList() << QVariant::fromValue<Sailfish::Secrets::Secret::Identifier>(identifier)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(interactionServiceAddress));
    return reply;
}
