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

Q_LOGGING_CATEGORY(lcSailfishSecrets, "org.sailfishos.secrets")

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
    , m_uiView(Q_NULLPTR)
    , m_secrets(Sailfish::Secrets::SecretsDaemonConnection::instance())
    , m_interface(m_secrets->connect()
                  ? m_secrets->createApiInterface(QLatin1String("/Sailfish/Secrets"), QLatin1String("org.sailfishos.secrets"), this)
                  : Q_NULLPTR)
{
}

Sailfish::Secrets::SecretManagerPrivate::~SecretManagerPrivate()
{
    Sailfish::Secrets::SecretsDaemonConnection::releaseInstance();
}

Sailfish::Secrets::Result
Sailfish::Secrets::SecretManagerPrivate::registerUiService(
        Sailfish::Secrets::SecretManager::UserInteractionMode mode,
        QString *address)
{
    if (mode == Sailfish::Secrets::SecretManager::InProcessUserInteractionMode) {
        if (!m_uiService) {
            m_uiService = new Sailfish::Secrets::UiService(this);
        }
        if (!m_uiService->registerServer()) {
            Sailfish::Secrets::Result result(Sailfish::Secrets::Result::UiServiceUnavailableError,
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
  The \a view the UiView instance which will display any UI required during secret request
  if the authentication plugin for the secret or collection supports \c ApplicationSpecificAuthentication
  in-process UI flows.

  Note that the UiView type does not extend QObject and thus no smart pointer (QPointer, etc)
  is used to track the lifetime of the view object.  The client must ensure that the view isn't
  destroyed prior to or during a request performed via the SecretManager, to avoid undefined behaviour.
 */
void Sailfish::Secrets::SecretManager::registerUiView(Sailfish::Secrets::UiView *view)
{
    // Note: UiView is not QObject-derived, so we cannot use QPointer etc.
    m_data->m_uiView = view;
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
 * and register a \l Sailfish::Secrets::UiView with the manager
 * which will then be used to provide the UI interaction with the
 * user, in-process.  (Note that if you do not wish any UI interaction,
 * the UiView implementation can return a precalculated key directly.)
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
 * If the \a userInteractionMode specified is \c InProcessUserInteractionMode
 * and the specified authentication plugin supports
 * \c ApplicationSpecificAuthentication flows, then the authentication key
 * will be obtained from the user via an in-process authentication flow (see
 * the documentation for \l registerUiView() for more information); otherwise,
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

    QString uiServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerUiService(userInteractionMode, &uiServiceAddress);
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
                               << QVariant::fromValue<QString>(uiServiceAddress));
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
 * permission (unless the given \a userInteractionMode is \a PreventUserInteractionMode
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
 * \brief Requests the Secrets service to store the given \a secret with the given
 * \a secretName into the collection identified by the given \a collectionName.
 *
 * If the calling application is the creator of the collection, or alternatively
 * if the user has granted the application permission to modify the collection
 * and either there are no special access controls associated with the particular
 * secret or the secret does not yet exist, then the Secrets service will instruct
 * the storage plugin to store the secret into the collection.
 *
 * If the application is not the creator of the collection and the user has not yet
 * been asked if the application should have permission to modify the collection,
 * or if the secret already exists and has specific access controls associated with
 * it but the user has not yet been asked whether the application should have permission
 * to modify the secret, then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given \a userInteractionMode is
 * \a PreventUserInteractionMode in which case the request will fail).
 *
 * If the collection uses an encryption key derived from the system device-lock,
 * then the value will be able to be stored without any other UI flow being required;
 * however, if the collection uses an encryption key derived from a custom lock,
 * then the custom lock authentication key will be obtained from the user via
 * an authentication flow determined by the authentication plugin used for that
 * collection (which may support \c InProcessUserInteractionMode if the collection
 * is an application-specific collection using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventUserInteractionMode in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::setSecret(
        const QString &collectionName,
        const QString &secretName,
        const QByteArray &secret,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString uiServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerUiService(userInteractionMode, &uiServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<QString>(secretName)
                               << QVariant::fromValue<QByteArray>(secret)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(uiServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to store the given \a secret with the given
 * \a secretName which is a standalone secret (not associated with a collection)
 * encrypted with an encryption key derived from the system device lock, which
 * will be locked and unlocked according to the given \a unlockSemantic.
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
 * \a userInteractionMode is \a PreventUserInteractionMode in which case the request
 * will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::setSecret(
        const QString &storagePluginName,
        const QString &encryptionPluginName,
        const QString &secretName,
        const QByteArray &secret,
        Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
        Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "setSecret",
                QVariantList() << QVariant::fromValue<QString>(storagePluginName)
                               << QVariant::fromValue<QString>(encryptionPluginName)
                               << QVariant::fromValue<QString>(secretName)
                               << QVariant::fromValue<QByteArray>(secret)
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
 * \a userInteractionMode is \a PreventUserInteractionMode in which case the request
 * will fail).
 *
 * The custom lock authentication key will be obtained from the user via an
 * authentication flow determined by the authentication plugin (which may support
 * \c InProcessUserInteractionMode for \c ApplicationSpecificAuthentication, but
 * otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventUserInteractionMode in which case the request will fail).
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
        const QString &secretName,
        const QByteArray &secret,
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

    QString uiServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerUiService(userInteractionMode, &uiServiceAddress);
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
                               << QVariant::fromValue<QString>(secretName)
                               << QVariant::fromValue<QByteArray>(secret)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic>(unlockSemantic)
                               << QVariant::fromValue<int>(customLockTimeoutMs)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::AccessControlMode>(accessControlMode)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(uiServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to retrieve the secret identified by the
 * given \a secretName from the collection identified by the given \a collectionName.
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
 * \a PreventUserInteractionMode in which case the request will fail).
 *
 * If the collection uses an encryption key derived from the system device-lock,
 * then the value will be able to be retrieved without any other UI flow being required
 * if the collection is currently unlocked; however, if the collection uses an encryption
 * key derived from a custom lock, then the custom lock authentication key will be obtained
 * from the user via an authentication flow determined by the authentication plugin used for that
 * collection (which may support \c InProcessUserInteractionMode if the collection
 * is an application-specific collection using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventUserInteractionMode in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result, QByteArray>
Sailfish::Secrets::SecretManager::getSecret(
        const QString &collectionName,
        const QString &secretName,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString uiServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerUiService(userInteractionMode, &uiServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result, QByteArray> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "getSecret",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<QString>(secretName)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(uiServiceAddress));
    return reply;
}


/*!
 * \brief Requests the Secrets service to retrieve the secret identified by the
 * given \a secretName which is a standalone secret (not part of any collection).
 *
 * If the calling application is the creator of the secret, or alternatively
 * if the user has granted the application permission to read the specific secret,
 * then the Secrets service will instruct the storage plugin to retrieve the secret.
 *
 * If the application is not the creator of the secret and the user has not yet
 * been asked if the application should have permission to read the secret, then a
 * system-mediated access control UI flow may be triggered to obtain the user's
 * permission (unless the given \a userInteractionMode is \a PreventUserInteractionMode
 * in which case the request will fail).
 *
 * If the collection uses an encryption key derived from the system device-lock,
 * then the value will be able to be retrieved without any other UI flow being required
 * if the collection is currently unlocked; however, if the collection uses an encryption
 * key derived from a custom lock, then the custom lock authentication key will be obtained
 * from the user via an authentication flow determined by the authentication plugin used for that
 * collection (which may support \c InProcessUserInteractionMode if the collection
 * is an application-specific collection using an \c ApplicationSpecificAuthentication
 * plugin, but otherwise will be a system-mediated UI flow, unless the \a userInteractionMode
 * specified is \c PreventUserInteractionMode in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result, QByteArray>
Sailfish::Secrets::SecretManager::getSecret(
        const QString &secretName,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString uiServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerUiService(userInteractionMode, &uiServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result, QByteArray> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "getSecret",
                QVariantList() << QVariant::fromValue<QString>(secretName)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(uiServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to delete the secret identified by the
 * given \a secretName from the collection identified by the given \a collectionName.
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
 * \a PreventUserInteractionMode in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::deleteSecret(
        const QString &collectionName,
        const QString &secretName,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QString uiServiceAddress;
    Sailfish::Secrets::Result uiServiceResult = m_data->registerUiService(userInteractionMode, &uiServiceAddress);
    if (uiServiceResult.code() == Sailfish::Secrets::Result::Failed) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                QDBusMessage().createReply(
                        QVariantList() << QVariant::fromValue<Sailfish::Secrets::Result>(uiServiceResult)));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "deleteSecret",
                QVariantList() << QVariant::fromValue<QString>(collectionName)
                               << QVariant::fromValue<QString>(secretName)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode)
                               << QVariant::fromValue<QString>(uiServiceAddress));
    return reply;
}

/*!
 * \brief Requests the Secrets service to delete the secret identified by the
 * given \a secretName which is a standalone secret (not part of a collection).
 *
 * If the calling application is the creator of the secret, or alternatively
 * if the user has granted the application permission to delete the secret,
 * then the Secrets service will instruct the storage plugin to delete the secret.
 *
 * If the application is not the creator of the secret and the user has not yet
 * been asked if the application should have permission to delete the secret,
 * then a system-mediated access control UI flow may be triggered
 * to obtain the user's permission (unless the given \a userInteractionMode is
 * \a PreventUserInteractionMode in which case the request will fail).
 */
QDBusPendingReply<Sailfish::Secrets::Result>
Sailfish::Secrets::SecretManager::deleteSecret(
        const QString &secretName,
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode)
{
    if (!m_data->m_interface) {
        return QDBusPendingReply<Sailfish::Secrets::Result>(
                    QDBusMessage::createError(QDBusError::Other,
                                              QStringLiteral("Not connected to daemon")));
    }

    QDBusPendingReply<Sailfish::Secrets::Result> reply
            = m_data->m_interface->asyncCallWithArgumentList(
                "deleteSecret",
                QVariantList() << QVariant::fromValue<QString>(secretName)
                               << QVariant::fromValue<Sailfish::Secrets::SecretManager::UserInteractionMode>(userInteractionMode));
    return reply;
}
