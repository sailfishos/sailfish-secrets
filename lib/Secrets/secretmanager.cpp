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


/*!
 * \internal
 * \brief Request the Secrets service create a collection with the given
 * \a collectionName which will be stored by the storage plugin
 * identified by the given \a storagePluginName, and whose secrets will
 * be encrypted and decrypted with an encryption key derived from the system
 * device lock key by the encryption plugin identified by the given
 * \a encryptionPluginName according to the specified \a unlockSemantic,
 * to which access will be controlled according to the given \a accessControlMode.
 *
 * If the \a storagePluginName is the same as the \a encryptionPluginName
 * then the plugin is assumed to be a EncryptedStoragePlugin.
 */
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

/*!
 * \internal
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
 * then the plugin is assumed to be a EncryptedStoragePlugin.
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

/*!
 * \internal
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

/*!
 * \internal
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

/*!
 * \internal
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

/*!
 * \internal
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

/*!
 * \internal
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

/*!
 * \internal
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

/*!
 * \internal
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

/*!
 * \internal
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
