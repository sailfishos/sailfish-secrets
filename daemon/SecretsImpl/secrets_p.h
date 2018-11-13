/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_APIIMPL_SECRETS_P_H
#define SAILFISHSECRETS_APIIMPL_SECRETS_P_H

#include "requestqueue_p.h"
#include "applicationpermissions_p.h"

#include "Secrets/secret.h"
#include "Secrets/interactionparameters.h"
#include "Secrets/plugininfo.h"
#include "Secrets/healthcheckrequest.h"
#include "Secrets/secretmanager.h"
#include "Secrets/result.h"
#include "Secrets/lockcoderequest.h"

#include "Crypto/result.h"
#include "Crypto/key.h"

#include <QtCore/QStringList>
#include <QtCore/QThreadPool>
#include <QtCore/QSharedPointer>
#include <QtDBus/QDBusContext>

// the environment variable which can be used to specify the name
// of the crypto plugin to use when deriving the master lock keys.
#define ENV_MASTERLOCK_CRYPTOPLUGIN "SAILFISH_SECRETSD_MASTERLOCK_CRYPTOPLUGIN"

namespace Sailfish {

// forward declare the CryptoRequestQueue type
namespace Crypto {
    namespace Daemon {
        namespace ApiImpl {
            class CryptoRequestQueue;
            class CryptoStoragePluginWrapper;
        }
    }
}

namespace Secrets {

namespace Daemon {

namespace ApiImpl {

class SecretsRequestQueue;
class SecretsDBusObject : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.sailfishos.secrets")
    Q_CLASSINFO("D-Bus Introspection", ""
    "  <interface name=\"org.sailfishos.secrets\">\n"
    "      <method name=\"getPluginInfo\">\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"storagePlugins\" type=\"a(ssi)\" direction=\"out\" />\n"
    "          <arg name=\"encryptionPlugins\" type=\"a(ssi)\" direction=\"out\" />\n"
    "          <arg name=\"encryptedStoragePlugins\" type=\"a(ssi)\" direction=\"out\" />\n"
    "          <arg name=\"authenticationPlugins\" type=\"a(ssi)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"QVector<Sailfish::Secrets::PluginInfo>\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out2\" value=\"QVector<Sailfish::Secrets::PluginInfo>\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out3\" value=\"QVector<Sailfish::Secrets::PluginInfo>\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out4\" value=\"QVector<Sailfish::Secrets::PluginInfo>\" />\n"
    "      </method>\n"
    "      <method name=\"getHealthInfo\">\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"saltDataHealth\" type=\"(i)\" direction=\"out\" />\n"
    "          <arg name=\"masterlockHealth\" type=\"(i)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Secrets::HealthCheckRequest::Health\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out2\" value=\"Sailfish::Secrets::HealthCheckRequest::Health\" />\n"
    "      </method>\n"
    "      <method name=\"userInput\">\n"
    "          <arg name=\"uiParams\" type=\"(ssss(i)sa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"collectionNames\">\n"
    "          <arg name=\"storagePluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"names\" type=\"a{sb}\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"createCollection\">\n"
    "          <arg name=\"collectionName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"storagePluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"encryptionPluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"unlockSemantic\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"accessControlMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Secrets::SecretManager::AccessControlMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"createCollection\">\n"
    "          <arg name=\"collectionName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"storagePluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"encryptionPluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"authenticationPluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"unlockSemantic\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"accessControlMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In5\" value=\"Sailfish::Secrets::SecretManager::AccessControlMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In6\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"deleteCollection\">\n"
    "          <arg name=\"collectionName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"storagePluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"setSecret\">\n"
    "          <arg name=\"secret\" type=\"((sss)aya{sv})\" direction=\"in\" />\n"
    "          <arg name=\"uiParams\" type=\"(ssss(i)sa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::Secret\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Secrets::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"setSecret\">\n"
    "          <arg name=\"secret\" type=\"((sss)aya{sv})\" direction=\"in\" />\n"
    "          <arg name=\"encryptionPluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"uiParams\" type=\"(ssss(i)sa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"unlockSemantic\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"accessControlMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::Secret\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Secrets::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Secrets::SecretManager::AccessControlMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In5\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"setSecret\">\n"
    "          <arg name=\"secret\" type=\"((sss)aya{sv})\" direction=\"in\" />\n"
    "          <arg name=\"encryptionPluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"authenticationPluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"uiParams\" type=\"(ssss(i)sa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"unlockSemantic\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"accessControlMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::Secret\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Secrets::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In5\" value=\"Sailfish::Secrets::SecretManager::AccessControlMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In6\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"getSecret\">\n"
    "          <arg name=\"identifier\" type=\"(sss)\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"secret\" type=\"((sss)aya{sv})\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::Secret::Identifier\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Secrets::Secret\" />\n"
    "      </method>\n"
    "      <method name=\"findSecrets\">\n"
    "          <arg name=\"collectionName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"storagePluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"filter\" type=\"a{ss}\" direction=\"in\" />\n"
    "          <arg name=\"filterOperator\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"identifiers\" type=\"(a(sss))\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Secrets::Secret::FilterData\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Secrets::SecretManager::FilterOperator\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"QVector<Sailfish::Secrets::Secret::Identifier>\" />\n"
    "      </method>\n"
    "      <method name=\"deleteSecret\">\n"
    "          <arg name=\"identifier\" type=\"(sss)\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::Secret::Identifier\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"queryLockStatus\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"lockStatus\" type=\"(i)\" direction=\"in\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Secrets::LockCodeRequest::LockStatus\" />\n"
    "      </method>\n"
    "      <method name=\"modifyLockCode\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"interactionParameters\" type=\"(ssss(i)sa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Secrets::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"provideLockCode\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"interactionParameters\" type=\"(ssss(i)sa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Secrets::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "      <method name=\"forgetLockCode\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"interactionParameters\" type=\"(ssss(i)sa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"userInteractionMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"interactionServiceAddress\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Secrets::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Secrets::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Secrets::SecretManager::UserInteractionMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Secrets::Result\" />\n"
    "      </method>\n"
    "  </interface>\n"
    "")

public:
    SecretsDBusObject(Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *parent);

public Q_SLOTS:
    // retrieve information about available plugins
    void getPluginInfo(
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result,
            QVector<Sailfish::Secrets::PluginInfo> &storagePlugins,
            QVector<Sailfish::Secrets::PluginInfo> &encryptionPlugins,
            QVector<Sailfish::Secrets::PluginInfo> &encryptedStoragePlugins,
            QVector<Sailfish::Secrets::PluginInfo> &authenticationPlugins);

    // retrieve information about secrets health
    void getHealthInfo(
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result,
            Sailfish::Secrets::HealthCheckRequest::Health &saltDataHealth,
            Sailfish::Secrets::HealthCheckRequest::Health &masterlockHealth);

    // retrieve user input for the client (daemon)
    void userInput(
            const Sailfish::Secrets::InteractionParameters &uiParams,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result,
            QByteArray &data);

    // retrieve the names of collections
    void collectionNames(
            const QString &storagePluginName,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result,
            QVariantMap &names);

    // create a DeviceLock-protected collection
    void createCollection(
            const QString &collectionName,
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // create a CustomLock-protected collection
    void createCollection(
            const QString &collectionName,
            const QString &storagePluginName,
            const QString &encryptionPluginName,
            const QString &authenticationPluginName,
            Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // delete a collection
    void deleteCollection(
            const QString &collectionName,
            const QString &storagePluginName,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // set a secret in a collection
    void setSecret(
            const Sailfish::Secrets::Secret &secret,
            const Sailfish::Secrets::InteractionParameters &uiParams,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // set a standalone DeviceLock-protected secret
    void setSecret(
            const Sailfish::Secrets::Secret &secret,
            const QString &encryptionPluginName,
            const Sailfish::Secrets::InteractionParameters &uiParams,
            Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic unlockSemantic,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // set a standalone CustomLock-protected secret
    void setSecret(
            const Sailfish::Secrets::Secret &secret,
            const QString &encryptionPluginName,
            const QString &authenticationPluginName,
            const Sailfish::Secrets::InteractionParameters &uiParams,
            Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic unlockSemantic,
            Sailfish::Secrets::SecretManager::AccessControlMode accessControlMode,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // get a secret
    void getSecret(
            const Sailfish::Secrets::Secret::Identifier &identifier,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result,
            Sailfish::Secrets::Secret &secret);

    // find secrets via filter
    void findSecrets(
            const QString &collectionName,
            const QString &storagePluginName,
            const Sailfish::Secrets::Secret::FilterData &filter,
            Sailfish::Secrets::SecretManager::FilterOperator filterOperator,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result,
            QVector<Sailfish::Secrets::Secret::Identifier> &identifiers);

    // delete a secret
    void deleteSecret(
            const Sailfish::Secrets::Secret::Identifier &identifier,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // query lock status of a plugin or metadata db
    void queryLockStatus(
            Sailfish::Secrets::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result,
            Sailfish::Secrets::LockCodeRequest::LockStatus &lockStatus);

    // modify a lock code (re-key a plugin or metadata db)
    void modifyLockCode(
            Sailfish::Secrets::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Secrets::InteractionParameters &interactionParameters,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // provide a lock code (unlock a plugin or metadata db)
    void provideLockCode(
            Sailfish::Secrets::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Secrets::InteractionParameters &interactionParameters,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

    // forget a lock code (lock a plugin or metadata db)
    void forgetLockCode(
            Sailfish::Secrets::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Secrets::InteractionParameters &interactionParameters,
            Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode,
            const QString &interactionServiceAddress,
            const QDBusMessage &message,
            Sailfish::Secrets::Result &result);

private:
    Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *m_requestQueue;
};

class RequestProcessor;
class SecretsRequestQueue : public Sailfish::Secrets::Daemon::ApiImpl::RequestQueue
{
    Q_OBJECT

public:
    enum InitializationMode {
        ModifyLockMode,
        UnlockMode,
        LockMode
    };

    SecretsRequestQueue(Sailfish::Secrets::Daemon::Controller *parent, bool autotestMode);
    ~SecretsRequestQueue();

    Sailfish::Secrets::Daemon::Controller *controller() const;
    QWeakPointer<QThreadPool> secretsThreadPool();
    bool initialize(const QByteArray &lockCode, InitializationMode mode);
    bool initializePlugins();

    void handlePendingRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) Q_DECL_OVERRIDE;
    void handleFinishedRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) Q_DECL_OVERRIDE;
    QString requestTypeToString(int type) const Q_DECL_OVERRIDE;

public: // helpers for crypto API: secretscryptohelpers.cpp
    QMap<QString, QObject*> potentialCryptoStoragePlugins() const;
    Sailfish::Crypto::Daemon::ApiImpl::CryptoStoragePluginWrapper *cryptoStoragePluginWrapper(const QString &pluginName) const;
    QStringList encryptedStoragePluginNames() const;
    QStringList storagePluginNames() const;
    QString displayNameForStoragePlugin(const QString &name) const;

private:
    QSharedPointer<QThreadPool> m_secretsThreadPool;
    Sailfish::Secrets::Daemon::ApiImpl::ApplicationPermissions *m_appPermissions;
    Sailfish::Secrets::Daemon::ApiImpl::RequestProcessor *m_requestProcessor;
    Sailfish::Secrets::Daemon::Controller *m_controller;
    bool m_autotestMode;

    // mlock() data for the bookkeeping database lock key and device lock key
    char *m_bkdbLockKeyData;
    char *m_deviceLockKeyData;
    int m_bkdbLockKeyLen;
    int m_deviceLockKeyLen;
    bool m_noLockCode;
    bool m_locked;
    mutable QByteArray m_saltData;
    bool generateKeyData(const QByteArray &lockCode, const QString &cipherPluginName, QByteArray *bkdbKey, QByteArray *deviceLockKey, QByteArray *testCipherText, QString *usedCipherPluginName) const;
    bool initializeKeyData(const QByteArray &bkdkKey, const QByteArray &deviceLockKey);
    void dealWithDataCorruption() const;

public: // For use by the secrets request processor to handle device-locked collection/secret semantics
    bool masterLocked() const;
    bool testLockCode(const QByteArray &lockCode) const;
    bool compareTestCipherText(const QByteArray &testCipherText, bool writeIfNotExists, const QString &cipherPluginName) const;
    bool writeTestCipherText(const QByteArray &testCipherText, const QString &cipherPluginName) const; // the testCipherText file should be considered mutable.
    bool determineTestCipherPlugin(QString *cipherPluginName) const;
    QByteArray saltData() const;
    bool noLockCode() const;
    void setNoLockCode(bool value);
    const QByteArray bkdbLockKey() const;
    const QByteArray deviceLockKey() const;

    Sailfish::Secrets::Result queryLockStatusCryptoPlugin(const QString &pluginName, Sailfish::Secrets::LockCodeRequest::LockStatus *lockStatus);
    Sailfish::Secrets::Result lockCryptoPlugin(const QString &pluginName);
    Sailfish::Secrets::Result unlockCryptoPlugin(const QString &pluginName, const QByteArray &lockCode);
    Sailfish::Secrets::Result setLockCodeCryptoPlugin(const QString &pluginName, const QByteArray &oldCode, const QByteArray &newCode);

public: // Crypto API helper methods.
    // these methods are provided in order to implement Crypto functionality
    // while using just one single database (for atomicity etc).
    void asynchronousCryptoRequestCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result, const QVariantList &parameters);
    // the first methods are synchronous:
    Sailfish::Secrets::Result storagePluginInfo(pid_t callerPid, quint64 cryptoRequestId, QVector<Sailfish::Secrets::PluginInfo> *info) const;
    // the others are asynchronous methods:
    Sailfish::Secrets::Result useKeyPreCheck(pid_t callerPid, quint64 cryptoRequestId, const Sailfish::Crypto::Key::Identifier &identifier, Sailfish::Crypto::CryptoManager::Operation operation, const QString &cryptoPluginName);
    Sailfish::Secrets::Result storedKey(pid_t callerPid, quint64 cryptoRequestId, const Sailfish::Crypto::Key::Identifier &identifier, QByteArray *serializedKey, QMap<QString, QString> *filterData);
    Sailfish::Secrets::Result storeKeyPreCheck(pid_t callerPid, quint64 cryptoRequestId, const Sailfish::Crypto::Key::Identifier &identifier);
    Sailfish::Secrets::Result storeKey(pid_t callerPid, quint64 cryptoRequestId, const Sailfish::Crypto::Key::Identifier &identifier, const QByteArray &serializedKey,
                                       const QMap<QString, QString> &filterData, const QByteArray &collectionDecryptionKey);
    Sailfish::Secrets::Result storedKeyIdentifiers(pid_t callerPid, quint64 cryptoRequestId, const QString &collectionName, const QString &storagePluginName,
                                                   const QVariantMap &customParameters, QVector<Sailfish::Crypto::Key::Identifier> *identifiers);
    Sailfish::Secrets::Result deleteStoredKey(pid_t callerPid, quint64 cryptoRequestId, const Sailfish::Crypto::Key::Identifier &identifier);
    Sailfish::Secrets::Result userInput(pid_t callerPid, quint64 cryptoRequestId, const Sailfish::Secrets::InteractionParameters &uiParams);
    Sailfish::Secrets::Result queryCryptoPluginLockStatus(pid_t callerPid, quint64 cryptoRequestId, const QString &cryptoPluginName);
    Sailfish::Secrets::Result modifyCryptoPluginLockCode(pid_t callerPid, quint64 cryptoRequestId, const QString &cryptoPluginName, const Sailfish::Secrets::InteractionParameters &uiParams);
    Sailfish::Secrets::Result provideCryptoPluginLockCode(pid_t callerPid, quint64 cryptoRequestId, const QString &cryptoPluginName, const Sailfish::Secrets::InteractionParameters &uiParams);
    Sailfish::Secrets::Result forgetCryptoPluginLockCode(pid_t callerPid, quint64 cryptoRequestId, const QString &cryptoPluginName, const Sailfish::Secrets::InteractionParameters &uiParams);

Q_SIGNALS:
    void useKeyPreCheckCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result, const QByteArray &collectionDecryptionKey);
    void storedKeyCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result, const QByteArray &serializedKey, const QMap<QString,QString> &filterData);
    void storeKeyPreCheckCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result, const QByteArray &collectionDecryptionKey);
    void storeKeyCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result);
    void deleteStoredKeyCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result);
    void storedKeyIdentifiersCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result, const QVector<Sailfish::Secrets::Secret::Identifier> &idents);
    void userInputCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result, const QByteArray &userInput);
    void cryptoPluginLockStatusRequestCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result, Sailfish::Secrets::LockCodeRequest::LockStatus lockStatus);
    void cryptoPluginLockCodeRequestCompleted(quint64 cryptoRequestId, const Sailfish::Secrets::Result &result);
private:
    enum CryptoApiHelperRequestType {
        InvalidCryptoApiHelperRequest = 0,
        StoragePluginNamesCryptoApiHelperRequest,
        StoredKeyCryptoApiHelperRequest,
        StoredKeyIdentifiersCryptoApiHelperRequest,
        DeleteStoredKeyCryptoApiHelperRequest,
        UseKeyPreCheckCryptoApiHelperRequest,
        StoreKeyPreCheckCryptoApiHelperRequest,
        StoreKeyCryptoApiHelperRequest,
        UserInputCryptoApiHelperRequest,
        QueryLockStatusCryptoApiHelperRequest,
        ModifyLockCodeCryptoApiHelperRequest,
        ProvideLockCodeCryptoApiHelperRequest,
        ForgetLockCodeCryptoApiHelperRequest
    };
    QMap<quint64, CryptoApiHelperRequestType> m_cryptoApiHelperRequests; // crypto request id to crypto api call type.
};

enum RequestType {
    InvalidRequest = 0,
    GetPluginInfoRequest,
    GetHealthInfoRequest,
    UserInputRequest,
    CollectionNamesRequest,
    CreateDeviceLockCollectionRequest,
    CreateCustomLockCollectionRequest,
    DeleteCollectionRequest,
    SetCollectionSecretRequest,
    SetStandaloneDeviceLockSecretRequest,
    SetStandaloneCustomLockSecretRequest,
    GetCollectionSecretRequest,
    GetStandaloneSecretRequest,
    FindCollectionSecretsRequest,
    FindStandaloneSecretsRequest,
    DeleteCollectionSecretRequest,
    DeleteStandaloneSecretRequest,
    QueryLockStatusRequest,
    ModifyLockCodeRequest,
    ProvideLockCodeRequest,
    ForgetLockCodeRequest,
    // Internal user input request types:
    SetCollectionUserInputSecretRequest,
    SetStandaloneDeviceLockUserInputSecretRequest,
    SetStandaloneCustomLockUserInputSecretRequest,
    // Crypto API helper request types:
    UseCollectionKeyPreCheckRequest,
    SetCollectionKeyPreCheckRequest,
    SetCollectionKeyRequest,
    StoredKeyIdentifiersRequest
};

} // ApiImpl

} // Daemon

} // Secrets

} // Sailfish

#endif // SAILFISHSECRETS_APIIMPL_SECRETS_P_H
