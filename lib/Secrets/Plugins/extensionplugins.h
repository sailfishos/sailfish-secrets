/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_PLUGINAPI_EXTENSIONPLUGINS_H
#define LIBSAILFISHSECRETS_PLUGINAPI_EXTENSIONPLUGINS_H

#include <Secrets/secretsglobal.h>
#include <Secrets/secretmanager.h>
#include <Secrets/secret.h>
#include <Secrets/interactionparameters.h>
#include <Secrets/result.h>

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QMap>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QLoggingCategory>

#define Sailfish_Secrets_StoragePlugin_IID "org.sailfishos.secrets.StoragePlugin/1.0"
#define Sailfish_Secrets_EncryptionPlugin_IID "org.sailfishos.secrets.EncryptionPlugin/1.0"
#define Sailfish_Secrets_EncryptedStoragePlugin_IID "org.sailfishos.secrets.EncryptedStoragePlugin/1.0"
#define Sailfish_Secrets_AuthenticationPlugin_IID "org.sailfishos.secrets.AuthenticationPlugin/1.0"

SAILFISH_SECRETS_API Q_DECLARE_LOGGING_CATEGORY(lcSailfishSecretsPlugin)

namespace Sailfish {

namespace Secrets {

class SAILFISH_SECRETS_API PluginBase
{
public:
    PluginBase();
    virtual ~PluginBase();

    virtual void initialize();

    virtual QString displayName() const = 0;
    virtual QString name() const = 0;
    virtual int version() const = 0;
    virtual bool supportsLocking() const;
    virtual bool supportsSetLockCode() const;

    virtual bool isAvailable() const;
    virtual bool isLocked() const;
    virtual bool lock();
    virtual bool unlock(const QByteArray &lockCode);
    virtual bool setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode);
};

class SAILFISH_SECRETS_API EncryptionPlugin : public virtual Sailfish::Secrets::PluginBase
{
public:
    enum EncryptionType {
        NoEncryption = 0,                   // no encryption is performed
        SoftwareEncryption,                 // encryption is performed by "normal" rich execution environment application
        TrustedExecutionSoftwareEncryption, // encryption is performed by trusted execution environment application
        SecurePeripheralEncryption,         // encryption is performed by a secure hardware peripheral via TEE application
    };

    enum EncryptionAlgorithm {
        NoAlgorithm = 0,
        CustomAlgorithm,
        AES_256_CBC
    };

    EncryptionPlugin();
    virtual ~EncryptionPlugin();

    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const = 0;
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const = 0;

    virtual Sailfish::Secrets::Result deriveKeyFromCode(const QByteArray &authenticationCode, const QByteArray &salt, QByteArray *key) = 0;
    virtual Sailfish::Secrets::Result encryptSecret(const QByteArray &plaintext, const QByteArray &key, QByteArray *encrypted) = 0;
    virtual Sailfish::Secrets::Result decryptSecret(const QByteArray &encrypted, const QByteArray &key, QByteArray *plaintext) = 0;
};

class SAILFISH_SECRETS_API StoragePlugin : public virtual Sailfish::Secrets::PluginBase
{
public:
    enum StorageType {
        NoStorage = 0,
        InMemoryStorage,            // stored in-memory only, won't survive reboot
        FileSystemStorage,          // normal filesystem storage
        SecureFileSystemStorage,    // storage available to trusted execution environment applications only
        SecurePeripheralStorage,    // data is stored to a secure hardware peripheral via TEE application
    };

    enum FilterOperator {
        OperatorOr  = SecretManager::OperatorOr,
        OperatorAnd = SecretManager::OperatorAnd
    };

    StoragePlugin();
    virtual ~StoragePlugin();

    virtual Sailfish::Secrets::StoragePlugin::StorageType storageType() const = 0;

    virtual Sailfish::Secrets::Result collectionNames(QStringList *names) = 0;
    virtual Sailfish::Secrets::Result createCollection(const QString &collectionName) = 0;
    virtual Sailfish::Secrets::Result removeCollection(const QString &collectionName) = 0;
    virtual Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData) = 0;
    virtual Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) = 0;
    virtual Sailfish::Secrets::Result secretNames(const QString &collectionName, QStringList *secretNames) = 0;
    virtual Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QStringList *secretNames) = 0;
    virtual Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &secretName) = 0;

    virtual Sailfish::Secrets::Result reencrypt(
            const QString &collectionName,  // if non-empty, all secrets in this collection will be re-encrypted
            const QString &secretName,      // otherwise, this standalone secret will be encrypted.
            const QByteArray &oldkey,
            const QByteArray &newkey,
            Sailfish::Secrets::EncryptionPlugin *plugin) = 0;
};

class SAILFISH_SECRETS_API EncryptedStoragePlugin : public virtual Sailfish::Secrets::PluginBase
{
public:
    EncryptedStoragePlugin();
    virtual ~EncryptedStoragePlugin();

    virtual Sailfish::Secrets::StoragePlugin::StorageType storageType() const = 0;
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const = 0;
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const = 0;

    virtual Sailfish::Secrets::Result collectionNames(QStringList *names) = 0;
    virtual Sailfish::Secrets::Result createCollection(const QString &collectionName, const QByteArray &key) = 0;
    virtual Sailfish::Secrets::Result removeCollection(const QString &collectionName) = 0;

    virtual Sailfish::Secrets::Result isCollectionLocked(const QString &collectionName, bool *locked) = 0;
    virtual Sailfish::Secrets::Result deriveKeyFromCode(const QByteArray &authenticationCode, const QByteArray &salt, QByteArray *key) = 0;
    virtual Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName, const QByteArray &key) = 0;
    virtual Sailfish::Secrets::Result reencrypt(const QString &collectionName, const QByteArray &oldkey, const QByteArray &newkey) = 0;

    virtual Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData) = 0;
    virtual Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) = 0;
    virtual Sailfish::Secrets::Result secretNames(const QString &collectionName, QStringList *secretNames) = 0;
    virtual Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<Sailfish::Secrets::Secret::Identifier> *identifiers) = 0;
    virtual Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &secretName) = 0;

    // standalone secret operations.
    virtual Sailfish::Secrets::Result setSecret(const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData, const QByteArray &key) = 0;
    virtual Sailfish::Secrets::Result accessSecret(const QString &secretName, const QByteArray &key, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) = 0;
    virtual Sailfish::Secrets::Result removeSecret(const QString &secretName) = 0;
    virtual Sailfish::Secrets::Result reencryptSecret(const QString &secretName, const QByteArray &oldkey, const QByteArray &newkey) = 0;
};

class SAILFISH_SECRETS_API AuthenticationPlugin : public QObject, public virtual PluginBase
{
    Q_OBJECT

public:
    enum AuthenticationType {
        NoAuthentication                  = 0,  // no authentication, flows requiring authentication data will fail.
        ApplicationSpecificAuthentication = 1,  // unknown type, application generates auth code based on custom UI flow.
        SystemDefaultAuthentication       = 2,  // user enters some authentication data, as required by the system, to authenticate.
        PinCodeAuthentication             = 4,  // user enters a pin code as the authentication method
        PasswordAuthentication            = 8,  // user enters a password as the authentication method
        FingerprintAuthentication         = 16, // user scans their fingerprint as the authentication method
        IrisScanAuthentication            = 32, // user scans their iris as the authentication method
        VoiceRecognitionAuthentication    = 64  // user performs voice recognition as the authentication method
    };
    Q_ENUM(AuthenticationType)
    Q_DECLARE_FLAGS(AuthenticationTypes, AuthenticationType)

    AuthenticationPlugin(QObject *parent = Q_NULLPTR);
    virtual ~AuthenticationPlugin();

    virtual Sailfish::Secrets::AuthenticationPlugin::AuthenticationTypes authenticationTypes() const = 0;
    virtual Sailfish::Secrets::InteractionParameters::InputTypes inputTypes() const = 0;

    virtual Sailfish::Secrets::Result beginAuthentication(
            uint callerPid,
            qint64 requestId,
            const Sailfish::Secrets::InteractionParameters::PromptText &promptText) = 0;

    virtual Sailfish::Secrets::Result beginUserInputInteraction(
            uint callerPid,
            qint64 requestId,
            const Sailfish::Secrets::InteractionParameters &interactionParameters,
            const QString &interactionServiceAddress) = 0;

Q_SIGNALS:
    void authenticationCompleted(
            uint callerPid,
            qint64 requestId,
            const Sailfish::Secrets::Result &result);

    void userInputInteractionCompleted(
            uint callerPid,
            qint64 requestId,
            const Sailfish::Secrets::InteractionParameters &interactionParameters,
            const QString &interactionServiceAddress,
            const Sailfish::Secrets::Result &result,
            const QByteArray &userInput);
};

} // namespace Secrets

} // namespace Sailfish

Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Secrets::AuthenticationPlugin::AuthenticationTypes);

QT_BEGIN_NAMESPACE
Q_DECLARE_INTERFACE(Sailfish::Secrets::StoragePlugin, Sailfish_Secrets_StoragePlugin_IID)
Q_DECLARE_INTERFACE(Sailfish::Secrets::EncryptionPlugin, Sailfish_Secrets_EncryptionPlugin_IID)
Q_DECLARE_INTERFACE(Sailfish::Secrets::EncryptedStoragePlugin, Sailfish_Secrets_EncryptedStoragePlugin_IID)
Q_DECLARE_INTERFACE(Sailfish::Secrets::AuthenticationPlugin, Sailfish_Secrets_AuthenticationPlugin_IID)
QT_END_NAMESPACE

#endif // LIBSAILFISHSECRETS_PLUGINAPI_EXTENSIONPLUGINS_H
