/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_EXTENSIONPLUGINS_H
#define LIBSAILFISHSECRETS_EXTENSIONPLUGINS_H

#include "Secrets/secretsglobal.h"
#include "Secrets/secret.h"
#include "Secrets/interactionparameters.h"
#include "Secrets/result.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QMap>
#include <QtCore/QByteArray>
#include <QtCore/QVector>

#define Sailfish_Secrets_StoragePlugin_IID "org.sailfishos.secrets.StoragePlugin/1.0"
#define Sailfish_Secrets_EncryptionPlugin_IID "org.sailfishos.secrets.EncryptionPlugin/1.0"
#define Sailfish_Secrets_EncryptedStoragePlugin_IID "org.sailfishos.secrets.EncryptedStoragePlugin/1.0"
#define Sailfish_Secrets_AuthenticationPlugin_IID "org.sailfishos.secrets.AuthenticationPlugin/1.0"

namespace Sailfish {

namespace Secrets {

class SAILFISH_SECRETS_API EncryptionPlugin : public QObject
{
    Q_OBJECT

public:
    enum EncryptionType {
        NoEncryption = 0,                   // no encryption is performed
        SoftwareEncryption,                 // encryption is performed by "normal" rich execution environment application
        TrustedExecutionSoftwareEncryption, // encryption is performed by trusted execution environment application
        SecurePeripheralEncryption,         // encryption is performed by a secure hardware peripheral via TEE application
    };
    Q_ENUM(EncryptionType)

    enum EncryptionAlgorithm {
        NoAlgorithm = 0,
        AES_256_CBC
    };
    Q_ENUM(EncryptionAlgorithm)

    EncryptionPlugin(QObject *parent = Q_NULLPTR);
    virtual ~EncryptionPlugin();

    virtual QString name() const = 0;
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const = 0;
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const = 0;

    virtual Sailfish::Secrets::Result encryptSecret(const QByteArray &plaintext, const QByteArray &key, QByteArray *encrypted) = 0;
    virtual Sailfish::Secrets::Result decryptSecret(const QByteArray &encrypted, const QByteArray &key, QByteArray *plaintext) = 0;
};

class EncryptionPluginInfoPrivate;
class SAILFISH_SECRETS_API EncryptionPluginInfo
{
public:
    EncryptionPluginInfo();
    EncryptionPluginInfo(const Sailfish::Secrets::EncryptionPluginInfo &other);
    EncryptionPluginInfo(const Sailfish::Secrets::EncryptionPlugin *plugin);
    ~EncryptionPluginInfo();

    QString name() const;
    void setName(const QString &name);

    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const;
    void setEncryptionType(Sailfish::Secrets::EncryptionPlugin::EncryptionType type);

    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const;
    void setEncryptionAlgorithm(Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm algorithm);

private:
    EncryptionPluginInfoPrivate *d;
};

class SAILFISH_SECRETS_API StoragePlugin : public QObject
{
    Q_OBJECT

public:
    enum StorageType {
        NoStorage = 0,
        InMemoryStorage,            // stored in-memory only, won't survive reboot
        FileSystemStorage,          // normal filesystem storage
        SecureFilesystemStorage,    // storage available to trusted execution environment applications only
        SecurePeripheralStorage,    // data is stored to a secure hardware peripheral via TEE application
    };
    Q_ENUM(StorageType)

    enum FilterOperator {
        OperatorOr = 0,
        OperatorAnd
    };
    Q_ENUM(FilterOperator)

    StoragePlugin(QObject *parent = Q_NULLPTR);
    virtual ~StoragePlugin();

    virtual QString name() const = 0;
    virtual Sailfish::Secrets::StoragePlugin::StorageType storageType() const = 0;

    virtual Sailfish::Secrets::Result createCollection(const QString &collectionName) = 0;
    virtual Sailfish::Secrets::Result removeCollection(const QString &collectionName) = 0;
    virtual Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &hashedSecretName, const QByteArray &encryptedSecretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData) = 0;
    virtual Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &hashedSecretName, QByteArray *encryptedSecretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) = 0;
    virtual Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<QByteArray> *encryptedSecretNames) = 0;
    virtual Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &hashedSecretName) = 0;

    virtual Sailfish::Secrets::Result reencryptSecrets(
            const QString &collectionName,             // if non-empty, all secrets in this collection will be re-encrypted
            const QVector<QString> &hashedSecretNames, // if collectionName is empty, these standalone secrets will be re-encrypted.
            const QByteArray &oldkey,
            const QByteArray &newkey,
            Sailfish::Secrets::EncryptionPlugin *plugin) = 0;
};

class StoragePluginInfoPrivate;
class SAILFISH_SECRETS_API StoragePluginInfo
{
public:
    StoragePluginInfo();
    StoragePluginInfo(const Sailfish::Secrets::StoragePluginInfo &other);
    StoragePluginInfo(const Sailfish::Secrets::StoragePlugin *plugin);
    ~StoragePluginInfo();

    QString name() const;
    void setName(const QString &name);

    Sailfish::Secrets::StoragePlugin::StorageType storageType() const;
    void setStorageType(Sailfish::Secrets::StoragePlugin::StorageType type);

private:
    StoragePluginInfoPrivate *d;
};

class SAILFISH_SECRETS_API EncryptedStoragePlugin : public QObject
{
    Q_OBJECT

public:
    EncryptedStoragePlugin(QObject *parent = Q_NULLPTR);
    virtual ~EncryptedStoragePlugin();

    virtual QString name() const = 0;
    virtual Sailfish::Secrets::StoragePlugin::StorageType storageType() const = 0;
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const = 0;
    virtual Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const = 0;

    virtual Sailfish::Secrets::Result createCollection(const QString &collectionName, const QByteArray &key) = 0;
    virtual Sailfish::Secrets::Result removeCollection(const QString &collectionName) = 0;

    virtual Sailfish::Secrets::Result isLocked(const QString &collectionName, bool *locked) = 0;
    virtual Sailfish::Secrets::Result setEncryptionKey(const QString &collectionName, const QByteArray &key) = 0;
    virtual Sailfish::Secrets::Result reencrypt(const QString &collectionName, const QByteArray &oldkey, const QByteArray &newkey) = 0;

    virtual Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &hashedSecretName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData) = 0;
    virtual Sailfish::Secrets::Result getSecret(const QString &collectionName, const QString &hashedSecretName, QString *secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) = 0;
    virtual Sailfish::Secrets::Result findSecrets(const QString &collectionName, const Sailfish::Secrets::Secret::FilterData &filter, Sailfish::Secrets::StoragePlugin::FilterOperator filterOperator, QVector<Sailfish::Secrets::Secret::Identifier> *identifiers) = 0;
    virtual Sailfish::Secrets::Result removeSecret(const QString &collectionName, const QString &hashedSecretName) = 0;

    virtual Sailfish::Secrets::Result setSecret(const QString &collectionName, const QString &hashedSecretName, const QString &secretName, const QByteArray &secret, const Sailfish::Secrets::Secret::FilterData &filterData, const QByteArray &key) = 0;
    virtual Sailfish::Secrets::Result accessSecret(const QString &collectionName, const QString &hashedSecretName, const QByteArray &key, QString *secretName, QByteArray *secret, Sailfish::Secrets::Secret::FilterData *filterData) = 0;
};

class EncryptedStoragePluginInfoPrivate;
class SAILFISH_SECRETS_API EncryptedStoragePluginInfo
{
public:
    EncryptedStoragePluginInfo();
    EncryptedStoragePluginInfo(const Sailfish::Secrets::EncryptedStoragePluginInfo &other);
    EncryptedStoragePluginInfo(const Sailfish::Secrets::EncryptedStoragePlugin *plugin);
    ~EncryptedStoragePluginInfo();

    QString name() const;
    void setName(const QString &name);

    Sailfish::Secrets::StoragePlugin::StorageType storageType() const;
    void setStorageType(Sailfish::Secrets::StoragePlugin::StorageType type);

    Sailfish::Secrets::EncryptionPlugin::EncryptionType encryptionType() const;
    void setEncryptionType(Sailfish::Secrets::EncryptionPlugin::EncryptionType type);

    Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm encryptionAlgorithm() const;
    void setEncryptionAlgorithm(Sailfish::Secrets::EncryptionPlugin::EncryptionAlgorithm algorithm);

private:
    EncryptedStoragePluginInfoPrivate *d;
};

class SAILFISH_SECRETS_API AuthenticationPlugin : public QObject
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

    virtual QString name() const = 0;
    virtual Sailfish::Secrets::AuthenticationPlugin::AuthenticationTypes authenticationTypes() const = 0;
    virtual Sailfish::Secrets::InteractionParameters::InputTypes inputTypes() const = 0;

    virtual Sailfish::Secrets::Result beginAuthentication(
            uint callerPid,
            qint64 requestId) = 0;

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

class AuthenticationPluginInfoPrivate;
class SAILFISH_SECRETS_API AuthenticationPluginInfo
{
public:
    AuthenticationPluginInfo();
    AuthenticationPluginInfo(const Sailfish::Secrets::AuthenticationPluginInfo &other);
    AuthenticationPluginInfo(const Sailfish::Secrets::AuthenticationPlugin *plugin);
    ~AuthenticationPluginInfo();

    QString name() const;
    void setName(const QString &name);

    Sailfish::Secrets::AuthenticationPlugin::AuthenticationTypes authenticationTypes() const;
    void setAuthenticationTypes(Sailfish::Secrets::AuthenticationPlugin::AuthenticationTypes types);

    Sailfish::Secrets::InteractionParameters::InputTypes inputTypes() const;
    void setInputTypes(Sailfish::Secrets::InteractionParameters::InputTypes types);

private:
    AuthenticationPluginInfoPrivate *d;
};

} // namespace Secrets

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Secrets::EncryptionPluginInfo);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::EncryptionPluginInfo, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Secrets::StoragePluginInfo);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::StoragePluginInfo, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Secrets::EncryptedStoragePluginInfo);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::EncryptedStoragePluginInfo, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Secrets::AuthenticationPluginInfo);
Q_DECLARE_TYPEINFO(Sailfish::Secrets::AuthenticationPluginInfo, Q_MOVABLE_TYPE);

Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Secrets::AuthenticationPlugin::AuthenticationTypes);

QT_BEGIN_NAMESPACE
Q_DECLARE_INTERFACE(Sailfish::Secrets::StoragePlugin, Sailfish_Secrets_StoragePlugin_IID)
Q_DECLARE_INTERFACE(Sailfish::Secrets::EncryptionPlugin, Sailfish_Secrets_EncryptionPlugin_IID)
Q_DECLARE_INTERFACE(Sailfish::Secrets::EncryptedStoragePlugin, Sailfish_Secrets_EncryptedStoragePlugin_IID)
Q_DECLARE_INTERFACE(Sailfish::Secrets::AuthenticationPlugin, Sailfish_Secrets_AuthenticationPlugin_IID)
QT_END_NAMESPACE

#endif // LIBSAILFISHSECRETS_EXTENSIONPLUGINS_H
