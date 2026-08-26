/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_PLUGINAPI_EXTENSIONPLUGINS_H
#define LIBSAILFISHCRYPTO_PLUGINAPI_EXTENSIONPLUGINS_H

#include <Secrets/Plugins/extensionplugins.h>

#include <Crypto/cryptoglobal.h>
#include <Crypto/key.h>
#include <Crypto/result.h>
#include <Crypto/storedkeyrequest.h>
#include <Crypto/keypairgenerationparameters.h>
#include <Crypto/keyderivationparameters.h>

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QMap>
#include <QtCore/QVariant>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QLoggingCategory>

#define Sailfish_Crypto_CryptoPlugin_IID "org.sailfishos.crypto.CryptoPlugin/1.0"
#define Sailfish_Crypto_MasterKeyPluginExtension_IID "org.sailfishos.crypto.MasterKeyPluginExtension/1.0"
#define Sailfish_Crypto_KeyMintOperationExtension_IID "org.sailfishos.crypto.KeyMintOperationExtension/1.1"

SAILFISH_CRYPTO_API Q_DECLARE_LOGGING_CATEGORY(lcSailfishCryptoPlugin)

namespace Sailfish {

namespace Crypto {

class SAILFISH_CRYPTO_API CryptoPlugin : public virtual Sailfish::Secrets::PluginBase
{
public:
    enum EncryptionType {
        NoEncryption = 0,                   // no encryption is performed
        SoftwareEncryption,                 // encryption is performed by "normal" rich execution environment application
        TrustedExecutionSoftwareEncryption, // encryption is performed by trusted execution environment application
        SecurePeripheralEncryption,         // encryption is performed by a secure hardware peripheral via TEE application
    };

    CryptoPlugin();
    virtual ~CryptoPlugin();

    virtual bool canStoreKeys() const = 0;

    virtual Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const = 0;

    virtual Sailfish::Crypto::Result generateRandomData(
            quint64 callerIdent,
            const QString &csprngEngineName,
            quint64 numberBytes,
            const QVariantMap &customParameters,
            QByteArray *randomData) = 0;

    virtual Sailfish::Crypto::Result seedRandomDataGenerator(
            quint64 callerIdent,
            const QString &csprngEngineName,
            const QByteArray &seedData,
            double entropyEstimate,
            const QVariantMap &customParameters) = 0;

    virtual Sailfish::Crypto::Result generateInitializationVector(
            Sailfish::Crypto::CryptoManager::Algorithm algorithm,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            int keySize,
            const QVariantMap &customParameters,
            QByteArray *generatedIV) = 0;

    virtual Sailfish::Crypto::Result generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *key) = 0;

    virtual Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *keyMetadata) = 0;

    virtual Sailfish::Crypto::Result importKey(
            const QByteArray &data,
            const QByteArray &passphrase,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *importedKey) = 0;

    virtual Sailfish::Crypto::Result importAndStoreKey(
            const QByteArray &data,
            const Sailfish::Crypto::Key &keyTemplate,
            const QByteArray &passphrase,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *keyMetadata) = 0;

    virtual Sailfish::Crypto::Result storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key::Components keyComponents,
            const QVariantMap &customParameters,
            Sailfish::Crypto::Key *key) = 0;

    // This doesn't exist - if you can store keys, then you must also
    // implement the Secrets::EncryptedStoragePlugin interface, and
    // stored key deletion will occur through that API instead.
    //virtual Sailfish::Crypto::Result deleteStoredKey(
    //        const Sailfish::Crypto::Key::Identifier &identifier) = 0;

    virtual Sailfish::Crypto::Result storedKeyIdentifiers(
            const QString &collectionName,
            const QVariantMap &customParameters,
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers) = 0;

    virtual Sailfish::Crypto::Result calculateDigest(
            const QByteArray &data,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            QByteArray *digest) = 0;

    virtual Sailfish::Crypto::Result sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            QByteArray *signature) = 0;

    virtual Sailfish::Crypto::Result verify(
            const QByteArray &signature,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) = 0;

    virtual Sailfish::Crypto::Result encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            QByteArray *encrypted,
            QByteArray *authenticationTag) = 0;

    virtual Sailfish::Crypto::Result decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QByteArray &authenticationTag,
            const QVariantMap &customParameters,
            QByteArray *decrypted,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) = 0;

    virtual Sailfish::Crypto::Result initializeCipherSession(
            quint64 clientId,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::Operation operation,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            quint32 *cipherSessionToken) = 0;

    virtual Sailfish::Crypto::Result updateCipherSessionAuthentication(
            quint64 clientId,
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken) = 0;

    virtual Sailfish::Crypto::Result updateCipherSession(
            quint64 clientId,
            const QByteArray &data,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken,
            QByteArray *generatedData) = 0;

    virtual Sailfish::Crypto::Result finalizeCipherSession(
            quint64 clientId,
            const QByteArray &data,
            const QVariantMap &customParameters,
            quint32 cipherSessionToken,
            QByteArray *generatedData,
            Sailfish::Crypto::CryptoManager::VerificationStatus *verificationStatus) = 0;
};

// Optional interfaces used by providers whose key material remains opaque to
// sailfishsecretsd.  They are deliberately separate from CryptoPlugin so an
// existing plugin does not gain new mandatory virtual methods.
class SAILFISH_CRYPTO_API MasterKeyPluginExtension
{
public:
    virtual ~MasterKeyPluginExtension() {}

    virtual Sailfish::Crypto::Result beginCreateMasterKey(
            const QByteArray &rootKey,
            quint32 sailfishUserId,
            quint64 secureUserId,
            const QByteArray &identityEpoch,
            quint64 *operationHandle,
            QByteArray *operationContext) = 0;

    virtual Sailfish::Crypto::Result finishCreateMasterKey(
            const QByteArray &operationContext,
            const QByteArray &serializedHardwareAuthToken,
            QByteArray *serializedEnvelope) = 0;

    virtual Sailfish::Crypto::Result beginOpenMasterKey(
            const QByteArray &serializedEnvelope,
            quint64 *operationHandle,
            QByteArray *operationContext) = 0;

    virtual Sailfish::Crypto::Result finishOpenMasterKey(
            const QByteArray &operationContext,
            const QByteArray &serializedHardwareAuthToken,
            QByteArray *rootKey) = 0;
};

class SAILFISH_CRYPTO_API KeyMintOperationExtension
{
public:
    virtual ~KeyMintOperationExtension() {}

    virtual Sailfish::Crypto::Result keyMintOneShot(
            quint32 operation,
            const QByteArray &request,
            qint32 *keyMintError,
            QByteArray *response) = 0;
    virtual Sailfish::Crypto::Result keyMintBegin(
            const QByteArray &request,
            qint32 *keyMintError,
            quint64 *operationHandle,
            QByteArray *response) = 0;
    virtual Sailfish::Crypto::Result keyMintUpdate(
            quint64 operationHandle,
            const QByteArray &request,
            qint32 *keyMintError,
            QByteArray *response) = 0;
    virtual Sailfish::Crypto::Result keyMintFinish(
            quint64 operationHandle,
            const QByteArray &request,
            qint32 *keyMintError,
            QByteArray *response) = 0;
    virtual Sailfish::Crypto::Result keyMintAbort(
            quint64 operationHandle,
            qint32 *keyMintError) = 0;
    virtual Sailfish::Crypto::Result keyMintDeviceLocked(
            bool passwordOnly,
            qint32 *keyMintError) = 0;
};

} // namespace Crypto

} // namespace Sailfish

QT_BEGIN_NAMESPACE
Q_DECLARE_INTERFACE(Sailfish::Crypto::CryptoPlugin, Sailfish_Crypto_CryptoPlugin_IID)
Q_DECLARE_INTERFACE(Sailfish::Crypto::MasterKeyPluginExtension, Sailfish_Crypto_MasterKeyPluginExtension_IID)
Q_DECLARE_INTERFACE(Sailfish::Crypto::KeyMintOperationExtension, Sailfish_Crypto_KeyMintOperationExtension_IID)
QT_END_NAMESPACE

#endif // LIBSAILFISHCRYPTO_PLUGINAPI_EXTENSIONPLUGINS_H
