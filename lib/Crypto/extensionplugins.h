/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_H
#define LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/certificate.h"
#include "Crypto/key.h"
#include "Crypto/result.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QMap>
#include <QtCore/QSharedDataPointer>

#define Sailfish_Crypto_CryptoPlugin_IID "org.sailfishos.crypto.CryptoPlugin/1.0"

namespace Sailfish {

namespace Crypto {

class CryptoPluginInfo;
class SAILFISH_CRYPTO_API CryptoPlugin
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

    virtual QString name() const = 0;
    virtual bool canStoreKeys() const = 0;

    virtual Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const = 0;

    virtual QVector<Sailfish::Crypto::CryptoManager::Algorithm> supportedAlgorithms() const = 0;
    virtual QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> > supportedBlockModes() const = 0;
    virtual QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> > supportedEncryptionPaddings() const = 0;
    virtual QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> > supportedSignaturePaddings() const = 0;
    virtual QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> > supportedDigests() const = 0;
    virtual QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::MessageAuthenticationCode> > supportedMessageAuthenticationCodes() const = 0;
    virtual QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::KeyDerivationFunction> > supportedKeyDerivationFunctions() const = 0;
    virtual QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations> supportedOperations() const = 0;

    virtual Sailfish::Crypto::Result generateRandomData(
            quint64 callerIdent,
            const QString &csprngEngineName,
            quint64 numberBytes,
            QByteArray *randomData) = 0;

    virtual Sailfish::Crypto::Result seedRandomDataGenerator(
            quint64 callerIdent,
            const QString &csprngEngineName,
            const QByteArray &seedData,
            double entropyEstimate) = 0;

    virtual Sailfish::Crypto::Result validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            bool *validated) = 0;

    virtual Sailfish::Crypto::Result generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            Sailfish::Crypto::Key *key) = 0;

    virtual Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            Sailfish::Crypto::Key *keyMetadata) = 0;

    virtual Sailfish::Crypto::Result storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key::Components keyComponents,
            Sailfish::Crypto::Key *key) = 0;

    // This doesn't exist - if you can store keys, then you must also
    // implement the Secrets::EncryptedStoragePlugin interface, and
    // stored key deletion will occur through that API instead.
    //virtual Sailfish::Crypto::Result deleteStoredKey(
    //        const Sailfish::Crypto::Key::Identifier &identifier) = 0;

    virtual Sailfish::Crypto::Result storedKeyIdentifiers(
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers) = 0;

    virtual Sailfish::Crypto::Result calculateDigest(
            const QByteArray &data,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            QByteArray *digest) = 0;

    virtual Sailfish::Crypto::Result sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digest,
            QByteArray *signature) = 0;

    virtual Sailfish::Crypto::Result verify(
            const QByteArray &signature,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digest,
            bool *verified) = 0;

    virtual Sailfish::Crypto::Result encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            QByteArray *encrypted) = 0;

    virtual Sailfish::Crypto::Result decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            QByteArray *decrypted) = 0;

    virtual Sailfish::Crypto::Result initialiseCipherSession(
            quint64 clientId,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::Operation operation,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            Sailfish::Crypto::CryptoManager::DigestFunction digest,
            quint32 *cipherSessionToken,
            QByteArray *generatedIV) = 0;

    virtual Sailfish::Crypto::Result updateCipherSessionAuthentication(
            quint64 clientId,
            const QByteArray &authenticationData,
            quint32 cipherSessionToken) = 0;

    virtual Sailfish::Crypto::Result updateCipherSession(
            quint64 clientId,
            const QByteArray &data,
            quint32 cipherSessionToken,
            QByteArray *generatedData) = 0;

    virtual Sailfish::Crypto::Result finaliseCipherSession(
            quint64 clientId,
            const QByteArray &data,
            quint32 cipherSessionToken,
            QByteArray *generatedData,
            bool *verified) = 0;
};

class CryptoPluginInfoPrivate;
class SAILFISH_CRYPTO_API CryptoPluginInfo
{
public:
    CryptoPluginInfo();
    CryptoPluginInfo(const CryptoPluginInfo &other);
    CryptoPluginInfo(Sailfish::Crypto::CryptoPlugin *plugin);
    ~CryptoPluginInfo();

    CryptoPluginInfo &operator=(const CryptoPluginInfo &other);

    QString name() const;
    bool canStoreKeys() const;
    Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const;
    QVector<Sailfish::Crypto::CryptoManager::Algorithm> supportedAlgorithms() const;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> > supportedBlockModes() const;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> > supportedEncryptionPaddings() const;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> > supportedSignaturePaddings() const;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> > supportedDigests() const;
    QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations> supportedOperations() const;

    void setName(const QString &name);
    void setCanStoreKeys(bool v);
    void setEncryptionType(Sailfish::Crypto::CryptoPlugin::EncryptionType type);
    void setSupportedAlgorithms(const QVector<Sailfish::Crypto::CryptoManager::Algorithm> &algorithms);
    void setSupportedBlockModes(const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::BlockMode> > &modes);
    void setSupportedEncryptionPaddings(const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::EncryptionPadding> > &paddings);
    void setSupportedSignaturePaddings(const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::SignaturePadding> > &paddings);
    void setSupportedDigests(const QMap<Sailfish::Crypto::CryptoManager::Algorithm, QVector<Sailfish::Crypto::CryptoManager::DigestFunction> > &digests);
    void setSupportedOperations(const QMap<Sailfish::Crypto::CryptoManager::Algorithm, Sailfish::Crypto::CryptoManager::Operations> &operations);

    static QByteArray serialise(const Sailfish::Crypto::CryptoPluginInfo &pluginInfo);
    static Sailfish::Crypto::CryptoPluginInfo deserialise(const QByteArray &data);

private:
    QSharedDataPointer<CryptoPluginInfoPrivate> d_ptr;
    friend class CryptoPluginInfoPrivate;
};

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoPluginInfo);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::CryptoPluginInfo, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(QVector<Sailfish::Crypto::CryptoPluginInfo>);

QT_BEGIN_NAMESPACE
Q_DECLARE_INTERFACE(Sailfish::Crypto::CryptoPlugin, Sailfish_Crypto_CryptoPlugin_IID)
QT_END_NAMESPACE

#endif // LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_H
