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

#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QMap>

#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

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

    virtual bool isTestPlugin() const = 0;

    virtual QString name() const = 0;
    virtual bool canStoreKeys() const = 0;

    virtual Sailfish::Crypto::CryptoPlugin::EncryptionType encryptionType() const = 0;

    virtual QVector<Sailfish::Crypto::Key::Algorithm> supportedAlgorithms() const = 0;
    virtual QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> supportedBlockModes() const = 0;
    virtual QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> supportedEncryptionPaddings() const = 0;
    virtual QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> supportedSignaturePaddings() const = 0;
    virtual QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> supportedDigests() const = 0;
    virtual QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> supportedOperations() const = 0;

    virtual Sailfish::Crypto::Result validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            bool *validated) = 0;

    virtual Sailfish::Crypto::Result generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            Sailfish::Crypto::Key *key) = 0;

    virtual Sailfish::Crypto::Result generateAndStoreKey(
            const Sailfish::Crypto::Key &keyTemplate,
            Sailfish::Crypto::Key *keyMetadata) = 0;

    virtual Sailfish::Crypto::Result storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key *key) = 0;

    // This doesn't exist - if you can store keys, then you must also
    // implement the Secrets::EncryptedStoragePlugin interface, and
    // stored key deletion will occur through that API instead.
    //virtual Sailfish::Crypto::Result deleteStoredKey(
    //        const Sailfish::Crypto::Key::Identifier &identifier) = 0;

    virtual Sailfish::Crypto::Result storedKeyIdentifiers(
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers) = 0;

    virtual Sailfish::Crypto::Result sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            QByteArray *signature) = 0;

    virtual Sailfish::Crypto::Result verify(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            bool *verified) = 0;

    virtual Sailfish::Crypto::Result encrypt(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            Sailfish::Crypto::Key::Digest digest,
            QByteArray *encrypted) = 0;

    virtual Sailfish::Crypto::Result decrypt(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            Sailfish::Crypto::Key::Digest digest,
            QByteArray *decrypted) = 0;
};

class CryptoPluginInfoData;
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
    QVector<Sailfish::Crypto::Key::Algorithm> supportedAlgorithms() const;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> supportedBlockModes() const;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> supportedEncryptionPaddings() const;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> supportedSignaturePaddings() const;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> supportedDigests() const;
    QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> supportedOperations() const;

    void setName(const QString &name);
    void setCanStoreKeys(bool v);
    void setEncryptionType(Sailfish::Crypto::CryptoPlugin::EncryptionType type);
    void setSupportedAlgorithms(const QVector<Sailfish::Crypto::Key::Algorithm> &algorithms);
    void setSupportedBlockModes(const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::BlockModes> &modes);
    void setSupportedEncryptionPaddings(const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::EncryptionPaddings> &paddings);
    void setSupportedSignaturePaddings(const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::SignaturePaddings> &paddings);
    void setSupportedDigests(const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Digests> &digests);
    void setSupportedOperations(const QMap<Sailfish::Crypto::Key::Algorithm, Sailfish::Crypto::Key::Operations> &operations);

    static QByteArray serialise(const Sailfish::Crypto::CryptoPluginInfo &pluginInfo);
    static Sailfish::Crypto::CryptoPluginInfo deserialise(const QByteArray &data);

private:
    CryptoPluginInfoData *m_data;
};

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoPluginInfo &pluginInfo) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoPluginInfo &pluginInfo) SAILFISH_CRYPTO_API;

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::CryptoPluginInfo);
Q_DECLARE_METATYPE(QVector<Sailfish::Crypto::CryptoPluginInfo>);

QT_BEGIN_NAMESPACE
Q_DECLARE_INTERFACE(Sailfish::Crypto::CryptoPlugin, Sailfish_Crypto_CryptoPlugin_IID)
QT_END_NAMESPACE

#endif // LIBSAILFISHCRYPTO_EXTENSIONPLUGINS_H
