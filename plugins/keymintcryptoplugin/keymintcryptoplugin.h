/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_PLUGIN_KEYMINT_H
#define SAILFISHCRYPTO_PLUGIN_KEYMINT_H

#include "Crypto/Plugins/extensionplugins.h"

#include <QtCore/QObject>

namespace Sailfish {
namespace Crypto {
namespace Daemon {
namespace Plugins {

class KeyMintCryptoPlugin : public QObject,
        public virtual Sailfish::Crypto::CryptoPlugin,
        public virtual Sailfish::Crypto::MasterKeyPluginExtension,
        public virtual Sailfish::Crypto::KeyMintOperationExtension
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID Sailfish_Crypto_CryptoPlugin_IID)
    Q_INTERFACES(Sailfish::Crypto::CryptoPlugin
                 Sailfish::Crypto::MasterKeyPluginExtension
                 Sailfish::Crypto::KeyMintOperationExtension)

public:
    explicit KeyMintCryptoPlugin(QObject *parent = Q_NULLPTR);
    ~KeyMintCryptoPlugin();

    QString displayName() const Q_DECL_OVERRIDE;
    QString name() const Q_DECL_OVERRIDE;
    int version() const Q_DECL_OVERRIDE;
    bool canStoreKeys() const Q_DECL_OVERRIDE;
    EncryptionType encryptionType() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result generateRandomData(quint64, const QString &, quint64,
                                                const QVariantMap &, QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result seedRandomDataGenerator(quint64, const QString &,
                                                     const QByteArray &, double,
                                                     const QVariantMap &) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result generateInitializationVector(CryptoManager::Algorithm,
                                                          CryptoManager::BlockMode, int,
                                                          const QVariantMap &, QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result generateKey(const Key &, const KeyPairGenerationParameters &,
                                         const KeyDerivationParameters &, const QVariantMap &,
                                         Key *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result generateAndStoreKey(const Key &, const KeyPairGenerationParameters &,
                                                 const KeyDerivationParameters &, const QVariantMap &,
                                                 Key *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result importKey(const QByteArray &, const QByteArray &,
                                       const QVariantMap &, Key *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result importAndStoreKey(const QByteArray &, const Key &,
                                               const QByteArray &, const QVariantMap &,
                                               Key *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result storedKey(const Key::Identifier &, Key::Components,
                                       const QVariantMap &, Key *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result storedKeyIdentifiers(const QString &, const QVariantMap &,
                                                  QVector<Key::Identifier> *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result calculateDigest(const QByteArray &, CryptoManager::SignaturePadding,
                                             CryptoManager::DigestFunction, const QVariantMap &,
                                             QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result sign(const QByteArray &, const Key &,
                                  CryptoManager::SignaturePadding, CryptoManager::DigestFunction,
                                  const QVariantMap &, QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result verify(const QByteArray &, const QByteArray &, const Key &,
                                    CryptoManager::SignaturePadding, CryptoManager::DigestFunction,
                                    const QVariantMap &,
                                    CryptoManager::VerificationStatus *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result encrypt(const QByteArray &, const QByteArray &, const Key &,
                                     CryptoManager::BlockMode, CryptoManager::EncryptionPadding,
                                     const QByteArray &, const QVariantMap &, QByteArray *,
                                     QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result decrypt(const QByteArray &, const QByteArray &, const Key &,
                                     CryptoManager::BlockMode, CryptoManager::EncryptionPadding,
                                     const QByteArray &, const QByteArray &, const QVariantMap &,
                                     QByteArray *, CryptoManager::VerificationStatus *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result initializeCipherSession(quint64, const QByteArray &, const Key &,
                                                     CryptoManager::Operation, CryptoManager::BlockMode,
                                                     CryptoManager::EncryptionPadding,
                                                     CryptoManager::SignaturePadding,
                                                     CryptoManager::DigestFunction,
                                                     const QVariantMap &, quint32 *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result updateCipherSessionAuthentication(quint64, const QByteArray &,
                                                              const QVariantMap &, quint32) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result updateCipherSession(quint64, const QByteArray &,
                                                 const QVariantMap &, quint32,
                                                 QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result finalizeCipherSession(quint64, const QByteArray &,
                                                   const QVariantMap &, quint32, QByteArray *,
                                                   CryptoManager::VerificationStatus *) Q_DECL_OVERRIDE;

    Sailfish::Crypto::Result beginCreateMasterKey(const QByteArray &, quint32, quint64,
                                                  const QByteArray &, quint64 *,
                                                  QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result finishCreateMasterKey(const QByteArray &, const QByteArray &,
                                                   QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result beginOpenMasterKey(const QByteArray &, quint64 *,
                                                QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result finishOpenMasterKey(const QByteArray &, const QByteArray &,
                                                 QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result keyMintOneShot(quint32, const QByteArray &, qint32 *,
                                           QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result keyMintBegin(const QByteArray &, qint32 *, quint64 *,
                                         QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result keyMintUpdate(quint64, const QByteArray &, qint32 *,
                                          QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result keyMintFinish(quint64, const QByteArray &, qint32 *,
                                          QByteArray *) Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result keyMintAbort(quint64, qint32 *) Q_DECL_OVERRIDE;
};

} // namespace Plugins
} // namespace Daemon
} // namespace Crypto
} // namespace Sailfish

#endif // SAILFISHCRYPTO_PLUGIN_KEYMINT_H
