/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "keymintcryptoplugin.h"

using namespace Sailfish::Crypto;
using namespace Sailfish::Crypto::Daemon::Plugins;

namespace {

Result notSupported()
{
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("Physical AIDL KeyMint transport is unavailable"));
}

} // namespace

KeyMintCryptoPlugin::KeyMintCryptoPlugin(QObject *parent)
    : QObject(parent)
{
}

KeyMintCryptoPlugin::~KeyMintCryptoPlugin()
{
}

QString KeyMintCryptoPlugin::displayName() const
{
    return QStringLiteral("Android KeyMint");
}

QString KeyMintCryptoPlugin::name() const
{
    return QStringLiteral("org.sailfishos.crypto.plugin.crypto.keymint");
}

int KeyMintCryptoPlugin::version() const
{
    return 1;
}

bool KeyMintCryptoPlugin::canStoreKeys() const
{
    // Opaque KeyMint blobs are stored by the encrypted Secrets database.
    return false;
}

CryptoPlugin::EncryptionType KeyMintCryptoPlugin::encryptionType() const
{
    // The jp2601 FakeKeyMintDevice truthfully reports SOFTWARE.
    return CryptoPlugin::SoftwareEncryption;
}

Result KeyMintCryptoPlugin::generateRandomData(quint64, const QString &, quint64,
                                               const QVariantMap &, QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::seedRandomDataGenerator(quint64, const QString &, const QByteArray &,
                                                    double, const QVariantMap &) { return notSupported(); }
Result KeyMintCryptoPlugin::generateInitializationVector(CryptoManager::Algorithm,
                                                         CryptoManager::BlockMode, int,
                                                         const QVariantMap &, QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::generateKey(const Key &, const KeyPairGenerationParameters &,
                                        const KeyDerivationParameters &, const QVariantMap &,
                                        Key *) { return notSupported(); }
Result KeyMintCryptoPlugin::generateAndStoreKey(const Key &, const KeyPairGenerationParameters &,
                                                const KeyDerivationParameters &, const QVariantMap &,
                                                Key *) { return notSupported(); }
Result KeyMintCryptoPlugin::importKey(const QByteArray &, const QByteArray &,
                                      const QVariantMap &, Key *) { return notSupported(); }
Result KeyMintCryptoPlugin::importAndStoreKey(const QByteArray &, const Key &, const QByteArray &,
                                              const QVariantMap &, Key *) { return notSupported(); }
Result KeyMintCryptoPlugin::storedKey(const Key::Identifier &, Key::Components,
                                      const QVariantMap &, Key *) { return notSupported(); }
Result KeyMintCryptoPlugin::storedKeyIdentifiers(const QString &, const QVariantMap &,
                                                 QVector<Key::Identifier> *) { return notSupported(); }
Result KeyMintCryptoPlugin::calculateDigest(const QByteArray &, CryptoManager::SignaturePadding,
                                            CryptoManager::DigestFunction, const QVariantMap &,
                                            QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::sign(const QByteArray &, const Key &, CryptoManager::SignaturePadding,
                                 CryptoManager::DigestFunction, const QVariantMap &,
                                 QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::verify(const QByteArray &, const QByteArray &, const Key &,
                                   CryptoManager::SignaturePadding, CryptoManager::DigestFunction,
                                   const QVariantMap &, CryptoManager::VerificationStatus *) { return notSupported(); }
Result KeyMintCryptoPlugin::encrypt(const QByteArray &, const QByteArray &, const Key &,
                                    CryptoManager::BlockMode, CryptoManager::EncryptionPadding,
                                    const QByteArray &, const QVariantMap &, QByteArray *,
                                    QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::decrypt(const QByteArray &, const QByteArray &, const Key &,
                                    CryptoManager::BlockMode, CryptoManager::EncryptionPadding,
                                    const QByteArray &, const QByteArray &, const QVariantMap &,
                                    QByteArray *, CryptoManager::VerificationStatus *) { return notSupported(); }
Result KeyMintCryptoPlugin::initializeCipherSession(quint64, const QByteArray &, const Key &,
                                                    CryptoManager::Operation, CryptoManager::BlockMode,
                                                    CryptoManager::EncryptionPadding,
                                                    CryptoManager::SignaturePadding,
                                                    CryptoManager::DigestFunction,
                                                    const QVariantMap &, quint32 *) { return notSupported(); }
Result KeyMintCryptoPlugin::updateCipherSessionAuthentication(quint64, const QByteArray &,
                                                             const QVariantMap &, quint32) { return notSupported(); }
Result KeyMintCryptoPlugin::updateCipherSession(quint64, const QByteArray &,
                                                const QVariantMap &, quint32,
                                                QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::finalizeCipherSession(quint64, const QByteArray &,
                                                  const QVariantMap &, quint32, QByteArray *,
                                                  CryptoManager::VerificationStatus *) { return notSupported(); }
Result KeyMintCryptoPlugin::beginCreateMasterKey(const QByteArray &, quint32, quint64,
                                                 const QByteArray &, quint64 *,
                                                 QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::finishCreateMasterKey(const QByteArray &, const QByteArray &,
                                                  QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::beginOpenMasterKey(const QByteArray &, quint64 *,
                                               QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::finishOpenMasterKey(const QByteArray &, const QByteArray &,
                                                QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::keyMintOneShot(quint32, const QByteArray &, qint32 *,
                                          QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::keyMintBegin(const QByteArray &, qint32 *, quint64 *,
                                        QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::keyMintUpdate(quint64, const QByteArray &, qint32 *,
                                         QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::keyMintFinish(quint64, const QByteArray &, qint32 *,
                                         QByteArray *) { return notSupported(); }
Result KeyMintCryptoPlugin::keyMintAbort(quint64, qint32 *) { return notSupported(); }
