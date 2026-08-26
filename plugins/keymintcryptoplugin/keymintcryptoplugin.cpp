/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "keymintcryptoplugin.h"
#include "keymintbinderclient_p.h"

using namespace Sailfish::Crypto;
using namespace Sailfish::Crypto::Daemon::Plugins;

namespace {

Result notSupported()
{
    return Result(Result::OperationNotSupportedError,
                  QStringLiteral("Operation is not exposed by the KeyMint plugin"));
}

Result masterKeyResult(const KeyMintBinderClient::CallResult &result,
                       Result::ErrorCode keyMintError)
{
    if (result.succeeded()) {
        return Result(Result::Succeeded);
    }
    if (!result.transportSucceeded) {
        return Result(result.keyMintError == -68
                      ? Result::CryptoManagerNotInitializedError
                      : Result::DaemonError,
                      result.errorMessage);
    }
    return Result(keyMintError, result.errorMessage);
}

Result keyMintResult(const KeyMintBinderClient::CallResult &result,
                     qint32 *keyMintError)
{
    if (keyMintError) {
        *keyMintError = result.keyMintError;
    }
    if (result.transportSucceeded) {
        return Result(Result::Succeeded);
    }
    return Result(result.keyMintError == -68
                  ? Result::CryptoManagerNotInitializedError
                  : Result::DaemonError,
                  result.errorMessage);
}

} // namespace

KeyMintCryptoPlugin::KeyMintCryptoPlugin(QObject *parent)
    : QObject(parent)
    , m_client(new KeyMintBinderClient)
{
}

KeyMintCryptoPlugin::~KeyMintCryptoPlugin()
{
    delete m_client;
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
Result KeyMintCryptoPlugin::beginCreateMasterKey(
        const QByteArray &rootKey,
        quint32 sailfishUserId,
        quint64 secureUserId,
        const QByteArray &identityEpoch,
        quint64 *challenge,
        QByteArray *operationContext)
{
    return masterKeyResult(m_client->beginCreateMasterKey(
                               rootKey, sailfishUserId, secureUserId,
                               identityEpoch, challenge, operationContext),
                           Result::CryptoPluginKeyGenerationError);
}

Result KeyMintCryptoPlugin::finishCreateMasterKey(
        const QByteArray &operationContext,
        const QByteArray &serializedHardwareAuthToken,
        QByteArray *serializedEnvelope)
{
    return masterKeyResult(m_client->finishCreateMasterKey(
                               operationContext, serializedHardwareAuthToken,
                               serializedEnvelope),
                           Result::CryptoPluginKeyGenerationError);
}

Result KeyMintCryptoPlugin::beginOpenMasterKey(
        const QByteArray &serializedEnvelope,
        quint64 *challenge,
        QByteArray *operationContext)
{
    return masterKeyResult(m_client->beginOpenMasterKey(
                               serializedEnvelope, challenge, operationContext),
                           Result::CryptoPluginDecryptionError);
}

Result KeyMintCryptoPlugin::finishOpenMasterKey(
        const QByteArray &operationContext,
        const QByteArray &serializedHardwareAuthToken,
        QByteArray *rootKey)
{
    return masterKeyResult(m_client->finishOpenMasterKey(
                               operationContext, serializedHardwareAuthToken,
                               rootKey),
                           Result::CryptoPluginDecryptionError);
}

Result KeyMintCryptoPlugin::keyMintOneShot(
        quint32 operation,
        const QByteArray &request,
        qint32 *keyMintError,
        QByteArray *response)
{
    return keyMintResult(m_client->oneShot(operation, request, response),
                         keyMintError);
}

Result KeyMintCryptoPlugin::keyMintBegin(
        const QByteArray &request,
        qint32 *keyMintError,
        quint64 *operationHandle,
        QByteArray *response)
{
    return keyMintResult(m_client->begin(request, operationHandle, response),
                         keyMintError);
}

Result KeyMintCryptoPlugin::keyMintUpdate(
        quint64 operationHandle,
        const QByteArray &request,
        qint32 *keyMintError,
        QByteArray *response)
{
    return keyMintResult(m_client->update(operationHandle, request, response),
                         keyMintError);
}

Result KeyMintCryptoPlugin::keyMintFinish(
        quint64 operationHandle,
        const QByteArray &request,
        qint32 *keyMintError,
        QByteArray *response)
{
    return keyMintResult(m_client->finish(operationHandle, request, response),
                         keyMintError);
}

Result KeyMintCryptoPlugin::keyMintAbort(
        quint64 operationHandle,
        qint32 *keyMintError)
{
    return keyMintResult(m_client->abort(operationHandle), keyMintError);
}

Result KeyMintCryptoPlugin::keyMintDeviceLocked(
        bool passwordOnly,
        qint32 *keyMintError)
{
    return keyMintResult(m_client->deviceLocked(passwordOnly), keyMintError);
}
