/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CRYPTOMANAGER_P_H
#define LIBSAILFISHCRYPTO_CRYPTOMANAGER_P_H

#include "Crypto/cryptomanager.h"

#include "Crypto/cryptodaemonconnection_p.h"
#include "Crypto/result.h"
#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/plugininfo.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/interactionparameters.h"
#include "Crypto/lockcoderequest.h"

#include <QtDBus/QDBusContext>
#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusMetaType>
#include <QtDBus/QDBusArgument>

#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QVector>

#include <QtDBus/QDBusInterface>

namespace Sailfish {

namespace Crypto {

// not actually part of the public API, but exporting symbols for unit tests.
class SAILFISH_CRYPTO_API CryptoManagerPrivate
{
public:
    CryptoManagerPrivate(CryptoManager *parent = Q_NULLPTR);
    ~CryptoManagerPrivate();

    QDBusPendingReply<Sailfish::Crypto::Result,
                      QVector<Sailfish::Crypto::PluginInfo>,
                      QVector<Sailfish::Crypto::PluginInfo> > getPluginInfo();

    QDBusPendingReply<Sailfish::Crypto::Result> seedRandomDataGenerator(
            const QByteArray &seedData,
            double entropyEstimate,
            const QString &csprngEngineName,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> generateRandomData(
            quint64 numberBytes,
            const QString &csprngEngineName,
            const QString &cryptosystemProviderName);

    // TODO: add a method (and corresponding Request type) to generateRandomNumber
    // perhaps with range limits, precision parameters, etc.

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> generateInitializationVector(
            Sailfish::Crypto::CryptoManager::Algorithm algorithm,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            int keySize,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, bool> validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &pkgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> generateStoredKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &pkgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const Sailfish::Crypto::InteractionParameters &uiParams,
            const QString &cryptosystemProviderName,
            const QString &storageProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> importKey(
            const Sailfish::Crypto::Key &key,
            const Sailfish::Crypto::InteractionParameters &uiParams,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> importStoredKey(
            const Sailfish::Crypto::Key &key,
            const Sailfish::Crypto::InteractionParameters &uiParams,
            const QString &cryptosystemProviderName,
            const QString &storageProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Key::Components keyComponents);

    QDBusPendingReply<Sailfish::Crypto::Result> deleteStoredKey(
            const Sailfish::Crypto::Key::Identifier &identifier);

    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::Key::Identifier> > storedKeyIdentifiers();

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> calculateDigest(
            const QByteArray &data,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, bool> verify(
            const QByteArray &signature,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, QByteArray> encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Result, QByteArray, bool> decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Key &key, // or keyreference, i.e. Key(keyName)
            CryptoManager::BlockMode blockMode,
            CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QByteArray &authenticationTag,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Result, quint32> initialiseCipherSession(
            const QByteArray &initialisationVector,
            const Sailfish::Crypto::Key &key, // or keyreference
            const Sailfish::Crypto::CryptoManager::Operation operation,
            const Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            const Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            const Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            const Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result> updateCipherSessionAuthentication(
            const QByteArray &authenticationData,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken);

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> updateCipherSession(
            const QByteArray &data,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken);

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray, bool> finaliseCipherSession(
            const QByteArray &data,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken);

    QDBusPendingReply<Sailfish::Crypto::Result> modifyLockCode(
            Sailfish::Crypto::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Crypto::InteractionParameters &interactionParameters);

    QDBusPendingReply<Sailfish::Crypto::Result> provideLockCode(
            Sailfish::Crypto::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Crypto::InteractionParameters &interactionParameters);

    QDBusPendingReply<Sailfish::Crypto::Result> forgetLockCode(
            Sailfish::Crypto::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Crypto::InteractionParameters &interactionParameters);

private:
    friend class CryptoManager;
    Sailfish::Crypto::CryptoManager *m_parent;
    Sailfish::Crypto::CryptoDaemonConnection *m_crypto;
    QDBusInterface *m_interface;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_CRYPTOMANAGER_P_H
