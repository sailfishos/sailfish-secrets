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
#include "Crypto/extensionplugins.h"
#include "Crypto/storedkeyrequest.h"

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

class CryptoManagerPrivate
{
public:
    CryptoManagerPrivate(CryptoManager *parent = Q_NULLPTR);
    ~CryptoManagerPrivate();

    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::CryptoPluginInfo>, QStringList> getPluginInfo();

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

    QDBusPendingReply<Sailfish::Crypto::Result, bool> validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> generateStoredKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const QString &cryptosystemProviderName,
            const QString &storageProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, Sailfish::Crypto::Key> storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            StoredKeyRequest::KeyComponents keyComponents);

    QDBusPendingReply<Sailfish::Crypto::Result> deleteStoredKey(
            const Sailfish::Crypto::Key::Identifier &identifier);

    QDBusPendingReply<Sailfish::Crypto::Result, QVector<Sailfish::Crypto::Key::Identifier> > storedKeyIdentifiers();

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, bool> verify(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            const QString &cryptosystemProviderName);

    QDBusPendingReply<Sailfish::Crypto::Result, QByteArray> decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key, // or keyreference, i.e. Key(keyName)
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            const QString &cryptosystemProviderName);

    // do we also need "continueEncrypt(data, ...)" etc?  Do we need "cipher sessions"?  what about denial of service / resource exhaustion etc?

private:
    friend class CryptoManager;
    Sailfish::Crypto::CryptoManager *m_parent;
    Sailfish::Crypto::CryptoDaemonConnection *m_crypto;
    QDBusInterface *m_interface;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_CRYPTOMANAGER_P_H
