/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "crypto_p.h"
#include "cryptorequestprocessor_p.h"
#include "logging_p.h"

#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/result.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/cryptodaemonconnection.h"

#include <QtCore/QString>
#include <QtCore/QVector>
#include <QtCore/QByteArray>

Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::CryptoDBusObject(
        Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *parent)
    : QObject(parent)
    , m_requestQueue(parent)
{
}


void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::getPluginInfo(
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QVector<Sailfish::Crypto::CryptoPluginInfo> &cryptoPlugins,
        QStringList &storagePlugins)
{
    Q_UNUSED(cryptoPlugins);   // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(storagePlugins);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::GetPluginInfoRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::validateCertificateChain(
        const QVector<Sailfish::Crypto::Certificate> &chain,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        bool &valid)
{
    Q_UNUSED(valid);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QVector<Sailfish::Crypto::Certificate> >(chain);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::ValidateCertificateChainRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::generateKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        Sailfish::Crypto::Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::GenerateKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::generateStoredKey(
        const Sailfish::Crypto::Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        Sailfish::Crypto::Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Crypto::Key>(keyTemplate);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<QString>(storageProviderName);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::GenerateStoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::storedKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        Sailfish::Crypto::Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::Identifier>(identifier);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::StoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::deleteStoredKey(
        const Sailfish::Crypto::Key::Identifier &identifier,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::Identifier>(identifier);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::DeleteStoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::storedKeyIdentifiers(
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QVector<Sailfish::Crypto::Key::Identifier> &identifiers)
{
    Q_UNUSED(identifiers);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::StoredKeyIdentifiersRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::sign(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &signature)
{
    Q_UNUSED(signature);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key>(key);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::SignaturePadding>(padding);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::SignRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::verify(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::SignaturePadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        bool &verified)
{
    Q_UNUSED(verified);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key>(key);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::SignaturePadding>(padding);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::VerifyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::encrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &encrypted)
{
    Q_UNUSED(encrypted);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key>(key);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::BlockMode>(blockMode);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::EncryptionPadding>(padding);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::EncryptRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject::decrypt(
        const QByteArray &data,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding padding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &decrypted)
{
    Q_UNUSED(decrypted);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key>(key);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::BlockMode>(blockMode);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::EncryptionPadding>(padding);
    inParams << QVariant::fromValue<Sailfish::Crypto::Key::Digest>(digest);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Sailfish::Crypto::Daemon::ApiImpl::DecryptRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

//-----------------------------------

Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue::CryptoRequestQueue(
        Sailfish::Secrets::Daemon::Controller *parent,
        Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets,
        const QString &pluginDir,
        bool autotestMode)
    : Sailfish::Secrets::Daemon::ApiImpl::RequestQueue(
          QLatin1String("/Sailfish/Crypto"),
          QLatin1String("org.sailfishos.crypto"),
          parent,
          pluginDir,
          autotestMode)
{
    Sailfish::Crypto::CryptoDaemonConnection::registerDBusTypes();

    m_requestProcessor = new Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor(secrets, this);
    if (!m_requestProcessor->loadPlugins(pluginDir, autotestMode)) {
        qCWarning(lcSailfishCryptoDaemon) << "Crypto: failed to load plugins!";
        return;
    }

    setDBusObject(new Sailfish::Crypto::Daemon::ApiImpl::CryptoDBusObject(this));
    qCDebug(lcSailfishCryptoDaemon) << "Crypto: initialisation succeeded, awaiting client connections.";
}

Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue::~CryptoRequestQueue()
{
}

QString Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue::requestTypeToString(int type) const
{
    switch (type) {
        case InvalidRequest:                   return QLatin1String("InvalidRequest");
        case GetPluginInfoRequest:             return QLatin1String("GetPluginInfoRequest");
        case ValidateCertificateChainRequest:  return QLatin1String("ValidateCertificateChainRequest");
        case GenerateKeyRequest:               return QLatin1String("GenerateKeyRequest");
        case GenerateStoredKeyRequest:         return QLatin1String("GenerateStoredKeyRequest");
        case StoredKeyRequest:                 return QLatin1String("StoredKeyRequest");
        case DeleteStoredKeyRequest:           return QLatin1String("DeleteStoredKeyRequest");
        case StoredKeyIdentifiersRequest:      return QLatin1String("StoredKeyIdentifiersRequest");
        case SignRequest:                      return QLatin1String("SignRequest");
        case VerifyRequest:                    return QLatin1String("VerifyRequest");
        case EncryptRequest:                   return QLatin1String("EncryptRequest");
        case DecryptRequest:                   return QLatin1String("DecryptRequest");
        default: break;
    }
    return QLatin1String("Unknown Crypto Request!");
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue::handlePendingRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GetPluginInfoRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<Sailfish::Crypto::CryptoPluginInfo> cryptoPlugins;
            QStringList storagePlugins;
            Sailfish::Crypto::Result result = m_requestProcessor->getPluginInfo(
                        request->remotePid,
                        request->requestId,
                        &cryptoPlugins,
                        &storagePlugins);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QVector<Sailfish::Crypto::CryptoPluginInfo> >(cryptoPlugins)
                                                                        << QVariant::fromValue<QStringList>(storagePlugins));
                *completed = true;
            }
            break;
        }
        case ValidateCertificateChainRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling ValidateCertificateChainRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            bool validated = false;
            QVector<Sailfish::Crypto::Certificate> chain = request->inParams.size() ? request->inParams.takeFirst().value<QVector<Sailfish::Crypto::Certificate> >() : QVector<Sailfish::Crypto::Certificate>();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->validateCertificateChain(
                        request->remotePid,
                        request->requestId,
                        chain,
                        cryptosystemProviderName,
                        &validated);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<bool>(validated));
                *completed = true;
            }
            break;
        }
        case GenerateKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Crypto::Key key;
            Sailfish::Crypto::Key templateKey = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key>() : Sailfish::Crypto::Key();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->generateKey(
                        request->remotePid,
                        request->requestId,
                        templateKey,
                        cryptosystemProviderName,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<Sailfish::Crypto::Key>(key));
                *completed = true;
            }
            break;
        }
        case GenerateStoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateStoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Crypto::Key key;
            Sailfish::Crypto::Key templateKey = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key>() : Sailfish::Crypto::Key();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString storageProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->generateStoredKey(
                        request->remotePid,
                        request->requestId,
                        templateKey,
                        cryptosystemProviderName,
                        storageProviderName,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<Sailfish::Crypto::Key>(key));
                *completed = true;
            }
            break;
        }
        case StoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling StoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Sailfish::Crypto::Key key;
            QString name = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->storedKey(
                        request->remotePid,
                        request->requestId,
                        name,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<Sailfish::Crypto::Key>(key));
                *completed = true;
            }
            break;
        }
        case DeleteStoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling DeleteStoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QString name = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->deleteStoredKey(
                        request->remotePid,
                        request->requestId,
                        name);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result));
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling StoredKeyIdentifiersRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<Sailfish::Crypto::Key::Identifier> identifiers;
            Sailfish::Crypto::Result result = m_requestProcessor->storedKeyIdentifiers(
                        request->remotePid,
                        request->requestId,
                        &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QVector<Sailfish::Crypto::Key::Identifier> >(identifiers));
                *completed = true;
            }
            break;
        }
        case SignRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling SignRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray signature;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Sailfish::Crypto::Key key = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key>() : Sailfish::Crypto::Key();
            Sailfish::Crypto::Key::SignaturePadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::SignaturePadding>() : Sailfish::Crypto::Key::SignaturePaddingUnknown;
            Sailfish::Crypto::Key::Digest digest = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::Digest>() : Sailfish::Crypto::Key::DigestUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->sign(
                        request->remotePid,
                        request->requestId,
                        data,
                        key,
                        padding,
                        digest,
                        cryptosystemProviderName,
                        &signature);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(signature));
                *completed = true;
            }
            break;
        }
        case VerifyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling VerifyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            bool verified;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Sailfish::Crypto::Key key = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key>() : Sailfish::Crypto::Key();
            Sailfish::Crypto::Key::SignaturePadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::SignaturePadding>() : Sailfish::Crypto::Key::SignaturePaddingUnknown;
            Sailfish::Crypto::Key::Digest digest = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::Digest>() : Sailfish::Crypto::Key::DigestUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->verify(
                        request->remotePid,
                        request->requestId,
                        data,
                        key,
                        padding,
                        digest,
                        cryptosystemProviderName,
                        &verified);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case EncryptRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling EncryptRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray encrypted;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Sailfish::Crypto::Key key = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key>() : Sailfish::Crypto::Key();
            Sailfish::Crypto::Key::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::BlockMode>() : Sailfish::Crypto::Key::BlockModeUnknown;
            Sailfish::Crypto::Key::EncryptionPadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::EncryptionPadding>() : Sailfish::Crypto::Key::EncryptionPaddingUnknown;
            Sailfish::Crypto::Key::Digest digest = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::Digest>() : Sailfish::Crypto::Key::DigestUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->encrypt(
                        request->remotePid,
                        request->requestId,
                        data,
                        key,
                        blockMode,
                        padding,
                        digest,
                        cryptosystemProviderName,
                        &encrypted);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(encrypted));
                *completed = true;
            }
            break;
        }
        case DecryptRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling DecryptRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray decrypted;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Sailfish::Crypto::Key key = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key>() : Sailfish::Crypto::Key();
            Sailfish::Crypto::Key::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::BlockMode>() : Sailfish::Crypto::Key::BlockModeUnknown;
            Sailfish::Crypto::Key::EncryptionPadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::EncryptionPadding>() : Sailfish::Crypto::Key::EncryptionPaddingUnknown;
            Sailfish::Crypto::Key::Digest digest = request->inParams.size() ? request->inParams.takeFirst().value<Sailfish::Crypto::Key::Digest>() : Sailfish::Crypto::Key::DigestUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Sailfish::Crypto::Result result = m_requestProcessor->decrypt(
                        request->remotePid,
                        request->requestId,
                        data,
                        key,
                        blockMode,
                        padding,
                        digest,
                        cryptosystemProviderName,
                        &decrypted);
            // send the reply to the calling peer.
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(decrypted));
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishCryptoDaemon) << "Cannot handle request:" << request->requestId
                                               << "with invalid type:" << requestTypeToString(request->type);
            *completed = false;
            break;
        }
    }
}

void Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue::handleFinishedRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of GetPluginInfoRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GetPluginInfoRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<Sailfish::Crypto::CryptoPluginInfo> cryptoPlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<Sailfish::Crypto::CryptoPluginInfo> >()
                        : QVector<Sailfish::Crypto::CryptoPluginInfo>();
                QStringList storagePlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QStringList>()
                        : QStringList();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QVector<Sailfish::Crypto::CryptoPluginInfo> >(cryptoPlugins)
                                                                        << QVariant::fromValue<QStringList>(storagePlugins));
                *completed = true;
            }
            break;
        }
        case ValidateCertificateChainRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of ValidateCertificateChainRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "ValidateCertificateChainRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                bool validated = request->outParams.size() ? request->outParams.takeFirst().value<bool>() : false;
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<bool>(validated));
                *completed = true;
            }
            break;
        }
        case GenerateKeyRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of GenerateKeyRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Sailfish::Crypto::Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Sailfish::Crypto::Key>()
                        : Sailfish::Crypto::Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<Sailfish::Crypto::Key>(key));
                *completed = true;
            }
            break;
        }
        case GenerateStoredKeyRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of GenerateStoredKeyRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateStoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Sailfish::Crypto::Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Sailfish::Crypto::Key>()
                        : Sailfish::Crypto::Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<Sailfish::Crypto::Key>(key));
                *completed = true;
            }
            break;
        }
        case StoredKeyRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of StoredKeyRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "StoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Sailfish::Crypto::Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Sailfish::Crypto::Key>()
                        : Sailfish::Crypto::Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<Sailfish::Crypto::Key>(key));
                *completed = true;
            }
            break;
        }
        case DeleteStoredKeyRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of DeleteStoredKeyRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "DeleteStoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result));
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of StoredKeyIdentifiersRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "StoredKeyIdentifiersRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<Sailfish::Crypto::Key::Identifier> identifiers = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<Sailfish::Crypto::Key::Identifier> >()
                        : QVector<Sailfish::Crypto::Key::Identifier>();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QVector<Sailfish::Crypto::Key::Identifier> >(identifiers));
                *completed = true;
            }
            break;
        }
        case SignRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of SignRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "SignRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray signature = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(signature));
                *completed = true;
            }
            break;
        }
        case VerifyRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of VerifyRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "VerifyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                bool verified = request->outParams.size()
                        ? request->outParams.takeFirst().toBool()
                        : false;
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case EncryptRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of EncryptRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "EncryptRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray encrypted = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(encrypted));
                *completed = true;
            }
            break;
        }
        case DecryptRequest: {
            Sailfish::Crypto::Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Sailfish::Crypto::Result>()
                    : Sailfish::Crypto::Result(Sailfish::Crypto::Result::UnknownError,
                                                QLatin1String("Unable to determine result of DecryptRequest request"));
            if (result.code() == Sailfish::Crypto::Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "DecryptRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray decrypted = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Sailfish::Crypto::Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(decrypted));
                *completed = true;
            }
            break;
        }
        default: {
            qCWarning(lcSailfishCryptoDaemon) << "Cannot handle synchronous request:" << request->requestId << "with type:" << requestTypeToString(request->type) << "in an asynchronous fashion";
            *completed = false;
            break;
        }
    }
}
