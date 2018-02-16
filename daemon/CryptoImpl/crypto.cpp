/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "crypto_p.h"
#include "cryptorequestprocessor_p.h"
#include "logging_p.h"

#include "Crypto/serialisation_p.h"
#include "Crypto/cryptodaemonconnection_p.h"

#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/result.h"
#include "Crypto/cryptomanager.h"

#include <QtCore/QString>
#include <QtCore/QVector>
#include <QtCore/QByteArray>

using namespace Sailfish::Crypto;

Daemon::ApiImpl::CryptoDBusObject::CryptoDBusObject(
        Daemon::ApiImpl::CryptoRequestQueue *parent)
    : QObject(parent)
    , m_requestQueue(parent)
{
}


void Daemon::ApiImpl::CryptoDBusObject::getPluginInfo(
        const QDBusMessage &message,
        Result &result,
        QVector<CryptoPluginInfo> &cryptoPlugins,
        QStringList &storagePlugins)
{
    Q_UNUSED(cryptoPlugins);   // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(storagePlugins);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Daemon::ApiImpl::GetPluginInfoRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::generateRandomData(
        quint64 numberBytes,
        const QString &csprngEngineName,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &randomData)
{
    Q_UNUSED(randomData);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<quint64>(numberBytes);
    inParams << QVariant::fromValue<QString>(csprngEngineName);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::GenerateRandomDataRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::seedRandomDataGenerator(
        const QByteArray &seedData,
        double entropyEstimate,
        const QString &csprngEngineName,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(seedData);
    inParams << QVariant::fromValue<double>(entropyEstimate);
    inParams << QVariant::fromValue<QString>(csprngEngineName);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SeedRandomDataGeneratorRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::validateCertificateChain(
        const QVector<Certificate> &chain,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        bool &valid)
{
    Q_UNUSED(valid);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QVector<Certificate> >(chain);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::ValidateCertificateChainRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::generateKey(
        const Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key>(keyTemplate);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::GenerateKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::generateStoredKey(
        const Key &keyTemplate,
        const QString &cryptosystemProviderName,
        const QString &storageProviderName,
        const QDBusMessage &message,
        Result &result,
        Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key>(keyTemplate);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<QString>(storageProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::GenerateStoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::storedKey(
        const Key::Identifier &identifier,
        StoredKeyRequest::KeyComponents keyComponents,
        const QDBusMessage &message,
        Result &result,
        Key &key)
{
    Q_UNUSED(key);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key::Identifier>(identifier);
    inParams << QVariant::fromValue<StoredKeyRequest::KeyComponents>(keyComponents);
    m_requestQueue->handleRequest(Daemon::ApiImpl::StoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::deleteStoredKey(
        const Key::Identifier &identifier,
        const QDBusMessage &message,
        Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<Key::Identifier>(identifier);
    m_requestQueue->handleRequest(Daemon::ApiImpl::DeleteStoredKeyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::storedKeyIdentifiers(
        const QDBusMessage &message,
        Result &result,
        QVector<Key::Identifier> &identifiers)
{
    Q_UNUSED(identifiers);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    m_requestQueue->handleRequest(Daemon::ApiImpl::StoredKeyIdentifiersRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::sign(
        const QByteArray &data,
        const Key &key,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &signature)
{
    Q_UNUSED(signature);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<Key::SignaturePadding>(padding);
    inParams << QVariant::fromValue<Key::Digest>(digest);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::SignRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::verify(
        const QByteArray &data,
        const Key &key,
        Key::SignaturePadding padding,
        Key::Digest digest,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        bool &verified)
{
    Q_UNUSED(verified);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<Key::SignaturePadding>(padding);
    inParams << QVariant::fromValue<Key::Digest>(digest);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::VerifyRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::encrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &encrypted)
{
    Q_UNUSED(encrypted);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QByteArray>(iv);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<Key::BlockMode>(blockMode);
    inParams << QVariant::fromValue<Key::EncryptionPadding>(padding);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::EncryptRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::decrypt(
        const QByteArray &data,
        const QByteArray &iv,
        const Key &key,
        Key::BlockMode blockMode,
        Key::EncryptionPadding padding,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Result &result,
        QByteArray &decrypted)
{
    Q_UNUSED(decrypted);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QByteArray>(iv);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<Key::BlockMode>(blockMode);
    inParams << QVariant::fromValue<Key::EncryptionPadding>(padding);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::DecryptRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::initialiseCipherSession(
        const QByteArray &initialisationVector,
        const Sailfish::Crypto::Key &key,
        Sailfish::Crypto::Key::Operation operation,
        Sailfish::Crypto::Key::BlockMode blockMode,
        Sailfish::Crypto::Key::EncryptionPadding encryptionPadding,
        Sailfish::Crypto::Key::SignaturePadding signaturePadding,
        Sailfish::Crypto::Key::Digest digest,
        const QString &cryptosystemProviderName,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        quint32 &cipherSessionToken,
        QByteArray &generatedInitialisationVector)
{
    Q_UNUSED(cipherSessionToken);  // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(generatedInitialisationVector); // outparam
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(initialisationVector);
    inParams << QVariant::fromValue<Key>(key);
    inParams << QVariant::fromValue<Key::Operation>(operation);
    inParams << QVariant::fromValue<Key::BlockMode>(blockMode);
    inParams << QVariant::fromValue<Key::EncryptionPadding>(encryptionPadding);
    inParams << QVariant::fromValue<Key::SignaturePadding>(signaturePadding);
    inParams << QVariant::fromValue<Key::Digest>(digest);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    m_requestQueue->handleRequest(Daemon::ApiImpl::InitialiseCipherSessionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::updateCipherSessionAuthentication(
        const QByteArray &authenticationData,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result)
{
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(authenticationData);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<quint32>(cipherSessionToken);
    m_requestQueue->handleRequest(Daemon::ApiImpl::UpdateCipherSessionAuthenticationRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::updateCipherSession(
        const QByteArray &data,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &generatedData)
{
    Q_UNUSED(generatedData);  // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<quint32>(cipherSessionToken);
    m_requestQueue->handleRequest(Daemon::ApiImpl::UpdateCipherSessionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

void Daemon::ApiImpl::CryptoDBusObject::finaliseCipherSession(
        const QByteArray &data,
        const QString &cryptosystemProviderName,
        quint32 cipherSessionToken,
        const QDBusMessage &message,
        Sailfish::Crypto::Result &result,
        QByteArray &generatedData,
        bool &verified)
{
    Q_UNUSED(generatedData);  // outparam, set in handlePendingRequest / handleFinishedRequest
    Q_UNUSED(verified);       // outparam, set in handlePendingRequest / handleFinishedRequest
    QList<QVariant> inParams;
    inParams << QVariant::fromValue<QByteArray>(data);
    inParams << QVariant::fromValue<QString>(cryptosystemProviderName);
    inParams << QVariant::fromValue<quint32>(cipherSessionToken);
    m_requestQueue->handleRequest(Daemon::ApiImpl::FinaliseCipherSessionRequest,
                                  inParams,
                                  connection(),
                                  message,
                                  result);
}

//-----------------------------------

Daemon::ApiImpl::CryptoRequestQueue::CryptoRequestQueue(
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
    CryptoDaemonConnection::registerDBusTypes();

    m_requestProcessor = new Daemon::ApiImpl::RequestProcessor(secrets, autotestMode, this);
    if (!m_requestProcessor->loadPlugins(pluginDir)) {
        qCWarning(lcSailfishCryptoDaemon) << "Crypto: failed to load plugins!";
        return;
    }

    setDBusObject(new Daemon::ApiImpl::CryptoDBusObject(this));
    qCDebug(lcSailfishCryptoDaemon) << "Crypto: initialisation succeeded, awaiting client connections.";
}

Daemon::ApiImpl::CryptoRequestQueue::~CryptoRequestQueue()
{
}

QString Daemon::ApiImpl::CryptoRequestQueue::requestTypeToString(int type) const
{
    switch (type) {
        case InvalidRequest:                   return QLatin1String("InvalidRequest");
        case GetPluginInfoRequest:             return QLatin1String("GetPluginInfoRequest");
        case GenerateRandomDataRequest:        return QLatin1String("GenerateRandomDataRequest");
        case SeedRandomDataGeneratorRequest:   return QLatin1String("SeedRandomDataGeneratorRequest");
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
        case InitialiseCipherSessionRequest:   return QLatin1String("InitialiseCipherSessionRequest");
        case UpdateCipherSessionAuthenticationRequest: return QLatin1String("UpdateCipherSessionAuthenticationRequest");
        case UpdateCipherSessionRequest:       return QLatin1String("UpdateCipherSessionRequest");
        case FinaliseCipherSessionRequest:     return QLatin1String("FinaliseCipherSessionRequest");
        default: break;
    }
    return QLatin1String("Unknown Crypto Request!");
}

void Daemon::ApiImpl::CryptoRequestQueue::handlePendingRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GetPluginInfoRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<CryptoPluginInfo> cryptoPlugins;
            QStringList storagePlugins;
            Result result = m_requestProcessor->getPluginInfo(
                        request->remotePid,
                        request->requestId,
                        &cryptoPlugins,
                        &storagePlugins);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<CryptoPluginInfo> >(cryptoPlugins)
                                                                        << QVariant::fromValue<QStringList>(storagePlugins));
                *completed = true;
            }
            break;
        }
        case GenerateRandomDataRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateRandomDataRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray randomData;
            quint64 numberBytes = request->inParams.size() ? request->inParams.takeFirst().value<quint64>() : 0;
            QString csprngEngineName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->generateRandomData(
                        request->remotePid,
                        request->requestId,
                        numberBytes,
                        csprngEngineName,
                        cryptosystemProviderName,
                        &randomData);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(randomData));
                *completed = true;
            }
            break;
        }
        case SeedRandomDataGeneratorRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling SeedRandomDataGeneratorRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray seedData = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            double entropyEstimate = request->inParams.size() ? request->inParams.takeFirst().value<double>() : 1.0;
            QString csprngEngineName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->seedRandomDataGenerator(
                        request->remotePid,
                        request->requestId,
                        seedData,
                        entropyEstimate,
                        csprngEngineName,
                        cryptosystemProviderName);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case ValidateCertificateChainRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling ValidateCertificateChainRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            bool validated = false;
            QVector<Certificate> chain = request->inParams.size() ? request->inParams.takeFirst().value<QVector<Certificate> >() : QVector<Certificate>();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->validateCertificateChain(
                        request->remotePid,
                        request->requestId,
                        chain,
                        cryptosystemProviderName,
                        &validated);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<bool>(validated));
                *completed = true;
            }
            break;
        }
        case GenerateKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key key;
            Key templateKey = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->generateKey(
                        request->remotePid,
                        request->requestId,
                        templateKey,
                        cryptosystemProviderName,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case GenerateStoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling GenerateStoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key key;
            Key templateKey = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            QString storageProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->generateStoredKey(
                        request->remotePid,
                        request->requestId,
                        templateKey,
                        cryptosystemProviderName,
                        storageProviderName,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case StoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling StoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key key;
            Key::Identifier ident = request->inParams.size()
                    ? request->inParams.takeFirst().value<Key::Identifier>()
                    : Key::Identifier();
            StoredKeyRequest::KeyComponents components = request->inParams.size()
                    ? request->inParams.takeFirst().value<StoredKeyRequest::KeyComponents>()
                    : (StoredKeyRequest::MetaData | StoredKeyRequest::PublicKeyData);
            Result result = m_requestProcessor->storedKey(
                        request->remotePid,
                        request->requestId,
                        ident,
                        components,
                        &key);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case DeleteStoredKeyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling DeleteStoredKeyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            Key::Identifier identifier = request->inParams.size()
                                                         ? request->inParams.takeFirst().value<Key::Identifier>()
                                                         : Key::Identifier();
            Result result = m_requestProcessor->deleteStoredKey(
                        request->remotePid,
                        request->requestId,
                        identifier);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling StoredKeyIdentifiersRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QVector<Key::Identifier> identifiers;
            Result result = m_requestProcessor->storedKeyIdentifiers(
                        request->remotePid,
                        request->requestId,
                        &identifiers);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<Key::Identifier> >(identifiers));
                *completed = true;
            }
            break;
        }
        case SignRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling SignRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray signature;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            Key::SignaturePadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Key::SignaturePadding>() : Key::SignaturePaddingUnknown;
            Key::Digest digest = request->inParams.size() ? request->inParams.takeFirst().value<Key::Digest>() : Key::DigestUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->sign(
                        request->remotePid,
                        request->requestId,
                        data,
                        key,
                        padding,
                        digest,
                        cryptosystemProviderName,
                        &signature);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(signature));
                *completed = true;
            }
            break;
        }
        case VerifyRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling VerifyRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            bool verified = false;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            Key::SignaturePadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Key::SignaturePadding>() : Key::SignaturePaddingUnknown;
            Key::Digest digest = request->inParams.size() ? request->inParams.takeFirst().value<Key::Digest>() : Key::DigestUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->verify(
                        request->remotePid,
                        request->requestId,
                        data,
                        key,
                        padding,
                        digest,
                        cryptosystemProviderName,
                        &verified);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case EncryptRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling EncryptRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray encrypted;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QByteArray iv = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            Key::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<Key::BlockMode>() : Key::BlockModeUnknown;
            Key::EncryptionPadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Key::EncryptionPadding>() : Key::EncryptionPaddingUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->encrypt(
                        request->remotePid,
                        request->requestId,
                        data,
                        iv,
                        key,
                        blockMode,
                        padding,
                        cryptosystemProviderName,
                        &encrypted);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(encrypted));
                *completed = true;
            }
            break;
        }
        case DecryptRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling DecryptRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray decrypted;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QByteArray iv = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            Key::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<Key::BlockMode>() : Key::BlockModeUnknown;
            Key::EncryptionPadding padding = request->inParams.size() ? request->inParams.takeFirst().value<Key::EncryptionPadding>() : Key::EncryptionPaddingUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->decrypt(
                        request->remotePid,
                        request->requestId,
                        data,
                        iv,
                        key,
                        blockMode,
                        padding,
                        cryptosystemProviderName,
                        &decrypted);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(decrypted));
                *completed = true;
            }
            break;
        }
        case InitialiseCipherSessionRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling InitialiseCipherSessionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray generatedIV;
            quint32 cipherSessionToken = 0;
            QByteArray iv = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            Key key = request->inParams.size() ? request->inParams.takeFirst().value<Key>() : Key();
            Key::Operation operation = request->inParams.size() ? request->inParams.takeFirst().value<Key::Operation>() : Key::OperationUnknown;
            Key::BlockMode blockMode = request->inParams.size() ? request->inParams.takeFirst().value<Key::BlockMode>() : Key::BlockModeUnknown;
            Key::EncryptionPadding encryptionPadding = request->inParams.size() ? request->inParams.takeFirst().value<Key::EncryptionPadding>() : Key::EncryptionPaddingUnknown;
            Key::SignaturePadding signaturePadding = request->inParams.size() ? request->inParams.takeFirst().value<Key::SignaturePadding>() : Key::SignaturePaddingUnknown;
            Key::Digest digest = request->inParams.size() ? request->inParams.takeFirst().value<Key::Digest>() : Key::DigestUnknown;
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            Result result = m_requestProcessor->initialiseCipherSession(
                        request->remotePid,
                        request->requestId,
                        iv,
                        key,
                        operation,
                        blockMode,
                        encryptionPadding,
                        signaturePadding,
                        digest,
                        cryptosystemProviderName,
                        &cipherSessionToken,
                        &generatedIV);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<quint32>(cipherSessionToken)
                                                                        << QVariant::fromValue<QByteArray>(generatedIV));
                *completed = true;
            }
            break;
        }
        case UpdateCipherSessionAuthenticationRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling UpdateCipherSessionAuthenticationRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray authenticationData = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            quint32 cipherSessionToken = request->inParams.size() ? request->inParams.takeFirst().value<quint32>() : 0;
            Result result = m_requestProcessor->updateCipherSessionAuthentication(
                        request->remotePid,
                        request->requestId,
                        authenticationData,
                        cryptosystemProviderName,
                        cipherSessionToken);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case UpdateCipherSessionRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling UpdateCipherSessionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray generatedData;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            quint32 cipherSessionToken = request->inParams.size() ? request->inParams.takeFirst().value<quint32>() : 0;
            Result result = m_requestProcessor->updateCipherSession(
                        request->remotePid,
                        request->requestId,
                        data,
                        cryptosystemProviderName,
                        cipherSessionToken,
                        &generatedData);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedData));
                *completed = true;
            }
            break;
        }
        case FinaliseCipherSessionRequest: {
            qCDebug(lcSailfishCryptoDaemon) << "Handling FinaliseCipherSessionRequest from client:" << request->remotePid << ", request number:" << request->requestId;
            QByteArray generatedData;
            bool verified = false;
            QByteArray data = request->inParams.size() ? request->inParams.takeFirst().value<QByteArray>() : QByteArray();
            QString cryptosystemProviderName = request->inParams.size() ? request->inParams.takeFirst().value<QString>() : QString();
            quint32 cipherSessionToken = request->inParams.size() ? request->inParams.takeFirst().value<quint32>() : 0;
            Result result = m_requestProcessor->finaliseCipherSession(
                        request->remotePid,
                        request->requestId,
                        data,
                        cryptosystemProviderName,
                        cipherSessionToken,
                        &generatedData,
                        &verified);
            // send the reply to the calling peer.
            if (result.code() == Result::Pending) {
                // waiting for asynchronous flow to complete
                *completed = false;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(generatedData)
                                                                        << QVariant::fromValue<bool>(verified));
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

void Daemon::ApiImpl::CryptoRequestQueue::handleFinishedRequest(
        Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request,
        bool *completed)
{
    switch (request->type) {
        case GetPluginInfoRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GetPluginInfoRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GetPluginInfoRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<CryptoPluginInfo> cryptoPlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<CryptoPluginInfo> >()
                        : QVector<CryptoPluginInfo>();
                QStringList storagePlugins = request->outParams.size()
                        ? request->outParams.takeFirst().value<QStringList>()
                        : QStringList();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<CryptoPluginInfo> >(cryptoPlugins)
                                                                        << QVariant::fromValue<QStringList>(storagePlugins));
                *completed = true;
            }
            break;
        }
        case GenerateRandomDataRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GenerateRandomDataRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateRandomDataRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray randomData = request->outParams.size() ? request->outParams.takeFirst().value<QByteArray>() : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(randomData));
                *completed = true;
            }
            break;
        }
        case SeedRandomDataGeneratorRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SeedRandomDataGeneratorRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "SeedRandomDataGeneratorRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case ValidateCertificateChainRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of ValidateCertificateChainRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "ValidateCertificateChainRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                bool validated = request->outParams.size() ? request->outParams.takeFirst().value<bool>() : false;
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<bool>(validated));
                *completed = true;
            }
            break;
        }
        case GenerateKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GenerateKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case GenerateStoredKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of GenerateStoredKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "GenerateStoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case StoredKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of StoredKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "StoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                Key key = request->outParams.size()
                        ? request->outParams.takeFirst().value<Key>()
                        : Key();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<Key>(key));
                *completed = true;
            }
            break;
        }
        case DeleteStoredKeyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DeleteStoredKeyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "DeleteStoredKeyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result));
                *completed = true;
            }
            break;
        }
        case StoredKeyIdentifiersRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of StoredKeyIdentifiersRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "StoredKeyIdentifiersRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QVector<Key::Identifier> identifiers = request->outParams.size()
                        ? request->outParams.takeFirst().value<QVector<Key::Identifier> >()
                        : QVector<Key::Identifier>();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QVector<Key::Identifier> >(identifiers));
                *completed = true;
            }
            break;
        }
        case SignRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of SignRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "SignRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray signature = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(signature));
                *completed = true;
            }
            break;
        }
        case VerifyRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of VerifyRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "VerifyRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                bool verified = request->outParams.size()
                        ? request->outParams.takeFirst().toBool()
                        : false;
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<bool>(verified));
                *completed = true;
            }
            break;
        }
        case EncryptRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of EncryptRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "EncryptRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray encrypted = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
                                                                        << QVariant::fromValue<QByteArray>(encrypted));
                *completed = true;
            }
            break;
        }
        case DecryptRequest: {
            Result result = request->outParams.size()
                    ? request->outParams.takeFirst().value<Result>()
                    : Result(Result::UnknownError,
                             QLatin1String("Unable to determine result of DecryptRequest request"));
            if (result.code() == Result::Pending) {
                // shouldn't happen!
                qCWarning(lcSailfishCryptoDaemon) << "DecryptRequest:" << request->requestId << "finished as pending!";
                *completed = true;
            } else {
                QByteArray decrypted = request->outParams.size()
                        ? request->outParams.takeFirst().toByteArray()
                        : QByteArray();
                request->connection.send(request->message.createReply() << QVariant::fromValue<Result>(result)
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
