/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_APIIMPL_REQUESTPROCESSOR_P_H
#define SAILFISHCRYPTO_APIIMPL_REQUESTPROCESSOR_P_H

#include <QtCore/QObject>
#include <QtCore/QVariantList>
#include <QtCore/QList>
#include <QtCore/QVariant>
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QDateTime>
#include <QtCore/QMap>

#include <sys/types.h>

#include "Crypto/result.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/key.h"
#include "Crypto/certificate.h"
#include "Crypto/extensionplugins.h"
#include "Crypto/storedkeyrequest.h"

#include "CryptoImpl/crypto_p.h"

#include "requestqueue_p.h"

namespace Sailfish {

namespace Secrets {
    namespace Daemon {
        namespace ApiImpl {
            class SecretsRequestQueue;
        }
    }
}

namespace Crypto {

namespace Daemon {

namespace ApiImpl {

// The RequestProcessor implements the Crypto Daemon API.
// It processes requests from clients which are forwarded
// by the RequestQueue, by interacting with the database
// and returns the results to the RequestQueue to forward
// back to clients.
class RequestProcessor : public QObject
{
    Q_OBJECT

public:
    RequestProcessor(Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets,
                     bool autotestMode,
                     Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *parent = Q_NULLPTR);

    bool loadPlugins(const QString &pluginDir);

    Sailfish::Crypto::Result getPluginInfo(
            pid_t callerPid,
            quint64 requestId,
            QVector<Sailfish::Crypto::CryptoPluginInfo> *cryptoPlugins,
            QStringList *storagePlugins);

    Sailfish::Crypto::Result generateRandomData(
            pid_t callerPid,
            quint64 requestId,
            quint64 numberBytes,
            const QString &csprngEngineName,
            const QString &cryptosystemProviderName,
            QByteArray *randomData);

    Sailfish::Crypto::Result seedRandomDataGenerator(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &seedData,
            double entropyEstimate,
            const QString &csprngEngineName,
            const QString &cryptosystemProviderName);

    Sailfish::Crypto::Result validateCertificateChain(
            pid_t callerPid,
            quint64 requestId,
            const QVector<Sailfish::Crypto::Certificate> &chain,
            const QString &cryptosystemProviderName,
            bool *valid);

    Sailfish::Crypto::Result generateKey(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Key &keyTemplate,
            const QString &cryptosystemProviderName,
            Sailfish::Crypto::Key *key);

    Sailfish::Crypto::Result generateStoredKey(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Key &keyTemplate,
            const QString &cryptosystemProviderName,
            const QString &storageProviderName,
            Sailfish::Crypto::Key *key);

    Sailfish::Crypto::Result storedKey(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Key::Identifier &identifier,
            StoredKeyRequest::KeyComponents keyComponents,
            Sailfish::Crypto::Key *key);

    Sailfish::Crypto::Result deleteStoredKey(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Key::Identifier &identifier);

    Sailfish::Crypto::Result storedKeyIdentifiers(
            pid_t callerPid,
            quint64 requestId,
            QVector<Sailfish::Crypto::Key::Identifier> *identifiers);

    Sailfish::Crypto::Result sign(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName,
            QByteArray *signature);

    Sailfish::Crypto::Result verify(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName,
            bool *verified);

    Sailfish::Crypto::Result encrypt(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            const QString &cryptosystemProviderName,
            QByteArray *encrypted);

    Sailfish::Crypto::Result decrypt(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            const QString &cryptosystemProviderName,
            QByteArray *decrypted);

    Sailfish::Crypto::Result initialiseCipherSession(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::Operation operation,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::Key::SignaturePadding signaturePadding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName,
            quint32 *cipherSessionToken,
            QByteArray *generatedIV);

    Sailfish::Crypto::Result updateCipherSessionAuthentication(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &authenticationData,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken);

    Sailfish::Crypto::Result updateCipherSession(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &data,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            QByteArray *generatedData);

    Sailfish::Crypto::Result finaliseCipherSession(
            pid_t callerPid,
            quint64 requestId,
            const QByteArray &data,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            QByteArray *generatedData,
            bool *verified);

public Q_SLOTS:
    void secretsStoreKeyCompleted(
            quint64 requestId,
            const Sailfish::Secrets::Result &result);

    void secretsStoreKeyMetadataCompleted(
            quint64 requestId,
            const Sailfish::Secrets::Result &result);

    void secretsStoredKeyCompleted(
            quint64 requestId,
            const Sailfish::Secrets::Result &result,
            const QByteArray &serialisedKey,
            const QMap<QString, QString> &filterData);

    void secretsDeleteStoredKeyCompleted(
            quint64 requestId,
            const Sailfish::Secrets::Result &result);

    void secretsDeleteStoredKeyMetadataCompleted(
            quint64 requestId,
            const Sailfish::Secrets::Result &result);

private:
    struct PendingRequest {
        PendingRequest()
            : callerPid(0), requestId(0), requestType(Sailfish::Crypto::Daemon::ApiImpl::InvalidRequest) {}
        PendingRequest(uint pid, quint64 rid, Sailfish::Crypto::Daemon::ApiImpl::RequestType rtype, QVariantList params)
            : callerPid(pid), requestId(rid), requestType(rtype), parameters(params) {}
        PendingRequest(const PendingRequest &other)
            : callerPid(other.callerPid), requestId(other.requestId), requestType(other.requestType), parameters(other.parameters) {}
        uint callerPid;
        quint64 requestId;
        Sailfish::Crypto::Daemon::ApiImpl::RequestType requestType;
        QVariantList parameters;
    };

    void storedKey2(
            quint64 requestId,
            StoredKeyRequest::KeyComponents keyComponents,
            const Sailfish::Crypto::Result &result,
            const QByteArray &serialisedKey,
            const QMap<QString, QString> &filterData);

    void generateStoredKey_inStoragePlugin(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const Sailfish::Crypto::Key &fullKey,
            const QString &cryptosystemProviderName,
            const QString &storagePluginName);

    void generateStoredKey_inCryptoPlugin(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const Sailfish::Crypto::Key &keyTemplate,
            const QString &cryptosystemProviderName,
            const QString &storagePluginName);

    void generateStoredKey_failedCleanup(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::Result &initialResult,
            const Sailfish::Crypto::Result &result);

    void deleteStoredKey2(
            pid_t callerPid,
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const Sailfish::Crypto::Key::Identifier &identifier);

    void sign2(
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const QByteArray &serialisedKey,
            const QByteArray &data,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptoPluginName);

    void verify2(
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const QByteArray &serialisedKey,
            const QByteArray &data,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptoPluginName);

    void encrypt2(
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const QByteArray &serialisedKey,
            const QByteArray &data,
            const QByteArray &iv,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            const QString &cryptoPluginName);

    void decrypt2(
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const QByteArray &serialisedKey,
            const QByteArray &data,
            const QByteArray &iv,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            const QString &cryptoPluginName);

    void initialiseCipherSession2(
            quint64 requestId,
            const Sailfish::Crypto::Result &result,
            const QByteArray &serialisedKey,
            pid_t callerPid,
            const QByteArray &iv,
            Sailfish::Crypto::Key::Operation operation,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::Key::SignaturePadding signaturePadding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptoPluginName);

private:
    Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *m_requestQueue;
    Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *m_secrets;
    QMap<QString, Sailfish::Crypto::CryptoPlugin*> m_cryptoPlugins;
    QMap<quint64, Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor::PendingRequest> m_pendingRequests;
    bool m_autotestMode;
};

} // namespace ApiImpl

} // namespace Daemon

} // namespace Secrets

} // namespace Sailfish

#endif // SAILFISHCRYPTO_APIIMPL_REQUESTPROCESSOR_P_H
