/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_APIIMPL_CRYPTO_P_H
#define SAILFISHCRYPTO_APIIMPL_CRYPTO_P_H

#include "database_p.h"
#include "requestqueue_p.h"
#include "applicationpermissions_p.h"

#include "Crypto/key.h"
#include "Crypto/extensionplugins.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/interactionparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/keypairgenerationparameters.h"

#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtDBus/QDBusContext>

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

class CryptoRequestQueue;
class CryptoDBusObject : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.sailfishos.crypto")
    Q_CLASSINFO("D-Bus Introspection", ""
    "  <interface name=\"org.sailfishos.crypto\">\n"
    "      <method name=\"getPluginInfo\">\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"cryptoPlugins\" type=\"a(ay))\" direction=\"out\" />\n"
    "          <arg name=\"storagePlugins\" type=\"as\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"QVector<Sailfish::Crypto::CryptoPluginInfo>\" />\n"
    "      </method>\n"
    "      <method name=\"generateRandomData\">\n"
    "          <arg name=\"numberBytes\" type=\"t\" direction=\"in\" />\n"
    "          <arg name=\"csprngEngineName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"randomData\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"seedRandomDataGenerator\">\n"
    "          <arg name=\"seedData\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"entropyEstimate\" type=\"d\" direction=\"in\" />\n"
    "          <arg name=\"csprngEngineName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"validateCertificateChain\">\n"
    "          <arg name=\"chain\" type=\"a(iay)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"valid\" type=\"b\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"QVector<Sailfish::Crypto::Certificate>\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"generateKey\">\n"
    "          <arg name=\"keyTemplate\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"kpgParameters\" type=\"(ia{sv}a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"skdfParameters\" type=\"(ayay(i)(i)(i)(i)xiiia{sv})\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::KeyPairGenerationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::KeyDerivationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"generateStoredKey\">\n"
    "          <arg name=\"keyTemplate\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"kpgParameters\" type=\"(ia{sv}a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"skdfParameters\" type=\"(ayay(i)(i)(i)(i)xiiia{sv})\" direction=\"in\" />\n"
    "          <arg name=\"uiParams\" type=\"(sss(i)sss(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"storageProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::KeyPairGenerationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::KeyDerivationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"storedKey\">\n"
    "          <arg name=\"identifier\" type=\"(ss)\" direction=\"in\" />\n"
    "          <arg name=\"keyComponents\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key::Identifier\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key::Components\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"deleteStoredKey\">\n"
    "          <arg name=\"identifier\" type=\"(ss)\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key::Identifier\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"storedKeyIdentifiers\">\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"identifiers\" type=\"a(ss)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"QVector<Sailfish::Crypto::Key::Identifier>\" />\n"
    "      </method>\n"
    "      <method name=\"calculateDigest\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digestFunction\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"digest\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::CryptoManager::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::CryptoManager::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"sign\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"signature\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::CryptoManager::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"verify\">\n"
    "          <arg name=\"signature\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"verified\" type=\"b\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::CryptoManager::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"encrypt\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"iv\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"encrypted\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::BlockMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::CryptoManager::EncryptionPadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"decrypt\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"iv\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"decrypted\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::BlockMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::CryptoManager::EncryptionPadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"initialiseCipherSession\">\n"
    "          <arg name=\"initialisationVector\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"operation\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"encryptionPadding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"signaturePadding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"out\" />\n"
    "          <arg name=\"generatedInitialisationVector\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::CryptoManager::Operation\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::CryptoManager::BlockMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::EncryptionPadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::CryptoManager::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In5\" value=\"Sailfish::Crypto::CryptoManager::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"updateCipherSessionAuthentication\">\n"
    "          <arg name=\"authenticationData\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"updateCipherSession\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"generatedData\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"finaliseCipherSession\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"generatedData\" type=\"ay\" direction=\"out\" />\n"
    "          <arg name=\"verified\" type=\"b\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "  </interface>\n"
    "")

public:
    CryptoDBusObject(Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *parent);

public Q_SLOTS:
    void getPluginInfo(
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QVector<Sailfish::Crypto::CryptoPluginInfo> &cryptoPlugins,
            QStringList &storagePlugins);

    void generateRandomData(
            quint64 numberBytes,
            const QString &csprngEngineName,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &randomData);

    void seedRandomDataGenerator(
            const QByteArray &seedData,
            double entropyEstimate,
            const QString &csprngEngineName,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void validateCertificateChain(
            const QVector<Sailfish::Crypto::Certificate> &chain,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            bool &valid);

    void generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void generateStoredKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const Sailfish::Crypto::InteractionParameters &uiParams,
            const QString &cryptosystemProviderName,
            const QString &storageProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key::Components keyComponents,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void deleteStoredKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void storedKeyIdentifiers(
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QVector<Sailfish::Crypto::Key::Identifier> &identifiers);

    void calculateDigest(
            const QByteArray &data,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &digest);

    void sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &signature);

    void verify(
            const QByteArray &signature,
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            bool &verified);

    void encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &encrypted);

    void decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &decrypted);

    void initialiseCipherSession(
            const QByteArray &initialisationVector,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::Operation operation,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            quint32 &cipherSessionToken,
            QByteArray &generatedInitialisationVector);

    void updateCipherSessionAuthentication(
            const QByteArray &authenticationData,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void updateCipherSession(
            const QByteArray &data,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &generatedData);

    void finaliseCipherSession(
            const QByteArray &data,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &generatedData,
            bool &verified);

private:
    Sailfish::Crypto::Daemon::ApiImpl::CryptoRequestQueue *m_requestQueue;
};

class RequestProcessor;
class CryptoRequestQueue : public Sailfish::Secrets::Daemon::ApiImpl::RequestQueue
{
    Q_OBJECT

public:
    CryptoRequestQueue(Sailfish::Secrets::Daemon::Controller *parent,
                       Sailfish::Secrets::Daemon::ApiImpl::SecretsRequestQueue *secrets,
                       const QString &pluginDir,
                       bool autotestMode);
    ~CryptoRequestQueue();

    QMap<QString, Sailfish::Crypto::CryptoPlugin*> plugins() const;
    bool lockPlugins();
    bool unlockPlugins(const QByteArray &unlockCode);
    bool setLockCodePlugins(const QByteArray &oldCode, const QByteArray &newCode);

    void handlePendingRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) Q_DECL_OVERRIDE;
    void handleFinishedRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) Q_DECL_OVERRIDE;
    QString requestTypeToString(int type) const Q_DECL_OVERRIDE;

private:
    Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor *m_requestProcessor;
};

enum RequestType {
    InvalidRequest = 0,
    GetPluginInfoRequest,
    GenerateRandomDataRequest,
    SeedRandomDataGeneratorRequest,
    ValidateCertificateChainRequest,
    GenerateKeyRequest,
    GenerateStoredKeyRequest,
    StoredKeyRequest,
    DeleteStoredKeyRequest,
    StoredKeyIdentifiersRequest,
    CalculateDigestRequest,
    SignRequest,
    VerifyRequest,
    EncryptRequest,
    DecryptRequest,
    InitialiseCipherSessionRequest,
    UpdateCipherSessionAuthenticationRequest,
    UpdateCipherSessionRequest,
    FinaliseCipherSessionRequest
};

} // ApiImpl

} // Daemon

} // Crypto

} // Sailfish

#endif // SAILFISHCRYPTO_APIIMPL_CRYPTO_P_H
