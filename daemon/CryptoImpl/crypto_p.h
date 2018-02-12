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

#include "Crypto/extensionplugins.h"
#include "Crypto/storedkeyrequest.h"

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
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"generateStoredKey\">\n"
    "          <arg name=\"keyTemplate\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"storageProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"storedKey\">\n"
    "          <arg name=\"identifier\" type=\"(ss)\" direction=\"in\" />\n"
    "          <arg name=\"keyComponents\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key::Identifier\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::StoredKeyRequest::KeyComponents\" />\n"
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
    "      <method name=\"sign\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"signature\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::Key::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"verify\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"verified\" type=\"b\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::Key::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"encrypt\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"encrypted\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key::BlockMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::Key::EncryptionPadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::Key::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"decrypt\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"decrypted\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key::BlockMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::Key::EncryptionPadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::Key::Digest\" />\n"
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
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void generateStoredKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const QString &cryptosystemProviderName,
            const QString &storageProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::StoredKeyRequest::KeyComponents keyComponents,
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

    void sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &signature);

    void verify(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::SignaturePadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            bool &verified);

    void encrypt(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &encrypted);

    void decrypt(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::Key::BlockMode blockMode,
            Sailfish::Crypto::Key::EncryptionPadding padding,
            Sailfish::Crypto::Key::Digest digest,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &decrypted);

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
    SignRequest,
    VerifyRequest,
    EncryptRequest,
    DecryptRequest
};

} // ApiImpl

} // Daemon

} // Crypto

} // Sailfish

#endif // SAILFISHCRYPTO_APIIMPL_CRYPTO_P_H
