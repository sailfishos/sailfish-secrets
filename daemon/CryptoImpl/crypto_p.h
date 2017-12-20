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

#include "Crypto/Plugins/extensionplugins.h"

#include "Crypto/key.h"
#include "Crypto/plugininfo.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/interactionparameters.h"
#include "Crypto/keyderivationparameters.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/lockcoderequest.h"

#include <QtCore/QVariantMap>
#include <QtCore/QByteArray>
#include <QtCore/QString>
#include <QtCore/QThreadPool>
#include <QtCore/QSharedPointer>
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
    "          <arg name=\"cryptoPlugins\" type=\"a(ssi)\" direction=\"out\" />\n"
    "          <arg name=\"storagePlugins\" type=\"a(ssi)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"QVector<Sailfish::Crypto::PluginInfo>\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out2\" value=\"QVector<Sailfish::Crypto::PluginInfo>\" />\n"
    "      </method>\n"
    "      <method name=\"generateRandomData\">\n"
    "          <arg name=\"numberBytes\" type=\"t\" direction=\"in\" />\n"
    "          <arg name=\"csprngEngineName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"randomData\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"seedRandomDataGenerator\">\n"
    "          <arg name=\"seedData\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"entropyEstimate\" type=\"d\" direction=\"in\" />\n"
    "          <arg name=\"csprngEngineName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"generateKey\">\n"
    "          <arg name=\"keyTemplate\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"kpgParameters\" type=\"(ia{sv}a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"skdfParameters\" type=\"(ayay(i)(i)(i)(i)xiiia{sv})\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::KeyPairGenerationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::KeyDerivationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"generateStoredKey\">\n"
    "          <arg name=\"keyTemplate\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"kpgParameters\" type=\"(ia{sv}a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"skdfParameters\" type=\"(ayay(i)(i)(i)(i)xiiia{sv})\" direction=\"in\" />\n"
    "          <arg name=\"uiParams\" type=\"(sss(i)sss(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::KeyPairGenerationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::KeyDerivationParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"importKey\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"uiParams\" type=\"(ssss(i)ssa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"importedKey\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"importStoredKey\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"keyTemplate\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"uiParams\" type=\"(ssss(i)ssa{is}(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"importedKeyReference\" type=\"(ay)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"storedKey\">\n"
    "          <arg name=\"identifier\" type=\"(sss)\" direction=\"in\" />\n"
    "          <arg name=\"keyComponents\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"key\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key::Identifier\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::Key::Components\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::Key\" />\n"
    "      </method>\n"
    "      <method name=\"deleteStoredKey\">\n"
    "          <arg name=\"identifier\" type=\"(sss)\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::Key::Identifier\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"storedKeyIdentifiers\">\n"
    "          <arg name=\"storagePluginName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"collectionName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"identifiers\" type=\"a(sss)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"QVector<Sailfish::Crypto::Key::Identifier>\" />\n"
    "      </method>\n"
    "      <method name=\"calculateDigest\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digestFunction\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"digest\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In1\" value=\"Sailfish::Crypto::CryptoManager::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::CryptoManager::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"sign\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
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
    "          <arg name=\"key\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"verificationStatus\" type=\"(i)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::SignaturePadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::CryptoManager::Digest\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::CryptoManager::VerificationStatus\" />\n"
    "      </method>\n"
    "      <method name=\"encrypt\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"iv\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"authenticationData\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"encrypted\" type=\"ay\" direction=\"out\" />\n"
    "          <arg name=\"authenticationTag\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::BlockMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::CryptoManager::EncryptionPadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"decrypt\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"iv\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"((sss)iiiiiayayaya(ay)a{sv})\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"padding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"authenticationData\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"authenticationTag\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"decrypted\" type=\"ay\" direction=\"out\" />\n"
    "          <arg name=\"verificationStatus\" type=\"(i)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::Key\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In3\" value=\"Sailfish::Crypto::CryptoManager::BlockMode\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In4\" value=\"Sailfish::Crypto::CryptoManager::EncryptionPadding\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::CryptoManager::VerificationStatus\" />\n"
    "      </method>\n"
    "      <method name=\"initializeCipherSession\">\n"
    "          <arg name=\"initializationVector\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"key\" type=\"(ay)\" direction=\"in\" />\n"
    "          <arg name=\"operation\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"blockMode\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"encryptionPadding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"signaturePadding\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"digest\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"out\" />\n"
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
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"updateCipherSession\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"generatedData\" type=\"ay\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"finalizeCipherSession\">\n"
    "          <arg name=\"data\" type=\"ay\" direction=\"in\" />\n"
    "          <arg name=\"customParameters\" type=\"a{sv}\" direction=\"in\" />\n"
    "          <arg name=\"cryptosystemProviderName\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"cipherSessionToken\" type=\"u\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iiis)\" direction=\"out\" />\n"
    "          <arg name=\"generatedData\" type=\"ay\" direction=\"out\" />\n"
    "          <arg name=\"verificationStatus\" type=\"(i)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::CryptoManager::VerificationStatus\" />\n"
    "      </method>\n"
    "      <method name=\"queryLockStatus\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <arg name=\"lockStatus\" type=\"(i)\" direction=\"in\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out1\" value=\"Sailfish::Crypto::LockCodeRequest::LockStatus\" />\n"
    "      </method>\n"
    "      <method name=\"modifyLockCode\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"interactionParameters\" type=\"(sss(i)sss(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"provideLockCode\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"interactionParameters\" type=\"(sss(i)sss(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::InteractionParameters\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.Out0\" value=\"Sailfish::Crypto::Result\" />\n"
    "      </method>\n"
    "      <method name=\"forgetLockCode\">\n"
    "          <arg name=\"lockCodeTargetType\" type=\"(i)\" direction=\"in\" />\n"
    "          <arg name=\"lockCodeTarget\" type=\"s\" direction=\"in\" />\n"
    "          <arg name=\"interactionParameters\" type=\"(sss(i)sss(i)(i))\" direction=\"in\" />\n"
    "          <arg name=\"result\" type=\"(iis)\" direction=\"out\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In0\" value=\"Sailfish::Crypto::LockCodeRequest::LockCodeTargetType\" />\n"
    "          <annotation name=\"org.qtproject.QtDBus.QtTypeName.In2\" value=\"Sailfish::Crypto::InteractionParameters\" />\n"
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
            QVector<Sailfish::Crypto::PluginInfo> &cryptoPlugins,
            QVector<Sailfish::Crypto::PluginInfo> &storagePlugins);

    void generateRandomData(
            quint64 numberBytes,
            const QString &csprngEngineName,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &randomData);

    void seedRandomDataGenerator(
            const QByteArray &seedData,
            double entropyEstimate,
            const QString &csprngEngineName,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void generateInitializationVector(
            Sailfish::Crypto::CryptoManager::Algorithm algorithm,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            int keySize,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &generatedIV);

    void generateKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void generateStoredKey(
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::KeyPairGenerationParameters &kpgParams,
            const Sailfish::Crypto::KeyDerivationParameters &skdfParams,
            const Sailfish::Crypto::InteractionParameters &uiParams,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void importKey(
            const QByteArray &data,
            const Sailfish::Crypto::InteractionParameters &uiParams,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &importedKey);

    void importStoredKey(
            const QByteArray &data,
            const Sailfish::Crypto::Key &keyTemplate,
            const Sailfish::Crypto::InteractionParameters &uiParams,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &importedKey);

    void storedKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            Sailfish::Crypto::Key::Components keyComponents,
            const QVariantMap &customParameters,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::Key &key);

    void deleteStoredKey(
            const Sailfish::Crypto::Key::Identifier &identifier,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void storedKeyIdentifiers(
            const QString &storagePluginName,
            const QString &collectionName,
            const QVariantMap &customParameters,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QVector<Sailfish::Crypto::Key::Identifier> &identifiers);

    void calculateDigest(
            const QByteArray &data,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &digest);

    void sign(
            const QByteArray &data,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::SignaturePadding padding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
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
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::CryptoManager::VerificationStatus &verificationStatus);

    void encrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &encrypted,
            QByteArray &authenticationTag);

    void decrypt(
            const QByteArray &data,
            const QByteArray &iv,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding padding,
            const QByteArray &authenticationData,
            const QByteArray &authenticationTag,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &decrypted,
            Sailfish::Crypto::CryptoManager::VerificationStatus &verificationStatus);

    void initializeCipherSession(
            const QByteArray &initializationVector,
            const Sailfish::Crypto::Key &key,
            Sailfish::Crypto::CryptoManager::Operation operation,
            Sailfish::Crypto::CryptoManager::BlockMode blockMode,
            Sailfish::Crypto::CryptoManager::EncryptionPadding encryptionPadding,
            Sailfish::Crypto::CryptoManager::SignaturePadding signaturePadding,
            Sailfish::Crypto::CryptoManager::DigestFunction digestFunction,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            quint32 &cipherSessionToken);

    void updateCipherSessionAuthentication(
            const QByteArray &authenticationData,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void updateCipherSession(
            const QByteArray &data,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &generatedData);

    void finalizeCipherSession(
            const QByteArray &data,
            const QVariantMap &customParameters,
            const QString &cryptosystemProviderName,
            quint32 cipherSessionToken,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            QByteArray &generatedData,
            Sailfish::Crypto::CryptoManager::VerificationStatus &verificationStatus);

    void queryLockStatus(
            Sailfish::Crypto::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result,
            Sailfish::Crypto::LockCodeRequest::LockStatus &lockStatus);

    void modifyLockCode(
            Sailfish::Crypto::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Crypto::InteractionParameters &interactionParameters,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void provideLockCode(
            Sailfish::Crypto::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Crypto::InteractionParameters &interactionParameters,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

    void forgetLockCode(
            Sailfish::Crypto::LockCodeRequest::LockCodeTargetType lockCodeTargetType,
            const QString &lockCodeTarget,
            const Sailfish::Crypto::InteractionParameters &interactionParameters,
            const QDBusMessage &message,
            Sailfish::Crypto::Result &result);

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
                       bool autotestMode);
    ~CryptoRequestQueue();

    Sailfish::Secrets::Daemon::Controller *controller();
    QWeakPointer<QThreadPool> cryptoThreadPool();
    QMap<QString, Sailfish::Crypto::CryptoPlugin*> plugins() const;

    Sailfish::Crypto::LockCodeRequest::LockStatus queryLockStatusPlugin(const QString &pluginName);
    bool lockPlugin(const QString &pluginName);
    bool unlockPlugin(const QString &pluginName, const QByteArray &lockCode);
    bool setLockCodePlugin(const QString &pluginName, const QByteArray &oldCode, const QByteArray &newCode);

    void handlePendingRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) Q_DECL_OVERRIDE;
    void handleFinishedRequest(Sailfish::Secrets::Daemon::ApiImpl::RequestQueue::RequestData *request, bool *completed) Q_DECL_OVERRIDE;
    QString requestTypeToString(int type) const Q_DECL_OVERRIDE;

private:
    QSharedPointer<QThreadPool> m_cryptoThreadPool;
    Sailfish::Crypto::Daemon::ApiImpl::RequestProcessor *m_requestProcessor;
    Sailfish::Secrets::Daemon::Controller *m_controller;
};

enum RequestType {
    InvalidRequest = 0,
    GetPluginInfoRequest,
    GenerateRandomDataRequest,
    SeedRandomDataGeneratorRequest,
    GenerateInitializationVectorRequest,
    GenerateKeyRequest,
    GenerateStoredKeyRequest,
    ImportKeyRequest,
    ImportStoredKeyRequest,
    StoredKeyRequest,
    DeleteStoredKeyRequest,
    StoredKeyIdentifiersRequest,
    CalculateDigestRequest,
    SignRequest,
    VerifyRequest,
    EncryptRequest,
    DecryptRequest,
    InitializeCipherSessionRequest,
    UpdateCipherSessionAuthenticationRequest,
    UpdateCipherSessionRequest,
    FinalizeCipherSessionRequest,
    QueryLockStatusRequest,
    ModifyLockCodeRequest,
    ProvideLockCodeRequest,
    ForgetLockCodeRequest
};

} // ApiImpl

} // Daemon

} // Crypto

} // Sailfish

#endif // SAILFISHCRYPTO_APIIMPL_CRYPTO_P_H
