/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "commandhelper.h"

#include <Secrets/interactionparameters.h>
#include <Secrets/plugininforequest.h>
#include <Secrets/collectionnamesrequest.h>
#include <Secrets/createcollectionrequest.h>
#include <Secrets/deletecollectionrequest.h>
#include <Secrets/storesecretrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/deletesecretrequest.h>

#include <Crypto/interactionparameters.h>
#include <Crypto/keypairgenerationparameters.h>
#include <Crypto/keyderivationparameters.h>
#include <Crypto/plugininforequest.h>
#include <Crypto/storedkeyidentifiersrequest.h>
#include <Crypto/generatestoredkeyrequest.h>
#include <Crypto/importstoredkeyrequest.h>
#include <Crypto/deletestoredkeyrequest.h>
#include <Crypto/signrequest.h>
#include <Crypto/verifyrequest.h>
#include <Crypto/encryptrequest.h>
#include <Crypto/decryptrequest.h>
#include <Crypto/generateinitializationvectorrequest.h>

#include <QtCore/QFile>
#include <QtCore/QByteArray>
#include <QtDebug>

#define EXITCODE_SUCCESS 0
#define EXITCODE_FAILED 1

static Sailfish::Crypto::CryptoManager::Algorithm algorithmEnum(const QString &algo)
{
    if (algo == QStringLiteral("RSA")) {
        return Sailfish::Crypto::CryptoManager::AlgorithmRsa;
    } else if (algo == QStringLiteral("EC")) {
        return Sailfish::Crypto::CryptoManager::AlgorithmEc;
    } else if (algo == QStringLiteral("AES")) {
        return Sailfish::Crypto::CryptoManager::AlgorithmAes;
    } else if (algo == QStringLiteral("GOST")) {
        return Sailfish::Crypto::CryptoManager::AlgorithmGost;
    }

    return Sailfish::Crypto::CryptoManager::AlgorithmRsa;
}

static Sailfish::Crypto::CryptoManager::DigestFunction digestEnum(const QString &dg)
{
    if (dg == QStringLiteral("SHA256")) {
        return Sailfish::Crypto::CryptoManager::DigestSha256;
    } else if (dg == QStringLiteral("SHA512")) {
        return Sailfish::Crypto::CryptoManager::DigestSha512;
    } else if (dg == QStringLiteral("GOST_94")) {
        return Sailfish::Crypto::CryptoManager::DigestGost_94;
    } else if (dg == QStringLiteral("GOST_2012_256")) {
        return Sailfish::Crypto::CryptoManager::DigestGost_2012_256;
    } else if (dg == QStringLiteral("GOST_2012_512")) {
        return Sailfish::Crypto::CryptoManager::DigestGost_2012_512;
    }

    return Sailfish::Crypto::CryptoManager::DigestSha512;
}

static QVariantMap toCustomParameters(const QStringList &options)
{
    QVariantMap customs;
    for (QList<QString>::ConstIterator it = options.constBegin(); it != options.constEnd(); it++) {
        int iEqual = it->indexOf('=');
        if (iEqual > 0 && iEqual < it->length() - 1) {
            const QString key = it->left(iEqual);
            const QString value = it->mid(iEqual + 1);
            bool ok;
            QVariant vd(value.toDouble(&ok));
            if (ok) {
                customs.insert(key, vd);
            } else {
                QVariant vi(value.toInt(&ok));
                if (ok) {
                    customs.insert(key, vi);
                } else {
                    if (value.compare("true", Qt::CaseInsensitive) == 0) {
                        customs.insert(key, QVariant(true));
                    } else if (value.compare("false", Qt::CaseInsensitive) == 0) {
                        customs.insert(key, QVariant(false));
                    } else {
                        customs.insert(key, QVariant(value));
                    }
                }
            }
        } else {
            qWarning() << "unrecognized option:" << *it;
        }
    }
    return customs;
}

CommandHelper::CommandHelper(bool autotestMode, QObject *parent)
    : QObject(parent), m_step(0), m_exitCode(0), m_autotestMode(autotestMode)
{
    Sailfish::Secrets::PluginInfoRequest spir;
    spir.setManager(&m_secretManager);
    spir.startRequest();

    Sailfish::Crypto::PluginInfoRequest cpir;
    cpir.setManager(&m_cryptoManager);
    cpir.startRequest();

    spir.waitForFinished();
    cpir.waitForFinished();

    if (spir.result().code() != Sailfish::Secrets::Result::Succeeded) {
        qInfo() << "Failed to request secrets plugin information!";
        qInfo() << "Error:" << spir.result().errorCode() << spir.result().errorMessage();
        m_exitCode = spir.result().errorCode();
        return;
    }

    if (cpir.result().code() != Sailfish::Crypto::Result::Succeeded) {
        qInfo() << "Failed to request crypto plugin information!";
        qInfo() << "Error:" << cpir.result().errorCode() << cpir.result().errorMessage();
        m_exitCode = cpir.result().errorCode();
        return;
    }

    for (const Sailfish::Secrets::PluginInfo &pi : spir.authenticationPlugins()) {
        m_authenticationPlugins.append(pi.name());
    }
    for (const Sailfish::Secrets::PluginInfo &pi : spir.encryptionPlugins()) {
        m_encryptionPlugins.append(pi.name());
    }
    for (const Sailfish::Secrets::PluginInfo &pi : spir.storagePlugins()) {
        m_storagePlugins.append(pi.name());
    }
    for (const Sailfish::Secrets::PluginInfo &pi : spir.encryptedStoragePlugins()) {
        m_encryptedStoragePlugins.append(pi.name());
    }
    for (const Sailfish::Crypto::PluginInfo &pi : cpir.cryptoPlugins()) {
        if (m_encryptedStoragePlugins.contains(pi.name())) {
            m_cryptoStoragePlugins.append(pi.name());
        } else {
            m_cryptoPlugins.append(pi.name());
        }
    }
}

int CommandHelper::exitCode() const
{
    return m_exitCode;
}

void CommandHelper::emitFinished(int exitCode)
{
    m_exitCode = exitCode;
    QMetaObject::invokeMethod(this, "finished", Qt::QueuedConnection);
}

void CommandHelper::start(const QString &command, const QStringList &args, const QStringList &options)
{
    m_command = command;

    const QVariantMap customs(toCustomParameters(options));
    if (command == QStringLiteral("--list-algorithms")) {
        const QStringList algorithms {
            "RSA",
            "EC",
            "AES",
            "GOST"
        };
        qInfo() << "Supported algorithms:";
        for (const QString &value : algorithms) {
            qInfo() << "\t" << value;
        }
        emitFinished(EXITCODE_SUCCESS);
    } else if (command == QStringLiteral("--list-digests")) {
        const QStringList digests {
            "SHA256",
            "SHA512",
            "GOST"
        };
        qInfo() << "Supported digests:";
        for (const QString &value : digests) {
            qInfo() << "\t" << value;
        }
        emitFinished(EXITCODE_SUCCESS);
    } else if (command == QStringLiteral("--list-plugins")) {
        if (m_exitCode == 0) {
            qInfo() << "Authentication plugins:";
            for (const QString &value : m_authenticationPlugins) {
                qInfo() << "\t" << value;
            }
            qInfo() << "Encryption plugins:";
            for (const QString &value : m_encryptionPlugins) {
                qInfo() << "\t" << value;
            }
            qInfo() << "Storage plugins:";
            for (const QString &value : m_storagePlugins) {
                qInfo() << "\t" << value;
            }
            qInfo() << "Encrypted storage plugins:";
            for (const QString &value : m_encryptedStoragePlugins) {
                qInfo() << "\t" << value;
            }
            qInfo() << "Crypto storage plugins:";
            for (const QString &value : m_cryptoStoragePlugins) {
                qInfo() << "\t" << value;
            }
            qInfo() << "Crypto plugins:";
            for (const QString &value : m_cryptoPlugins) {
                qInfo() << "\t" << value;
            }
        }
        emitFinished(m_exitCode);
    } else if (command == QStringLiteral("--list-collections")) {
        Sailfish::Secrets::CollectionNamesRequest *r = new Sailfish::Secrets::CollectionNamesRequest;
        r->setStoragePluginName(args.value(0));
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--create-collection")) {
        bool devicelock = false;
        bool keepUnlocked = false;
        QStringList ccArgs(args);
        if (ccArgs.first() == QStringLiteral("--devicelock")) {
            ccArgs.removeFirst();
            devicelock = true;
        }
        if (ccArgs.first() == QStringLiteral("--keep-unlocked")) {
            ccArgs.removeFirst();
            keepUnlocked = true;
        }

        if (ccArgs.size() < 2) {
            qInfo() << "Missing: storage plugin name or collection name";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QString storagePluginName = ccArgs.value(0);
        bool isEncryptedStoragePlugin = false;
        if (!m_storagePlugins.contains(storagePluginName)) {
            if (!m_encryptedStoragePlugins.contains(storagePluginName)) {
                qInfo() << "Invalid storage plugin name specified";
                emitFinished(EXITCODE_FAILED);
                return;
            } else {
                isEncryptedStoragePlugin = true;
            }
        }

        const QString collectionName = ccArgs.value(1);

        const QString encryptionPluginName = (ccArgs.size() == 3)
                ? ccArgs.value(2)
                : isEncryptedStoragePlugin
                    ? storagePluginName
                    : (Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName
                       + (m_autotestMode ? QStringLiteral(".test") : QString()));

        if ((isEncryptedStoragePlugin && encryptionPluginName != storagePluginName)
                || (!isEncryptedStoragePlugin && !m_encryptionPlugins.contains(encryptionPluginName))) {
            qInfo() << "Invalid encryption plugin specified";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        Sailfish::Secrets::CreateCollectionRequest *r = new Sailfish::Secrets::CreateCollectionRequest;
        r->setStoragePluginName(storagePluginName);
        r->setCollectionName(collectionName);
        r->setEncryptionPluginName(encryptionPluginName);
        r->setAuthenticationPluginName(Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName + (m_autotestMode ? QStringLiteral(".test") : QString()));
        if (devicelock) {
            r->setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
            if (keepUnlocked) {
                r->setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
            } else {
                r->setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockVerifyLock);
            }
        } else {
            r->setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::CustomLock);
            if (keepUnlocked) {
                r->setCustomLockUnlockSemantic(Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked);
            } else {
                r->setCustomLockUnlockSemantic(Sailfish::Secrets::SecretManager::CustomLockAccessRelock);
            }
        }
        r->setAccessControlMode(Sailfish::Secrets::SecretManager::NoAccessControlMode);
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--delete-collection")) {
        Sailfish::Secrets::DeleteCollectionRequest *r = new Sailfish::Secrets::DeleteCollectionRequest;
        r->setStoragePluginName(args.value(0));
        r->setCollectionName(args.value(1));
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--list-secrets")) {
        qInfo() << "This command is not yet implemented";
        emitFinished(EXITCODE_FAILED);
    } else if (command == QStringLiteral("--store-standalone-secret")) {
        bool devicelock = false;
        bool keepUnlocked = false;
        QStringList ccArgs(args);
        if (ccArgs.first() == QStringLiteral("--devicelock")) {
            ccArgs.removeFirst();
            devicelock = true;
        }
        if (ccArgs.first() == QStringLiteral("--keep-unlocked")) {
            ccArgs.removeFirst();
            keepUnlocked = true;
        }

        if (ccArgs.size() < 3) {
            qInfo() << "Missing: storage plugin name, encryption plugin name, or secret name";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QString storagePluginName = ccArgs.value(0);
        bool isEncryptedStoragePlugin = false;
        if (!m_storagePlugins.contains(storagePluginName)) {
            if (!m_encryptedStoragePlugins.contains(storagePluginName)) {
                qInfo() << "Invalid storage plugin name specified";
                emitFinished(EXITCODE_FAILED);
                return;
            } else {
                isEncryptedStoragePlugin = true;
            }
        }

        const QString encryptionPluginName = ccArgs.value(1);
        if ((isEncryptedStoragePlugin && encryptionPluginName != storagePluginName)
                || (!isEncryptedStoragePlugin && !m_encryptionPlugins.contains(encryptionPluginName))) {
            qInfo() << "Invalid encryption plugin specified";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QString secretName = ccArgs.value(2);

        const QByteArray secretData = ccArgs.value(3, QString()).toUtf8();
        Sailfish::Secrets::Secret secret(secretName, QString(), storagePluginName);
        if (secretData.size()) {
            secret.setData(secretData);
            secret.setType(Sailfish::Secrets::Secret::TypeBlob);
        }

        Sailfish::Secrets::StoreSecretRequest *r = new Sailfish::Secrets::StoreSecretRequest;
        r->setEncryptionPluginName(encryptionPluginName);
        r->setAuthenticationPluginName(Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName + (m_autotestMode ? QStringLiteral(".test") : QString()));
        r->setSecret(secret);
        if (devicelock) {
            r->setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::StandaloneDeviceLockSecret);
            if (keepUnlocked) {
                r->setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
            } else {
                r->setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockVerifyLock);
            }
        } else {
            r->setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::StandaloneCustomLockSecret);
            if (keepUnlocked) {
                r->setCustomLockUnlockSemantic(Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked);
            } else {
                r->setCustomLockUnlockSemantic(Sailfish::Secrets::SecretManager::CustomLockAccessRelock);
            }
        }
        r->setAccessControlMode(Sailfish::Secrets::SecretManager::NoAccessControlMode);
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        if (!secretData.size()) {
            Sailfish::Secrets::InteractionParameters uiParams;
            uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
            uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::NormalEcho);
            r->setInteractionParameters(uiParams);
        }
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--store-collection-secret")) {
        Sailfish::Secrets::Secret secret(args.value(2), args.value(1), args.value(0));
        const QByteArray secretData = args.value(3, QString()).toUtf8();
        if (secretData.size()) {
            secret.setData(secretData);
            secret.setType(Sailfish::Secrets::Secret::TypeBlob);
        }
        Sailfish::Secrets::StoreSecretRequest *r = new Sailfish::Secrets::StoreSecretRequest;
        r->setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
        r->setAuthenticationPluginName(Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName + (m_autotestMode ? QStringLiteral(".test") : QString()));
        r->setSecret(secret);
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        if (!secretData.size()) {
            Sailfish::Secrets::InteractionParameters uiParams;
            uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
            uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::NormalEcho);
            r->setInteractionParameters(uiParams);
        }
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--get-standalone-secret")) {
        Sailfish::Secrets::StoredSecretRequest *r = new Sailfish::Secrets::StoredSecretRequest;
        r->setIdentifier(Sailfish::Secrets::Secret::Identifier(
                             args.value(1), QString(), args.value(0)));
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--get-collection-secret")) {
        Sailfish::Secrets::StoredSecretRequest *r = new Sailfish::Secrets::StoredSecretRequest;
        r->setIdentifier(Sailfish::Secrets::Secret::Identifier(
                             args.value(2), args.value(1), args.value(0)));
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--delete-standalone-secret")) {
        Sailfish::Secrets::DeleteSecretRequest *r = new Sailfish::Secrets::DeleteSecretRequest;
        r->setIdentifier(Sailfish::Secrets::Secret::Identifier(
                             args.value(1), QString(), args.value(0)));
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--delete-collection-secret")) {
        Sailfish::Secrets::DeleteSecretRequest *r = new Sailfish::Secrets::DeleteSecretRequest;
        r->setIdentifier(Sailfish::Secrets::Secret::Identifier(
                             args.value(2), args.value(1), args.value(0)));
        r->setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
        m_secretsRequest.reset(r);
        m_secretsRequest->setManager(&m_secretManager);
        connect(m_secretsRequest.data(), &Sailfish::Secrets::Request::statusChanged,
                this, &CommandHelper::secretsRequestStatusChanged);
        m_secretsRequest->startRequest();
    } else if (command == QStringLiteral("--list-keys")) {
        Sailfish::Crypto::StoredKeyIdentifiersRequest *r = new Sailfish::Crypto::StoredKeyIdentifiersRequest;
        r->setStoragePluginName(args.value(0));
        r->setCustomParameters(customs);
        if (args.size() > 1 && args.value(1).size()) {
            r->setProperty("collectionName", args.value(1));
        }
        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--generate-stored-key")) {
        Sailfish::Crypto::Key keyTemplate;
        keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(
                args.value(3), args.value(2), args.value(1)));
        keyTemplate.setAlgorithm(algorithmEnum(args.value(4)));
        keyTemplate.setSize(args.value(5).toInt());

        Sailfish::Crypto::RsaKeyPairGenerationParameters rsakpg;
        if (keyTemplate.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmRsa) {
            rsakpg.setModulusLength(keyTemplate.size());
        }

        Sailfish::Crypto::EcKeyPairGenerationParameters eckpg;
        if (keyTemplate.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmEc) {
            if (keyTemplate.size() <= 256) {
                eckpg.setEllipticCurve(Sailfish::Crypto::CryptoManager::CurveNistP256);
                keyTemplate.setSize(256);
            } else if (keyTemplate.size() <= 384){
                eckpg.setEllipticCurve(Sailfish::Crypto::CryptoManager::CurveNistP384);
                keyTemplate.setSize(384);
            } else {
                eckpg.setEllipticCurve(Sailfish::Crypto::CryptoManager::CurveNistP521);
                keyTemplate.setSize(521);
            }
        }

        Sailfish::Crypto::InteractionParameters uiParams;
        uiParams.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
        uiParams.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);

        Sailfish::Crypto::GenerateStoredKeyRequest *r = new Sailfish::Crypto::GenerateStoredKeyRequest;
        r->setCryptoPluginName(args.value(0));
        r->setInteractionParameters(uiParams);
        r->setKeyTemplate(keyTemplate);
        r->setCustomParameters(customs);
        if (keyTemplate.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmRsa) {
            r->setKeyPairGenerationParameters(rsakpg);
        } else if (keyTemplate.algorithm() == Sailfish::Crypto::CryptoManager::AlgorithmEc) {
            r->setKeyPairGenerationParameters(eckpg);
        }

        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--derive-stored-key")) {
        const QString saltDataFile = args.value(6);
        if (saltDataFile.isEmpty()
                || !QFile::exists(saltDataFile)) {
            qInfo() << "Invalid salt data file specified!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        QFile saltFile(saltDataFile);
        if (!saltFile.open(QIODevice::ReadOnly)) {
            qInfo() << "Unable to open salt data file for reading!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray saltData = saltFile.read(16);
        if (saltData.size() < 16) {
            qInfo() << "Unable to read at least 16 bytes of salt data from salt file!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        Sailfish::Crypto::KeyDerivationParameters kdp;
        kdp.setKeyDerivationFunction(Sailfish::Crypto::CryptoManager::KdfPkcs5Pbkdf2);
        kdp.setKeyDerivationMac(Sailfish::Crypto::CryptoManager::MacHmac);
        kdp.setKeyDerivationDigestFunction(Sailfish::Crypto::CryptoManager::DigestSha512);
        kdp.setIterations(16384);
        kdp.setSalt(saltData);
        kdp.setOutputKeySize(args.value(5).toInt());

        Sailfish::Crypto::Key keyTemplate;
        keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(
                args.value(3), args.value(2), args.value(1)));
        keyTemplate.setAlgorithm(algorithmEnum(args.value(4)));
        keyTemplate.setSize(args.value(5).toInt());

        Sailfish::Crypto::InteractionParameters uiParams;
        uiParams.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
        uiParams.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);

        Sailfish::Crypto::GenerateStoredKeyRequest *r = new Sailfish::Crypto::GenerateStoredKeyRequest;
        r->setCryptoPluginName(args.value(0));
        r->setInteractionParameters(uiParams);
        r->setKeyTemplate(keyTemplate);
        r->setKeyDerivationParameters(kdp);
        r->setCustomParameters(customs);

        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--import-stored-key")) {
        const QString importDataFile = args.value(4);
        if (importDataFile.isEmpty()
                || !QFile::exists(importDataFile)) {
            qInfo() << "Invalid import data file specified!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        QFile importFile(importDataFile);
        if (!importFile.open(QIODevice::ReadOnly)) {
            qInfo() << "Unable to open import data file for reading!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        if (importFile.size() > (1024 * 1024)) {
            qInfo() << "Unable to import file - too large!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray importData = importFile.readAll();
        if (importData.isEmpty()) {
            qInfo() << "Empty file or unable to read data from import file!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        Sailfish::Crypto::Key keyTemplate;
        keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(
                args.value(3), args.value(2), args.value(1)));
        keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationSign
                                 |Sailfish::Crypto::CryptoManager::OperationVerify
                                 |Sailfish::Crypto::CryptoManager::OperationEncrypt
                                 |Sailfish::Crypto::CryptoManager::OperationDecrypt);
        keyTemplate.setComponentConstraints(Sailfish::Crypto::Key::MetaData
                                           |Sailfish::Crypto::Key::PublicKeyData);

        Sailfish::Crypto::InteractionParameters uiParams;
        uiParams.setInputType(Sailfish::Crypto::InteractionParameters::AlphaNumericInput);
        uiParams.setEchoMode(Sailfish::Crypto::InteractionParameters::NormalEcho);

        Sailfish::Crypto::ImportStoredKeyRequest *r = new Sailfish::Crypto::ImportStoredKeyRequest;
        r->setCryptoPluginName(args.value(0));
        r->setInteractionParameters(uiParams);
        r->setKeyTemplate(keyTemplate);
        r->setData(importData);
        r->setCustomParameters(customs);

        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--delete-key")) {
        Sailfish::Crypto::DeleteStoredKeyRequest *r = new Sailfish::Crypto::DeleteStoredKeyRequest;
        r->setIdentifier(Sailfish::Crypto::Key::Identifier(
                args.value(2), args.value(1), args.value(0)));
        r->setCustomParameters(customs);
        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--sign")) {
        const QString signFileName = args.value(5);
        if (signFileName.isEmpty()
                || !QFile::exists(signFileName)) {
            qInfo() << "Invalid filename specified!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        QFile signFile(signFileName);
        if (!signFile.open(QIODevice::ReadOnly)) {
            qInfo() << "Unable to open file for reading!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray signData = signFile.readAll();
        if (signData.isEmpty()) {
            qInfo() << "Unable to read data from file!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        Sailfish::Crypto::SignRequest *r = new Sailfish::Crypto::SignRequest;
        r->setKey(Sailfish::Crypto::Key(
                        args.value(3), args.value(2), args.value(1)));
        r->setCryptoPluginName(args.value(0));
        r->setPadding(Sailfish::Crypto::CryptoManager::SignaturePaddingNone);
        r->setDigestFunction(digestEnum(args.value(4)));
        r->setData(signData);
        r->setCustomParameters(customs);
        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--verify")) {
        const QString verifyFileName = args.value(5);
        if (verifyFileName.isEmpty()
                || !QFile::exists(verifyFileName)) {
            qInfo() << "Invalid filename specified!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        QFile verifyFile(verifyFileName);
        if (!verifyFile.open(QIODevice::ReadOnly)) {
            qInfo() << "Unable to open file for reading!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray verifyData = verifyFile.readAll();
        if (verifyData.isEmpty()) {
            qInfo() << "Unable to read data from file!";
            emitFinished(EXITCODE_FAILED);
            return;
        }
        const QString signatureFileName = args.value(6);
        if (signatureFileName.isEmpty()
                || !QFile::exists(signatureFileName)) {
            qInfo() << "Invalid filename specified!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        QFile signatureFile(signatureFileName);
        if (!signatureFile.open(QIODevice::ReadOnly)) {
            qInfo() << "Unable to open signature file for reading!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray signatureData = signatureFile.readAll();
        if (signatureData.isEmpty()) {
            qInfo() << "Unable to read data from signature file!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        Sailfish::Crypto::VerifyRequest *r = new Sailfish::Crypto::VerifyRequest;
        r->setKey(Sailfish::Crypto::Key(
                        args.value(3), args.value(2), args.value(1)));
        r->setCryptoPluginName(args.value(0));
        r->setPadding(Sailfish::Crypto::CryptoManager::SignaturePaddingNone);
        r->setDigestFunction(digestEnum(args.value(4)));
        r->setData(verifyData);
        r->setSignature(signatureData);
        r->setCustomParameters(customs);
        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--encrypt")) {
        const QString encryptFileName = args.value(4);
        if (encryptFileName.isEmpty()
                || !QFile::exists(encryptFileName)) {
            qInfo() << "Invalid filename specified!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        QFile encryptFile(encryptFileName);
        if (!encryptFile.open(QIODevice::ReadOnly)) {
            qInfo() << "Unable to open file for reading!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray encryptData = encryptFile.readAll();
        if (encryptData.isEmpty()) {
            qInfo() << "Unable to read data from file!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        // Assume that the key is an AES key.
        // (A better alternative is to first read the key metadata
        // using a StoredKeyRequest, determining its algorithm etc,
        // and then generating the appropriate IV using that info...)
        Sailfish::Crypto::GenerateInitializationVectorRequest ivr;
        ivr.setManager(&m_cryptoManager);
        ivr.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
        ivr.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
        ivr.setCryptoPluginName(args.value(0));
        ivr.setKeySize(256); // for AES the IV size is 16 bytes, independent of key size.
        ivr.setCustomParameters(customs);
        ivr.startRequest();
        ivr.waitForFinished();

        Sailfish::Crypto::EncryptRequest *r = new Sailfish::Crypto::EncryptRequest;
        r->setKey(Sailfish::Crypto::Key(
                            args.value(3), args.value(2), args.value(1)));
        r->setCryptoPluginName(args.value(0));
        r->setPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
        r->setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
        r->setData(encryptData);
        r->setInitializationVector(ivr.generatedInitializationVector());
        r->setCustomParameters(customs);
        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else if (command == QStringLiteral("--decrypt")) {
        const QString decryptFileName = args.value(4);
        if (decryptFileName.isEmpty()
                || !QFile::exists(decryptFileName)) {
            qInfo() << "Invalid filename specified!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        QFile decryptFile(decryptFileName);
        if (!decryptFile.open(QIODevice::ReadOnly)) {
            qInfo() << "Unable to open file for reading!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray encodedData = decryptFile.readAll();
        if (encodedData.isEmpty()) {
            qInfo() << "Unable to read data from file!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QList<QByteArray> chunks = encodedData.split('\n');
        if (chunks.size() < 2 || !chunks.first().startsWith("IV:")) {
            qInfo() << "Encrypted data file has unknown format!";
            emitFinished(EXITCODE_FAILED);
            return;
        }

        const QByteArray iv = QByteArray::fromBase64(chunks.first().mid(3, -1));
        QByteArray decryptData;
        for (int i = 1; i < chunks.size(); ++i) {
            decryptData.append(QByteArray::fromBase64(chunks.at(i)));
        }

        Sailfish::Crypto::DecryptRequest *r = new Sailfish::Crypto::DecryptRequest;
        r->setKey(Sailfish::Crypto::Key(
                            args.value(3), args.value(2), args.value(1)));
        r->setCryptoPluginName(args.value(0));
        r->setPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
        r->setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
        r->setData(decryptData);
        r->setInitializationVector(iv);
        r->setCustomParameters(customs);
        m_cryptoRequest.reset(r);
        m_cryptoRequest->setManager(&m_cryptoManager);
        connect(m_cryptoRequest.data(), &Sailfish::Crypto::Request::statusChanged,
                this, &CommandHelper::cryptoRequestStatusChanged);
        m_cryptoRequest->startRequest();
    } else {
        qInfo() << "Unknown command:" << command;
        emitFinished(EXITCODE_FAILED);
    }
}

void CommandHelper::secretsRequestStatusChanged()
{
    if (m_secretsRequest->status() != Sailfish::Secrets::Request::Finished) {
        return; // not finished yet, ignore.
    } else if (m_secretsRequest->result().code() != Sailfish::Secrets::Result::Succeeded) {
        qInfo() << "Error:" << m_secretsRequest->result().errorCode() << m_secretsRequest->result().errorMessage();
        emitFinished(static_cast<int>(m_secretsRequest->result().errorCode()));
        return;
    }

    if (m_command == QStringLiteral("--list-collections")) {
        Sailfish::Secrets::CollectionNamesRequest *r = qobject_cast<Sailfish::Secrets::CollectionNamesRequest*>(m_secretsRequest.data());
        qInfo() << "Collections in" << r->storagePluginName();
        for (const QString &cname : r->collectionNames()) {
            qInfo() << "\t" << cname;
        }
    } else if (m_command == QStringLiteral("--get-standalone-secret")) {
        Sailfish::Secrets::StoredSecretRequest *r = qobject_cast<Sailfish::Secrets::StoredSecretRequest*>(m_secretsRequest.data());
        qInfo() << "Got standalone secret data:";
        qInfo() << "\t" << r->secret().data();
    } else if (m_command == QStringLiteral("--get-collection-secret")) {
        Sailfish::Secrets::StoredSecretRequest *r = qobject_cast<Sailfish::Secrets::StoredSecretRequest*>(m_secretsRequest.data());
        qInfo() << "Got collection secret data:";
        qInfo() << "\t" << r->secret().data();
    }

    emitFinished(EXITCODE_SUCCESS);
}

void CommandHelper::cryptoRequestStatusChanged()
{
    if (m_cryptoRequest->status() != Sailfish::Crypto::Request::Finished) {
        return; // not finished yet, ignore.
    } else if (m_cryptoRequest->result().code() != Sailfish::Crypto::Result::Succeeded) {
        qInfo() << "Error:" << m_cryptoRequest->result().errorCode() << m_cryptoRequest->result().errorMessage();
        emitFinished(static_cast<int>(m_cryptoRequest->result().errorCode()));
        return;
    }

    if (m_command == QStringLiteral("--list-keys")) {
        Sailfish::Crypto::StoredKeyIdentifiersRequest *r = qobject_cast<Sailfish::Crypto::StoredKeyIdentifiersRequest*>(m_cryptoRequest.data());
        const QString collectionName = r->property("collectionName").toString();
        for (const Sailfish::Crypto::Key::Identifier &id : r->identifiers()) {
            if (collectionName.isEmpty() || id.collectionName() == collectionName) {
                qInfo() << "--------------------------------------------";
                qInfo() << "Storage plugin:" << id.storagePluginName();
                qInfo() << "    Collection:" << id.collectionName();
                qInfo() << "          Name:" << id.name();
            }
        }
    } else if (m_command == QStringLiteral("--sign")) {
        Sailfish::Crypto::SignRequest *r = qobject_cast<Sailfish::Crypto::SignRequest*>(m_cryptoRequest.data());
        QFile stdoutFile;
        stdoutFile.open(stdout, QIODevice::WriteOnly, QFile::AutoCloseHandle);
        stdoutFile.write(r->signature());
    } else if (m_command == QStringLiteral("--verify")) {
        Sailfish::Crypto::VerifyRequest *r = qobject_cast<Sailfish::Crypto::VerifyRequest*>(m_cryptoRequest.data());
        if (r->verificationStatus() == Sailfish::Crypto::CryptoManager::VerificationSucceeded) {
            qInfo() << "Verification SUCCEEDED!";
        } else {
            qInfo() << "Verification FAILED!";
        }
    } else if (m_command == QStringLiteral("--encrypt")) {
        Sailfish::Crypto::EncryptRequest *r =qobject_cast<Sailfish::Crypto::EncryptRequest*>(m_cryptoRequest.data());
        QFile stdoutFile;
        stdoutFile.open(stdout, QIODevice::WriteOnly, QFile::AutoCloseHandle);
        stdoutFile.write(QByteArray("IV:") + r->initializationVector().toBase64() + QByteArray("\n"));
        int handled = 0;
        const QByteArray ciphertext = r->ciphertext();
        while (handled < ciphertext.size()) {
            const QByteArray chunk = ciphertext.mid(handled, 32);
            stdoutFile.write(chunk.toBase64() + QByteArray("\n"));
            handled += 32;
        }
    } else if (m_command == QStringLiteral("--decrypt")) {
        Sailfish::Crypto::DecryptRequest *r = qobject_cast<Sailfish::Crypto::DecryptRequest*>(m_cryptoRequest.data());
        QFile stdoutFile;
        stdoutFile.open(stdout, QIODevice::WriteOnly, QFile::AutoCloseHandle);
        stdoutFile.write(r->plaintext());
    }

    emitFinished(EXITCODE_SUCCESS);
}
