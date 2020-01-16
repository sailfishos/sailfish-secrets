/*
 * Copyright (C) 2018 - 2020 Jolla Ltd.
 * Copyright (C) 2020 Open Mobile Platform LLC.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_QML_PLUGINTYPES_H
#define SAILFISHCRYPTO_QML_PLUGINTYPES_H

#include "Crypto/result.h"
#include "Crypto/key.h"
#include "Crypto/cryptomanager.h"

#include "Crypto/plugininforequest.h"
#include "Crypto/seedrandomdatageneratorrequest.h"
#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/generatestoredkeyrequest.h"
#include "Crypto/importkeyrequest.h"
#include "Crypto/importstoredkeyrequest.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/deletestoredkeyrequest.h"
#include "Crypto/storedkeyidentifiersrequest.h"
#include "Crypto/encryptrequest.h"
#include "Crypto/decryptrequest.h"
#include "Crypto/calculatedigestrequest.h"
#include "Crypto/signrequest.h"
#include "Crypto/verifyrequest.h"
#include "Crypto/cipherrequest.h"

#include <QQmlExtensionPlugin>
#include <QQmlParserStatus>
#include <QQmlEngine>

namespace Sailfish {

namespace Crypto {

namespace Plugin {

class CryptoPlugin : public QQmlExtensionPlugin
{
    Q_OBJECT
    Q_PLUGIN_METADATA(IID "Sailfish.Crypto")

public:
    void initializeEngine(QQmlEngine *, const char *);
    virtual void registerTypes(const char *uri);
};

class CryptoManager : public Sailfish::Crypto::CryptoManager
{
    Q_OBJECT
    Q_PROPERTY(QString defaultCryptoPluginName READ defaultCryptoPluginName CONSTANT)
    Q_PROPERTY(QString defaultCryptoStoragePluginName READ defaultCryptoStoragePluginName CONSTANT)

public:
    CryptoManager(QObject *parent = Q_NULLPTR);
    virtual ~CryptoManager() Q_DECL_OVERRIDE;

    // QML API - make static members accessible
    QString defaultCryptoPluginName() const { return DefaultCryptoPluginName; }
    QString defaultCryptoStoragePluginName() const { return DefaultCryptoStoragePluginName; }

    // QML API - allow clients to construct "uncreatable" value types
    Q_INVOKABLE Sailfish::Crypto::Result constructResult() const;
    Q_INVOKABLE Sailfish::Crypto::Key constructKey() const;
    Q_INVOKABLE Sailfish::Crypto::Key constructKey(const QString &name,
                                 const QString &collectionName,
                                 const QString &storagePluginName) const;
    Q_INVOKABLE Sailfish::Crypto::Key::Identifier
        constructIdentifier(const QString &name,
                            const QString &collectionName,
                            const QString &storagePluginName) const;
    Q_INVOKABLE QVariant constructRsaKeygenParams() const;
    Q_INVOKABLE QVariant constructRsaKeygenParams(const QVariantMap &args) const;

    Q_INVOKABLE QVariant constructEcKeygenParams() const;
    Q_INVOKABLE QVariant constructEcKeygenParams(const QVariantMap &args) const;

    Q_INVOKABLE QVariant constructDsaKeygenParams() const;
    Q_INVOKABLE QVariant constructDsaKeygenParams(const QVariantMap &args) const;

    Q_INVOKABLE QVariant constructDhKeygenParams() const;
    Q_INVOKABLE QVariant constructDhKeygenParams(const QVariantMap &args) const;
};

} // Plugin

} // Crypto

} // Sailfish

#endif // SAILFISHCRYPTO_QML_PLUGINTYPES_H
