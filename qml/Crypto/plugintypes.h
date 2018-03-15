/*
 * Copyright (C) 2018 Jolla Ltd.
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
#include "Crypto/validatecertificatechainrequest.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/generatestoredkeyrequest.h"
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

public:
    CryptoManager(QObject *parent = Q_NULLPTR);
    ~CryptoManager();

    // QML API - allow clients to construct "uncreatable" value types
    Q_INVOKABLE Result constructResult() const;
    Q_INVOKABLE Key constructKey() const;
};

} // Plugin

} // Crypto

} // Sailfish

#endif // SAILFISHCRYPTO_QML_PLUGINTYPES_H
