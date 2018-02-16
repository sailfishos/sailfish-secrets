/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_PLUGININFOREQUEST_H
#define LIBSAILFISHCRYPTO_PLUGININFOREQUEST_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/request.h"
#include "Crypto/extensionplugins.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>
#include <QtCore/QVector>
#include <QtCore/QStringList>

namespace Sailfish {

namespace Crypto {

class CryptoManager;

class PluginInfoRequestPrivate;
class SAILFISH_CRYPTO_API PluginInfoRequest : public Sailfish::Crypto::Request
{
    Q_OBJECT
    Q_PROPERTY(QVector<Sailfish::Crypto::CryptoPluginInfo> cryptoPlugins READ cryptoPlugins NOTIFY cryptoPluginsChanged)
    Q_PROPERTY(QStringList storagePlugins READ storagePlugins NOTIFY storagePluginsChanged)

public:
    PluginInfoRequest(QObject *parent = Q_NULLPTR);
    ~PluginInfoRequest();

    QVector<Sailfish::Crypto::CryptoPluginInfo> cryptoPlugins() const;
    QStringList storagePlugins() const;

    Sailfish::Crypto::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result result() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::CryptoManager *manager() const Q_DECL_OVERRIDE;
    void setManager(Sailfish::Crypto::CryptoManager *manager) Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void cryptoPluginsChanged();
    void storagePluginsChanged();

private:
    QScopedPointer<PluginInfoRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(PluginInfoRequest)
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_PLUGININFOREQUEST_H
