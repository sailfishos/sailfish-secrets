/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_VERIFYREQUEST_H
#define LIBSAILFISHCRYPTO_VERIFYREQUEST_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/request.h"
#include "Crypto/key.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace Sailfish {

namespace Crypto {

class CryptoManager;

class VerifyRequestPrivate;
class SAILFISH_CRYPTO_API VerifyRequest : public Sailfish::Crypto::Request
{
    Q_OBJECT
    Q_PROPERTY(QByteArray data READ data WRITE setData NOTIFY dataChanged)
    Q_PROPERTY(Sailfish::Crypto::Key key READ key WRITE setKey NOTIFY keyChanged)
    Q_PROPERTY(Sailfish::Crypto::Key::SignaturePadding padding READ padding WRITE setPadding NOTIFY paddingChanged)
    Q_PROPERTY(Sailfish::Crypto::Key::Digest digest READ digest WRITE setDigest NOTIFY digestChanged)
    Q_PROPERTY(QString cryptoPluginName READ cryptoPluginName WRITE setCryptoPluginName NOTIFY cryptoPluginNameChanged)
    Q_PROPERTY(bool verified READ verified NOTIFY verifiedChanged)

public:
    VerifyRequest(QObject *parent = Q_NULLPTR);
    ~VerifyRequest();

    QByteArray data() const;
    void setData(const QByteArray &data);

    Sailfish::Crypto::Key key() const;
    void setKey(const Sailfish::Crypto::Key &key);

    Sailfish::Crypto::Key::SignaturePadding padding() const;
    void setPadding(Sailfish::Crypto::Key::SignaturePadding padding);

    Sailfish::Crypto::Key::Digest digest() const;
    void setDigest(Sailfish::Crypto::Key::Digest digest);

    QString cryptoPluginName() const;
    void setCryptoPluginName(const QString &pluginName);

    bool verified() const;

    Sailfish::Crypto::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result result() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::CryptoManager *manager() const Q_DECL_OVERRIDE;
    void setManager(Sailfish::Crypto::CryptoManager *manager) Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void dataChanged();
    void keyChanged();
    void paddingChanged();
    void digestChanged();
    void cryptoPluginNameChanged();
    void verifiedChanged();

private:
    QScopedPointer<VerifyRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(VerifyRequest)
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_VERIFYREQUEST_H
