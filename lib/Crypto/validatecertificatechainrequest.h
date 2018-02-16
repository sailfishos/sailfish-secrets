/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_VALIDATECERTIFICATECHAINREQUEST_H
#define LIBSAILFISHCRYPTO_VALIDATECERTIFICATECHAINREQUEST_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/request.h"
#include "Crypto/certificate.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>

namespace Sailfish {

namespace Crypto {

class CryptoManager;

class ValidateCertificateChainRequestPrivate;
class SAILFISH_CRYPTO_API ValidateCertificateChainRequest : public Sailfish::Crypto::Request
{
    Q_OBJECT
    Q_PROPERTY(QString cryptoPluginName READ cryptoPluginName WRITE setCryptoPluginName NOTIFY cryptoPluginNameChanged)
    Q_PROPERTY(QVector<Sailfish::Crypto::Certificate> certificateChain READ certificateChain WRITE setCertificateChain NOTIFY certificateChainChanged)
    Q_PROPERTY(bool validated READ validated NOTIFY validatedChanged)

public:
    ValidateCertificateChainRequest(QObject *parent = Q_NULLPTR);
    ~ValidateCertificateChainRequest();

    QString cryptoPluginName() const;
    void setCryptoPluginName(const QString &name);

    QVector<Sailfish::Crypto::Certificate> certificateChain() const;
    void setCertificateChain(const QVector<Sailfish::Crypto::Certificate> &chain);

    bool validated() const;

    Sailfish::Crypto::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result result() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::CryptoManager *manager() const Q_DECL_OVERRIDE;
    void setManager(Sailfish::Crypto::CryptoManager *manager) Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void cryptoPluginNameChanged();
    void certificateChainChanged();
    void validatedChanged();

private:
    QScopedPointer<ValidateCertificateChainRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(ValidateCertificateChainRequest)
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_VALIDATECERTIFICATECHAINREQUEST_H
