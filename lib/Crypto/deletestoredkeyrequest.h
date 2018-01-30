/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_DELETESTOREDKEYREQUEST_H
#define LIBSAILFISHCRYPTO_DELETESTOREDKEYREQUEST_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/request.h"
#include "Crypto/key.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>

namespace Sailfish {

namespace Crypto {

class Certificate;
class CryptoManager;

class DeleteStoredKeyRequestPrivate;
class SAILFISH_CRYPTO_API DeleteStoredKeyRequest : public Sailfish::Crypto::Request
{
    Q_OBJECT
    Q_PROPERTY(Sailfish::Crypto::Key::Identifier identifier READ identifier NOTIFY identifierChanged)

public:
    DeleteStoredKeyRequest(Sailfish::Crypto::CryptoManager *manager, QObject *parent = Q_NULLPTR);
    ~DeleteStoredKeyRequest();

    Sailfish::Crypto::Key::Identifier identifier() const;
    void setIdentifier(const Sailfish::Crypto::Key::Identifier &ident);

    Sailfish::Crypto::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result result() const Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void identifierChanged();

private:
    QScopedPointer<DeleteStoredKeyRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(DeleteStoredKeyRequest)
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_DELETESTOREDKEYREQUEST_H
