/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_STOREDKEYREQUEST_H
#define LIBSAILFISHCRYPTO_STOREDKEYREQUEST_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/request.h"
#include "Crypto/key.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>

namespace Sailfish {

namespace Crypto {

class CryptoManager;

class StoredKeyRequestPrivate;
class SAILFISH_CRYPTO_API StoredKeyRequest : public Sailfish::Crypto::Request
{
    Q_OBJECT
    Q_PROPERTY(Sailfish::Crypto::Key::Identifier identifier READ identifier NOTIFY identifierChanged)
    Q_PROPERTY(KeyComponents keyComponents READ keyComponents WRITE setKeyComponents NOTIFY keyComponentsChanged)
    Q_PROPERTY(Sailfish::Crypto::Key storedKey READ storedKey NOTIFY storedKeyChanged)

public:
    enum KeyComponent {
        NoData          = 0,
        MetaData        = 1,
        PublicKeyData   = 2,
        SecretKeyData   = 4
    };
    Q_DECLARE_FLAGS(KeyComponents, KeyComponent)
    Q_FLAG(KeyComponents)

    StoredKeyRequest(QObject *parent = Q_NULLPTR);
    ~StoredKeyRequest();

    Sailfish::Crypto::Key::Identifier identifier() const;
    void setIdentifier(const Sailfish::Crypto::Key::Identifier &ident);

    KeyComponents keyComponents() const;
    void setKeyComponents(KeyComponents components);

    Sailfish::Crypto::Key storedKey() const;

    Sailfish::Crypto::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result result() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::CryptoManager *manager() const Q_DECL_OVERRIDE;
    void setManager(Sailfish::Crypto::CryptoManager *manager) Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void identifierChanged();
    void keyComponentsChanged();
    void storedKeyChanged();

private:
    QScopedPointer<StoredKeyRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(StoredKeyRequest)
};

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::StoredKeyRequest::KeyComponent);
Q_DECLARE_METATYPE(Sailfish::Crypto::StoredKeyRequest::KeyComponents);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::StoredKeyRequest::KeyComponents);

#endif // LIBSAILFISHCRYPTO_STOREDKEYREQUEST_H
