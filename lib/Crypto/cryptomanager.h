/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CRYPTOMANAGER_H
#define LIBSAILFISHCRYPTO_CRYPTOMANAGER_H

#include "Crypto/cryptoglobal.h"

#include <QtCore/QObject>
#include <QtCore/QString>

namespace Sailfish {

namespace Crypto {

class CryptoManagerPrivate;
class SAILFISH_CRYPTO_API CryptoManager : public QObject
{
    Q_OBJECT

public:
    static const QString DefaultCryptoPluginName;
    static const QString DefaultCryptoStoragePluginName;

    CryptoManager(QObject *parent = Q_NULLPTR);
    ~CryptoManager();

    bool isInitialised() const;

private:
    QScopedPointer<CryptoManagerPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(CryptoManager)
    friend class CipherRequest;
    friend class DecryptRequest;
    friend class DeleteStoredKeyRequest;
    friend class EncryptRequest;
    friend class GenerateKeyRequest;
    friend class GenerateRandomDataRequest;
    friend class GenerateStoredKeyRequest;
    friend class PluginInfoRequest;
    friend class SeedRandomDataGeneratorRequest;
    friend class SignRequest;
    friend class StoredKeyIdentifiersRequest;
    friend class StoredKeyRequest;
    friend class ValidateCertificateChainRequest;
    friend class VerifyRequest;
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_CRYPTOMANAGER_H
