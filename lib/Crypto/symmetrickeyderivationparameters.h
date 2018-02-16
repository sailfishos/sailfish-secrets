/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_SYMMETRICKEYDERIVATIONPARAMETERS_H
#define LIBSAILFISHCRYPTO_SYMMETRICKEYDERIVATIONPARAMETERS_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/key.h"

#include <QtCore/QByteArray>
#include <QtCore/QVariantMap>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QMetaType>

namespace Sailfish {

namespace Crypto {

class SymmetricKeyDerivationParametersPrivate;
class SAILFISH_CRYPTO_API SymmetricKeyDerivationParameters {
    Q_GADGET
    Q_PROPERTY(QByteArray inputData READ inputData WRITE setInputData)
    Q_PROPERTY(QByteArray salt READ salt WRITE setSalt)
    Q_PROPERTY(Sailfish::Crypto::CryptoManager::KeyDerivationFunction keyDerivationFunction READ keyDerivationFunction WRITE setKeyDerivationFunction)
    Q_PROPERTY(Sailfish::Crypto::CryptoManager::MessageAuthenticationCode keyDerivationMac READ keyDerivationMac WRITE setKeyDerivationMac)
    Q_PROPERTY(Sailfish::Crypto::CryptoManager::Algorithm keyDerivationAlgorithm READ keyDerivationAlgorithm WRITE setKeyDerivationAlgorithm)
    Q_PROPERTY(Sailfish::Crypto::CryptoManager::DigestFunction keyDerivationDigestFunction READ keyDerivationDigestFunction WRITE setKeyDerivationDigestFunction)
    Q_PROPERTY(qint64 memorySize READ memorySize WRITE setMemorySize)
    Q_PROPERTY(int iterations READ iterations WRITE setIterations)
    Q_PROPERTY(int parallelism READ parallelism WRITE setParallelism)
    Q_PROPERTY(int outputKeySize READ outputKeySize WRITE setOutputKeySize)
    Q_PROPERTY(QVariantMap customParameters READ customParameters WRITE setCustomParameters)

public:
    SymmetricKeyDerivationParameters();
    SymmetricKeyDerivationParameters(const SymmetricKeyDerivationParameters &other);
    ~SymmetricKeyDerivationParameters();

    SymmetricKeyDerivationParameters& operator=(const SymmetricKeyDerivationParameters &other);
    bool operator==(const SymmetricKeyDerivationParameters &other) const;
    bool operator!=(const SymmetricKeyDerivationParameters &other) const {
        return !operator==(other);
    }

    bool isValid() const;

    QByteArray inputData() const;
    void setInputData(const QByteArray &data);

    QByteArray salt() const;
    void setSalt(const QByteArray &salt);

    Sailfish::Crypto::CryptoManager::KeyDerivationFunction keyDerivationFunction() const;
    void setKeyDerivationFunction(Sailfish::Crypto::CryptoManager::KeyDerivationFunction kdf);

    Sailfish::Crypto::CryptoManager::MessageAuthenticationCode keyDerivationMac() const;
    void setKeyDerivationMac(Sailfish::Crypto::CryptoManager::MessageAuthenticationCode mac);

    Sailfish::Crypto::CryptoManager::Algorithm keyDerivationAlgorithm() const;
    void setKeyDerivationAlgorithm(Sailfish::Crypto::CryptoManager::Algorithm algo);

    Sailfish::Crypto::CryptoManager::DigestFunction keyDerivationDigestFunction() const;
    void setKeyDerivationDigestFunction(Sailfish::Crypto::CryptoManager::DigestFunction func);

    qint64 memorySize() const;
    void setMemorySize(qint64 size);

    int iterations() const;
    void setIterations(int iterations);

    int parallelism() const;
    void setParallelism(int parallelism);

    int outputKeySize() const;
    void setOutputKeySize(int size);

    QVariantMap customParameters() const;
    void setCustomParameters(const QVariantMap &params);

private:
    QSharedDataPointer<SymmetricKeyDerivationParametersPrivate> d_ptr;
    friend class SymmetricKeyDerivationParametersPrivate;
};

} // Crypto

} // Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::SymmetricKeyDerivationParameters);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::SymmetricKeyDerivationParameters, Q_MOVABLE_TYPE);

inline bool operator<(const Sailfish::Crypto::SymmetricKeyDerivationParameters &/*lhs*/, const Sailfish::Crypto::SymmetricKeyDerivationParameters &/*rhs*/)
{
    qWarning("'<' operator not valid for SymmetricKeyDerivationParameters\n");
    return false;
}

#endif // LIBSAILFISHCRYPTO_SYMMETRICKEYDERIVATIONPARAMETERS_H
