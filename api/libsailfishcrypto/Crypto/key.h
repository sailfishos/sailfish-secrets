/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_KEY_H
#define LIBSAILFISHCRYPTO_KEY_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/certificate.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QMap>

#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

namespace Sailfish {

namespace Crypto {

// Represents metadata about a key, and optionally the key data
// Do we need subclass for RSA with public exponent etc?
// Do we need subclass for EC curve with affine X / Y etc?
class KeyData;
class SAILFISH_CRYPTO_API Key
{
public:
    enum Origin {
        OriginUnknown       = 0,
        OriginImported, // do we need a link to the certificate chain?  or backend handles this?
        OriginDevice,
        OriginSecureDevice
    };

    // How do we map to/from the Certificate algorithm id name?
    // Can we do, e.g. Rsa2048 with DigestSha256 maps to "sha256WithRSAEncryption"
    // Or do we need an unambiguous one-to-one mapping to Certificate algorithmID?
    // Should we separate keysize from algorithm family?
    enum Algorithm {
        AlgorithmUnknown    = 0,

        Aes128              = 10,
        Aes196,
        Aes256,

        Dsa512              = 20,
        Dsa1024,
        Dsa2048,
        Dsa3072,
        Dsa4096,

        Rsa512              = 30,
        Rsa1028,
        Rsa2048,
        Rsa3072,
        Rsa4096,

        NistEcc192          = 40,
        NistEcc224,
        NistEcc256,
        NistEcc384,
        NistEcc521,

        BpEcc160            = 50,
        BpEcc192,
        BpEcc224,
        BpEcc256,
        BpEcc320,
        BpEcc384,
        BpEcc512
    };

    enum BlockMode {
        BlockModeUnknown    = 0,
        BlockModeCBC        = 1,
        BlockModeCTR        = 2,
        BlockModeECB        = 4,
        BlockModeGCM        = 8
    };
    Q_DECLARE_FLAGS(BlockModes, BlockMode)

    enum EncryptionPadding {
        EncryptionPaddingUnknown    = 0,
        EncryptionPaddingNone       = 1,
        EncryptionPaddingPkcs7      = 2,
        EncryptionPaddingRsaOaep    = 4,
        EncryptionPaddingRsaOaepMgf1= 8,
        EncryptionPaddingRsaPkcs1   = 16,
        EncryptionPaddingAnsiX923   = 32
    };
    Q_DECLARE_FLAGS(EncryptionPaddings, EncryptionPadding)

    enum SignaturePadding {
        SignaturePaddingUnknown     = 0,
        SignaturePaddingNone        = 1,
        SignaturePaddingRsaPss      = 2,
        SignaturePaddingRsaPkcs1    = EncryptionPaddingRsaPkcs1,
        SignaturePaddingAnsiX923    = EncryptionPaddingAnsiX923
    };
    Q_DECLARE_FLAGS(SignaturePaddings, SignaturePadding)

    enum Digest {
        DigestUnknown       = 0,
        DigestSha1          = 1,
        DigestSha256        = 2,
        DigestSha384        = 4,
        DigestSha512        = 8
    };
    Q_DECLARE_FLAGS(Digests, Digest)

    enum Operation {
        OperationUnknown    = 0,
        Sign                = 1,
        Verify              = 2,
        Encrypt             = 4,
        Decrypt             = 8
    };
    Q_DECLARE_FLAGS(Operations, Operation)

    class Identifier {
    public:
        Identifier(const QString &name = QString(), const QString &collectionName = QString())
            : m_name(name), m_collectionName(collectionName) {}
        Identifier(const Sailfish::Crypto::Key::Identifier &other)
            : m_name(other.m_name), m_collectionName(other.m_collectionName) {}
        Identifier(Sailfish::Crypto::Key::Identifier &&) = default;
        Identifier &operator=(const Sailfish::Crypto::Key::Identifier &other) {
            m_name = other.m_name;
            m_collectionName = other.m_collectionName;
            return *this;
        }
        bool operator==(const Sailfish::Crypto::Key::Identifier &other) const {
            return m_name == other.m_name && m_collectionName == other.m_collectionName;
        }
        bool operator<(const Sailfish::Crypto::Key::Identifier &other) const {
            return (m_collectionName < other.m_collectionName) ? true : (m_name < other.m_name);
        }
        QString name() const { return m_name; }
        QString collectionName() const { return m_collectionName; }
        void setName(const QString &name) { m_name = name; }
        void setCollectionName(const QString &collectionName) { m_collectionName = collectionName; }
    private:
        QString m_name;
        QString m_collectionName;
    };

    class FilterData : public QMap<QString,QString> {
    // this exists solely to prevent Qt's metatype system from erroring on duplicate registration
    public:
        FilterData(const QMap<QString,QString> &v) : QMap<QString,QString>(v) {}
        FilterData() = default;
        FilterData(const Sailfish::Crypto::Key::FilterData &) = default;
        FilterData(Sailfish::Crypto::Key::FilterData &&) = default;
        FilterData &operator=(const Sailfish::Crypto::Key::FilterData &) = default;
    };

    Key();
    Key(const Sailfish::Crypto::Key &other);
    explicit Key(const QString &keyName, const QString &collection);
    virtual ~Key();

    Sailfish::Crypto::Key & operator=(const Sailfish::Crypto::Key &other);
    bool operator==(const Sailfish::Crypto::Key &other);
    bool operator<(const Sailfish::Crypto::Key &other);

    Sailfish::Crypto::Key::Identifier identifier() const;
    void setIdentifier(const Sailfish::Crypto::Key::Identifier &identifier);

    Sailfish::Crypto::Key::Origin origin() const;
    void setOrigin(Sailfish::Crypto::Key::Origin origin);

    Sailfish::Crypto::Key::Algorithm algorithm() const;
    void setAlgorithm(Sailfish::Crypto::Key::Algorithm algorithm);

    Sailfish::Crypto::Key::BlockModes blockModes() const;
    void setBlockModes(Sailfish::Crypto::Key::BlockModes modes);

    Sailfish::Crypto::Key::EncryptionPaddings encryptionPaddings() const;
    void setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddings paddings);

    Sailfish::Crypto::Key::SignaturePaddings signaturePaddings() const;
    void setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddings paddings);

    Sailfish::Crypto::Key::Digests digests() const;
    void setDigests(Sailfish::Crypto::Key::Digests digests);

    Sailfish::Crypto::Key::Operations operations() const;
    void setOperations(Sailfish::Crypto::Key::Operations operations);

    // TODO: this might need to be a certificate chain rather than a public key.
    // The public key associated with a certificate is embedded within the certificate.
    // Alternatively, the certificate chain could be entirely separate, and we could have:
    //   -> manager.generateCertificateChain(key, (self signed, or passing in some cert authority data?))
    //   -> manager.verifyCertificateChain(key, certChain)
    //   -> etc.
    QByteArray publicKey() const;
    void setPublicKey(const QByteArray &key);

    QByteArray privateKey() const;
    void setPrivateKey(const QByteArray &key);

    QByteArray secretKey() const;
    void setSecretKey(const QByteArray &key);

    // Then there's the question: is validity period a property of the key, or the certificate?  Or both, separately?
    QDateTime validityStart() const;
    void setValidityStart(const QDateTime &timestamp);

    QDateTime validityEnd() const;
    void setValidityEnd(const QDateTime &timestamp);

    // Another open question: authentication to get access to the ability to perform operations with the key... via storage API?

    QVector<QByteArray> customParameters() const;
    void setCustomParameters(const QVector<QByteArray> &parameters);

    Sailfish::Crypto::Key::FilterData filterData() const;
    QString filterData(const QString &field) const;
    void setFilterData(const Sailfish::Crypto::Key::FilterData &data);
    void setFilterData(const QString &field, const QString &value);
    bool hasFilterData(const QString &field);

    enum SerialisationMode {
        DoNotSerialiseFilterDataMode = 0,
        SerialiseFilterDataMode
    };
    static QByteArray serialise(const Sailfish::Crypto::Key &key, SerialisationMode serialisationMode = SerialiseFilterDataMode);
    static Sailfish::Crypto::Key deserialise(const QByteArray &data, bool *ok = nullptr);
    static Sailfish::Crypto::Key fromCertificate(const Sailfish::Crypto::Certificate &certificate);

protected:
    KeyData *m_data;
};

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key &key) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key &key) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Identifier &identifier) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Identifier &identifier) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::FilterData &filterData) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::FilterData &filterData) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Origin origin) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Origin &origin) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Algorithm algorithm) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Algorithm &algorithm) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::BlockMode mode) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::BlockMode &mode) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::EncryptionPadding padding) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::EncryptionPadding &padding) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::SignaturePadding padding) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::SignaturePadding &padding) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Digest digest) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Digest &digest) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Operation operation) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Operation &operation) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::BlockModes modes) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::BlockModes &modes) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::EncryptionPaddings paddings) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::EncryptionPaddings &paddings) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::SignaturePaddings paddings) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::SignaturePaddings &paddings) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Digests digests) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Digests &digests) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Operations operations) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Operations &operations) SAILFISH_CRYPTO_API;

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::Key);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Identifier);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::Key::Identifier, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::FilterData);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::Key::FilterData, Q_MOVABLE_TYPE);

Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Origin);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Algorithm);

Q_DECLARE_METATYPE(Sailfish::Crypto::Key::BlockMode);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::EncryptionPadding);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::SignaturePadding);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Digest);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Operation);

Q_DECLARE_METATYPE(Sailfish::Crypto::Key::BlockModes);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::EncryptionPaddings);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::SignaturePaddings);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Digests);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Operations);

Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::Key::BlockModes);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::Key::EncryptionPaddings);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::Key::SignaturePaddings);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::Key::Digests);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::Key::Operations);

#endif // LIBSAILFISHCRYPTO_KEY_H
