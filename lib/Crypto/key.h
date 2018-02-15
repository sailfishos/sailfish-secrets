/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_KEY_H
#define LIBSAILFISHCRYPTO_KEY_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/cryptomanager.h"
#include "Crypto/certificate.h"

#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QVector>
#include <QtCore/QHash>
#include <QtCore/QMap>
#include <QtCore/QSharedDataPointer>
#include <QtCore/QMetaType>

namespace Sailfish {

namespace Crypto {

class KeyPrivate;
class KeyIdentifierPrivate;
class SAILFISH_CRYPTO_API Key
{
    Q_GADGET
    Q_PROPERTY(QString name READ name WRITE setName)
    Q_PROPERTY(QString collectionName READ collectionName WRITE setCollectionName)
    Q_PROPERTY(Origin origin READ origin WRITE setOrigin)
    Q_PROPERTY(Sailfish::Crypto::CryptoManager::Algorithm algorithm READ algorithm WRITE setAlgorithm)
    Q_PROPERTY(Sailfish::Crypto::CryptoManager::Operations operations READ operations WRITE setOperations)
    Q_PROPERTY(Sailfish::Crypto::Key::Components componentConstraints READ componentConstraints WRITE setComponentConstraints)
    Q_PROPERTY(int keySize READ keySize WRITE setKeySize)
    Q_PROPERTY(QByteArray publicKey READ publicKey WRITE setPublicKey)
    Q_PROPERTY(QByteArray privateKey READ privateKey WRITE setPrivateKey)
    Q_PROPERTY(QByteArray secretKey READ secretKey WRITE setSecretKey)
    Q_PROPERTY(QVector<QByteArray> customParameters READ customParameters WRITE setCustomParameters)

public:
    enum Origin {
        OriginUnknown       = 0,
        OriginImported, // do we need a link to the certificate chain?  or backend handles this?
        OriginDevice,
        OriginSecureDevice
    };
    Q_ENUM(Origin)

    enum Component {
        NoData          = 0,
        MetaData        = 1,
        PublicKeyData   = 2,
        PrivateKeyData  = 4,
        SecretKeyData   = PrivateKeyData
    };
    Q_ENUM(Component)
    Q_DECLARE_FLAGS(Components, Component)
    Q_FLAG(Components)

    class Identifier {
    public:
        Identifier();
        explicit Identifier(const QString &name, const QString &collectionName = QString());
        Identifier(const Sailfish::Crypto::Key::Identifier &other);
        ~Identifier();

        Identifier &operator=(const Sailfish::Crypto::Key::Identifier &other);
        bool operator==(const Sailfish::Crypto::Key::Identifier &other) const;
        bool operator!=(const Sailfish::Crypto::Key::Identifier &other) const {
            return !operator==(other);
        }

        QString name() const;
        void setName(const QString &name);
        QString collectionName() const;
        void setCollectionName(const QString &collectionName);
    private:
        QSharedDataPointer<KeyIdentifierPrivate> d_ptr;
        friend class KeyIdentifierPrivate;
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

    Sailfish::Crypto::Key& operator=(const Sailfish::Crypto::Key &other);
    bool operator==(const Sailfish::Crypto::Key &other) const;
    bool operator!=(const Sailfish::Crypto::Key &other) const {
        return !operator==(other);
    }

    Sailfish::Crypto::Key::Identifier identifier() const;
    void setIdentifier(const Sailfish::Crypto::Key::Identifier &identifier);

    QString name() const { return identifier().name(); }
    void setName(const QString &name) { setIdentifier(Identifier(name, collectionName())); }
    QString collectionName() const { return identifier().collectionName(); }
    void setCollectionName(const QString &collectionName) { setIdentifier(Identifier(name(), collectionName)); }

    Sailfish::Crypto::Key::Origin origin() const;
    void setOrigin(Sailfish::Crypto::Key::Origin origin);

    Sailfish::Crypto::CryptoManager::Algorithm algorithm() const;
    void setAlgorithm(Sailfish::Crypto::CryptoManager::Algorithm algorithm);

    Sailfish::Crypto::CryptoManager::Operations operations() const;
    void setOperations(Sailfish::Crypto::CryptoManager::Operations operations);

    Sailfish::Crypto::Key::Components componentConstraints() const;
    void setComponentConstraints(Sailfish::Crypto::Key::Components components);

    int keySize() const;
    void setKeySize(int size);

    QByteArray publicKey() const;
    void setPublicKey(const QByteArray &key);

    QByteArray privateKey() const;
    void setPrivateKey(const QByteArray &key);

    QByteArray secretKey() const;
    void setSecretKey(const QByteArray &key);

    QVector<QByteArray> customParameters() const;
    void setCustomParameters(const QVector<QByteArray> &parameters);

    Sailfish::Crypto::Key::FilterData filterData() const;
    void setFilterData(const Sailfish::Crypto::Key::FilterData &data);
    QStringList filterDataFields() const;
    Q_INVOKABLE QString filterData(const QString &field) const;
    Q_INVOKABLE void setFilterData(const QString &field, const QString &value);
    Q_INVOKABLE bool hasFilterData(const QString &field);

    enum SerialisationMode {
        LossySerialisationMode = 0, // don't serialise filter data or identifier, reduce known-plaintext surface.
        LosslessSerialisationMode
    };
    static QByteArray serialise(const Sailfish::Crypto::Key &key, SerialisationMode serialisationMode = LosslessSerialisationMode);
    static Sailfish::Crypto::Key deserialise(const QByteArray &data, bool *ok = nullptr);
    static Sailfish::Crypto::Key fromCertificate(const Sailfish::Crypto::Certificate &certificate);

protected:
    QSharedDataPointer<KeyPrivate> d_ptr;
    friend class KeyPrivate;
};

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::Key);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::Key, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Identifier);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::Key::Identifier, Q_MOVABLE_TYPE);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::FilterData);
Q_DECLARE_TYPEINFO(Sailfish::Crypto::Key::FilterData, Q_MOVABLE_TYPE);

Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Origin);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Component);
Q_DECLARE_METATYPE(Sailfish::Crypto::Key::Components);
Q_DECLARE_OPERATORS_FOR_FLAGS(Sailfish::Crypto::Key::Components);

bool operator<(const Sailfish::Crypto::Key &lhs, const Sailfish::Crypto::Key &rhs);
bool operator<(const Sailfish::Crypto::Key::Identifier &lhs, const Sailfish::Crypto::Key::Identifier &rhs);

#endif // LIBSAILFISHCRYPTO_KEY_H
