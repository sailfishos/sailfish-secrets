/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_CIPHERREQUEST_H
#define LIBSAILFISHCRYPTO_CIPHERREQUEST_H

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

class CipherRequestPrivate;
class SAILFISH_CRYPTO_API CipherRequest : public Sailfish::Crypto::Request
{
    Q_OBJECT
    Q_PROPERTY(CipherMode cipherMode READ cipherMode WRITE setCipherMode NOTIFY cipherModeChanged)
    Q_PROPERTY(Key::Operation operation READ operation WRITE setOperation NOTIFY operationChanged)
    Q_PROPERTY(QByteArray data READ data WRITE setData NOTIFY dataChanged)
    Q_PROPERTY(QByteArray initialisationVector READ initialisationVector WRITE setInitialisationVector NOTIFY initialisationVectorChanged)
    Q_PROPERTY(Sailfish::Crypto::Key key READ key WRITE setKey NOTIFY keyChanged)
    Q_PROPERTY(Sailfish::Crypto::Key::BlockMode blockMode READ blockMode WRITE setBlockMode NOTIFY blockModeChanged)
    Q_PROPERTY(Sailfish::Crypto::Key::EncryptionPadding encryptionPadding READ encryptionPadding WRITE setEncryptionPadding NOTIFY encryptionPaddingChanged)
    Q_PROPERTY(Sailfish::Crypto::Key::SignaturePadding signaturePadding READ signaturePadding WRITE setSignaturePadding NOTIFY signaturePaddingChanged)
    Q_PROPERTY(Sailfish::Crypto::Key::Digest digest READ digest WRITE setDigest NOTIFY digestChanged)
    Q_PROPERTY(QString cryptoPluginName READ cryptoPluginName WRITE setCryptoPluginName NOTIFY cryptoPluginNameChanged)
    Q_PROPERTY(QByteArray generatedData READ generatedData NOTIFY generatedDataChanged)
    Q_PROPERTY(QByteArray generatedInitialisationVector READ generatedInitialisationVector NOTIFY generatedInitialisationVectorChanged)
    Q_PROPERTY(bool verified READ verified NOTIFY verifiedChanged)

public:
    enum CipherMode {
        InitialiseCipher = 0,
        UpdateCipherAuthentication,
        UpdateCipher,
        FinaliseCipher,
    };
    Q_ENUM(CipherMode)

    CipherRequest(QObject *parent = Q_NULLPTR);
    ~CipherRequest();

    CipherMode cipherMode() const;
    void setCipherMode(CipherMode mode);

    Key::Operation operation() const;
    void setOperation(Key::Operation op);

    QByteArray data() const;
    void setData(const QByteArray &data);

    QByteArray initialisationVector() const;
    void setInitialisationVector(const QByteArray &iv);

    Sailfish::Crypto::Key key() const;
    void setKey(const Sailfish::Crypto::Key &key);

    Sailfish::Crypto::Key::BlockMode blockMode() const;
    void setBlockMode(Sailfish::Crypto::Key::BlockMode mode);

    Sailfish::Crypto::Key::EncryptionPadding encryptionPadding() const;
    void setEncryptionPadding(Sailfish::Crypto::Key::EncryptionPadding padding);

    Sailfish::Crypto::Key::SignaturePadding signaturePadding() const;
    void setSignaturePadding(Sailfish::Crypto::Key::SignaturePadding padding);

    Sailfish::Crypto::Key::Digest digest() const;
    void setDigest(Sailfish::Crypto::Key::Digest digest);

    QString cryptoPluginName() const;
    void setCryptoPluginName(const QString &pluginName);

    QByteArray generatedData() const;
    QByteArray generatedInitialisationVector() const;
    bool verified() const;

    Sailfish::Crypto::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result result() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::CryptoManager *manager() const Q_DECL_OVERRIDE;
    void setManager(Sailfish::Crypto::CryptoManager *manager) Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void cipherModeChanged();
    void operationChanged();
    void dataChanged();
    void initialisationVectorChanged();
    void keyChanged();
    void blockModeChanged();
    void encryptionPaddingChanged();
    void signaturePaddingChanged();
    void digestChanged();
    void cryptoPluginNameChanged();
    void generatedDataChanged();
    void generatedInitialisationVectorChanged();
    void verifiedChanged();

private:
    QScopedPointer<CipherRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(CipherRequest)
};

} // namespace Crypto

} // namespace Sailfish

Q_DECLARE_METATYPE(Sailfish::Crypto::CipherRequest::CipherMode);

#endif // LIBSAILFISHCRYPTO_CIPHERREQUEST_H
