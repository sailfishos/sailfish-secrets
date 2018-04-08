/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_IMPORTKEYREQUEST_H
#define LIBSAILFISHCRYPTO_IMPORTKEYREQUEST_H

#include "Crypto/cryptoglobal.h"
#include "Crypto/request.h"
#include "Crypto/key.h"
#include "Crypto/interactionparameters.h"

#include <QtCore/QObject>
#include <QtCore/QScopedPointer>
#include <QtCore/QString>

namespace Sailfish {

namespace Crypto {

class CryptoManager;

class ImportKeyRequestPrivate;
class SAILFISH_CRYPTO_API ImportKeyRequest : public Sailfish::Crypto::Request
{
    Q_OBJECT
    Q_PROPERTY(QString cryptoPluginName READ cryptoPluginName WRITE setCryptoPluginName NOTIFY cryptoPluginNameChanged)
    Q_PROPERTY(Sailfish::Crypto::InteractionParameters interactionParameters READ interactionParameters WRITE setInteractionParameters NOTIFY interactionParametersChanged)
    Q_PROPERTY(Sailfish::Crypto::Key key READ key WRITE setKey NOTIFY keyChanged)
    Q_PROPERTY(Sailfish::Crypto::Key importedKey READ importedKey NOTIFY importedKeyChanged)

public:
    ImportKeyRequest(QObject *parent = Q_NULLPTR);
    ~ImportKeyRequest();

    QString cryptoPluginName() const;
    void setCryptoPluginName(const QString &pluginName);

    Sailfish::Crypto::InteractionParameters interactionParameters() const;
    void setInteractionParameters(const Sailfish::Crypto::InteractionParameters &uiParams);

    Sailfish::Crypto::Key key() const;
    void setKey(const Sailfish::Crypto::Key &key);

    Sailfish::Crypto::Key importedKey() const;

    Sailfish::Crypto::Request::Status status() const Q_DECL_OVERRIDE;
    Sailfish::Crypto::Result result() const Q_DECL_OVERRIDE;

    Sailfish::Crypto::CryptoManager *manager() const Q_DECL_OVERRIDE;
    void setManager(Sailfish::Crypto::CryptoManager *manager) Q_DECL_OVERRIDE;

    void startRequest() Q_DECL_OVERRIDE;
    void waitForFinished() Q_DECL_OVERRIDE;

Q_SIGNALS:
    void cryptoPluginNameChanged();
    void interactionParametersChanged();
    void keyChanged();
    void importedKeyChanged();

private:
    QScopedPointer<ImportKeyRequestPrivate> const d_ptr;
    Q_DECLARE_PRIVATE(ImportKeyRequest)
};

} // namespace Crypto

} // namespace Sailfish

#endif // LIBSAILFISHCRYPTO_GENERATEKEYREQUEST_H
