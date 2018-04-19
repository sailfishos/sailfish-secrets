/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISH_SECRETS_TOOL_COMMANDHELPER_H
#define SAILFISH_SECRETS_TOOL_COMMANDHELPER_H

#include <QtCore/QObject>
#include <QtCore/QStringList>
#include <QtCore/QString>
#include <QtCore/QScopedPointer>

#include <Secrets/secretmanager.h>
#include <Secrets/request.h>

#include <Crypto/cryptomanager.h>
#include <Crypto/request.h>

class CommandHelper : public QObject
{
    Q_OBJECT

public:
    CommandHelper(bool autotestMode, QObject *parent = Q_NULLPTR);
    void start(const QString &command, const QStringList &args);
    int exitCode() const;

public Q_SLOTS:
    void secretsRequestStatusChanged();
    void cryptoRequestStatusChanged();

Q_SIGNALS:
    void finished();

private:
    void emitFinished(int exitCode);
    QScopedPointer<Sailfish::Secrets::Request> m_secretsRequest;
    QScopedPointer<Sailfish::Crypto::Request> m_cryptoRequest;
    Sailfish::Secrets::SecretManager m_secretManager;
    Sailfish::Crypto::CryptoManager m_cryptoManager;
    QStringList m_authenticationPlugins;
    QStringList m_encryptionPlugins;
    QStringList m_storagePlugins;
    QStringList m_encryptedStoragePlugins;
    QStringList m_cryptoStoragePlugins;
    QStringList m_cryptoPlugins;
    QString m_command;
    int m_step;
    int m_exitCode;
    bool m_autotestMode;
};

#endif // SAILFISH_SECRETS_TOOL_COMMANDHELPER_H
