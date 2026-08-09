/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHCRYPTO_KEYMINTBINDERCLIENT_P_H
#define SAILFISHCRYPTO_KEYMINTBINDERCLIENT_P_H

#include <QtCore/QByteArray>
#include <QtCore/QString>

namespace Sailfish {
namespace Crypto {
namespace Daemon {
namespace Plugins {

class KeyMintBinderClient
{
public:
    struct CallResult {
        bool transportSucceeded;
        qint32 keyMintError;
        QString errorMessage;

        CallResult(bool transportSucceeded = false,
                   qint32 keyMintError = -1000,
                   const QString &errorMessage = QString());
        bool succeeded() const;
    };

    KeyMintBinderClient();
    ~KeyMintBinderClient();

    CallResult beginCreateMasterKey(const QByteArray &rootKey,
                                    quint32 sailfishUserId,
                                    quint64 secureUserId,
                                    const QByteArray &identityEpoch,
                                    quint64 *challenge,
                                    QByteArray *operationContext);
    CallResult finishCreateMasterKey(const QByteArray &operationContext,
                                     const QByteArray &serializedHardwareAuthToken,
                                     QByteArray *serializedEnvelope);
    CallResult beginOpenMasterKey(const QByteArray &serializedEnvelope,
                                  quint64 *challenge,
                                  QByteArray *operationContext);
    CallResult finishOpenMasterKey(const QByteArray &operationContext,
                                   const QByteArray &serializedHardwareAuthToken,
                                   QByteArray *rootKey);

    CallResult oneShot(quint32 operation,
                       const QByteArray &request,
                       QByteArray *response);
    CallResult begin(const QByteArray &request,
                     quint64 *operationHandle,
                     QByteArray *response);
    CallResult update(quint64 operationHandle,
                      const QByteArray &request,
                      QByteArray *response);
    CallResult finish(quint64 operationHandle,
                      const QByteArray &request,
                      QByteArray *response);
    CallResult abort(quint64 operationHandle);
    CallResult deviceLocked(bool passwordOnly);
    CallResult setAuthenticationState(quint64 secureUserId,
                                      quint64 fingerprintAuthenticatorId);

private:
    Q_DISABLE_COPY(KeyMintBinderClient)
    class Private;
    Private *d;
};

} // namespace Plugins
} // namespace Daemon
} // namespace Crypto
} // namespace Sailfish

#endif // SAILFISHCRYPTO_KEYMINTBINDERCLIENT_P_H
