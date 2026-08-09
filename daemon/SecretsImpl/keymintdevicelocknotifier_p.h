/*
 * Copyright (C) 2026 Jolla Mobile Ltd
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_KEYMINTDEVICELOCKNOTIFIER_P_H
#define SAILFISHSECRETS_KEYMINTDEVICELOCKNOTIFIER_P_H

#include "devicelockbrokerclient_p.h"

#include <QtCore/QString>

namespace Sailfish {
namespace Crypto {
class KeyMintOperationExtension;
}
namespace Secrets {
namespace Daemon {
namespace ApiImpl {

class KeyMintDeviceLockNotifier
{
public:
    KeyMintDeviceLockNotifier();

    void setProvider(Sailfish::Crypto::KeyMintOperationExtension *provider);
    bool startup(QString *errorMessage = Q_NULLPTR);
    bool brokerUnavailable(QString *errorMessage = Q_NULLPTR);
    bool stateChanged(const DeviceLockBrokerClient::State &state,
                      bool *identityChanged = Q_NULLPTR,
                      QString *errorMessage = Q_NULLPTR);
    bool lifecycleEvent(DeviceLockBrokerClient::LifecycleEvent event,
                        QString *errorMessage = Q_NULLPTR);

private:
    bool notifyLocked(bool passwordOnly, QString *errorMessage);
    bool updateAuthenticationState(quint64 secureUserId,
                                   quint64 fingerprintAuthenticatorId,
                                   QString *errorMessage);

    Sailfish::Crypto::KeyMintOperationExtension *m_provider;
    DeviceLockBrokerClient::State m_state;
    bool m_haveState;
    bool m_lockRetryRequired;
    bool m_stateRetryRequired;
};

} // namespace ApiImpl
} // namespace Daemon
} // namespace Secrets
} // namespace Sailfish

#endif // SAILFISHSECRETS_KEYMINTDEVICELOCKNOTIFIER_P_H
