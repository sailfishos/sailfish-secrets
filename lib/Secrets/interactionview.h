/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_INTERACTIONVIEW_H
#define LIBSAILFISHSECRETS_INTERACTIONVIEW_H

#include "Secrets/secretsglobal.h"
#include "Secrets/result.h"
#include "Secrets/interactionrequest.h"

#include <QtDBus/QDBusServer>
#include <QtDBus/QDBusContext>
#include <QtDBus/QDBusConnection>
#include <QtDBus/QDBusInterface>
#include <QtDBus/QDBusMessage>
#include <QtDBus/QDBusPendingCallWatcher>

#include <QtCore/QObject>
#include <QtCore/QVariantMap>
#include <QtCore/QList>
#include <QtCore/QString>

namespace Sailfish {

namespace Secrets {

/*
 *  The InteractionView interface provides API to trigger or cancel
 *  different types of user interaction.  It is invoked by the
 *  InteractionService in response to communication from the sailfishsecretsd
 *  process, and it in turn invokes the sendResponse() method
 *  of the InteractionService when user interaction is complete.
 */
class SecretManager;
class InteractionService;
class InteractionViewData;
class SAILFISH_SECRETS_API InteractionView
{
public:
    InteractionView();
    virtual ~InteractionView();

protected:
    void sendResponse(const Sailfish::Secrets::Result &result,
                      const Sailfish::Secrets::InteractionResponse &response);

    virtual void performRequest(const Sailfish::Secrets::InteractionRequest &request) = 0;
    virtual void continueRequest(const Sailfish::Secrets::InteractionRequest &request) = 0;
    virtual void cancelRequest() = 0;
    virtual void finishRequest() = 0;

protected:
    void registerWithSecretManager(SecretManager *manager);
    SecretManager *registeredWithSecretManager() const;

private:
    friend class InteractionService;
    bool performRequest(QObject *sender, const Sailfish::Secrets::InteractionRequest &request);
    bool continueRequest(QObject *sender, const Sailfish::Secrets::InteractionRequest &request);
    bool cancelRequest(QObject *sender);
    bool finishRequest(QObject *sender);
    InteractionViewData *data;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_INTERACTIONVIEW_H
