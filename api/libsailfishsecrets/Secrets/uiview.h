/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_UIVIEW_H
#define LIBSAILFISHSECRETS_UIVIEW_H

#include "Secrets/secretsglobal.h"
#include "Secrets/result.h"
#include "Secrets/uirequest.h"

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
 *  The UiView interface provides API to trigger or cancel
 *  different types of user interaction.  It is invoked by the
 *  UiService in response to communication from the sailfishsecretsd
 *  process, and it in turn invokes the sendResponse() method
 *  of the UiService when user interaction is complete.
 */
class SecretManager;
class UiService;
class UiViewData;
class SAILFISH_SECRETS_API UiView
{
public:
    UiView();
    virtual ~UiView();

protected:
    void sendResponse(const Sailfish::Secrets::Result &result,
                      const Sailfish::Secrets::UiResponse &response);

    virtual void performRequest(const Sailfish::Secrets::UiRequest &request) = 0;
    virtual void continueRequest(const Sailfish::Secrets::UiRequest &request) = 0;
    virtual void cancelRequest() = 0;
    virtual void finishRequest() = 0;

protected:
    void registerWithSecretManager(SecretManager *manager);
    SecretManager *registeredWithSecretManager() const;

private:
    friend class UiService;
    bool performRequest(QObject *sender, const Sailfish::Secrets::UiRequest &request);
    bool continueRequest(QObject *sender, const Sailfish::Secrets::UiRequest &request);
    bool cancelRequest(QObject *sender);
    bool finishRequest(QObject *sender);
    UiViewData *data;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_UIVIEW_H
