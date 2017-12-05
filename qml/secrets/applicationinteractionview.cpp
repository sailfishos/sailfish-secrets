/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "applicationinteractionview.h"
#include "applicationinteractionview_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/result.h"
#include "Secrets/interactionrequest.h"

#include <QtQml/QQmlComponent>
#include <QtQml/QQmlContext>
#include <QtQml/QQmlEngine>

#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsInteractionView, "org.sailfishos.secrets.interaction.view", QtWarningMsg)

using namespace Sailfish::Secrets;

Plugin::ApplicationInteractionView::ApplicationInteractionView(QQuickItem *parent)
    : QQuickItem(parent), InteractionView()
    , m_childItem(Q_NULLPTR)
    , m_adapter(new Plugin::ApplicationInteractionViewPrivate(this))
{
}

Plugin::ApplicationInteractionView::~ApplicationInteractionView()
{
    if (m_childItem) {
        m_childItem->setParentItem(Q_NULLPTR);
        m_childItem->deleteLater();
    }
}

QObject *Plugin::ApplicationInteractionView::adapter() const
{
    return m_adapter;
}

void Plugin::ApplicationInteractionView::setSecretManager(QObject *manager)
{
    SecretManager *secretManager = qobject_cast<SecretManager*>(manager);
    if (secretManager) {
        m_adapter->m_secretManager = secretManager;
        InteractionView::registerWithSecretManager(secretManager);
        emit secretManagerChanged();
    }
}

QObject *Plugin::ApplicationInteractionView::secretManager() const
{
    return qobject_cast<QObject*>(m_adapter->m_secretManager);
}

void Plugin::ApplicationInteractionView::parentSizeChanged()
{
    QQuickItem *parent = parentItem();
    if (parent) {
        setWidth(parent->width());
        setHeight(parent->height());
    }
}

void Plugin::ApplicationInteractionView::performRequest(const InteractionRequest &request)
{
    if (request.type() == InteractionRequest::InvalidRequest) {
        qCWarning(lcSailfishSecretsInteractionView) << "ApplicationInteractionView unable to perform invalid request!";
        Result result(Result::InteractionViewRequestError,
                                         QStringLiteral("Unable to perform invalid request"));
        InteractionResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Result, result),
                                  Q_ARG(InteractionResponse, response));
        return;
    }

    QQuickItem *parent = parentItem();
    if (!parent) {
        qCWarning(lcSailfishSecretsInteractionView) << "Error creating in-process ui view: invalid parent item";
        Result result(Result::InteractionViewParentError,
                                         QStringLiteral("Invalid parent item, view cannot be shown"));
        InteractionResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Result, result),
                                  Q_ARG(InteractionResponse, response));
        return;
    }

    // fill the parent item
    setHeight(parent->height());
    setWidth(parent->width());
    connect(parent, &QQuickItem::widthChanged, this, &ApplicationInteractionView::parentSizeChanged);
    connect(parent, &QQuickItem::heightChanged, this, &ApplicationInteractionView::parentSizeChanged);

    // create the in-process view as a child item
    QUrl sourceUrl = request.interactionViewQmlFileUrl().isEmpty()
            ? QUrl(QStringLiteral("qrc:/defaultInteractionView.qml"))
            : QUrl::fromLocalFile(request.interactionViewQmlFileUrl());
    m_adapter->setRequestType(request.type());

    qCDebug(lcSailfishSecretsInteractionView) << "Creating ApplicationInteractionView with source url:" << sourceUrl;
    QQmlComponent *component = new QQmlComponent(qmlEngine(parent), sourceUrl, parent);
    if (!component->errors().isEmpty()) {
        qCWarning(lcSailfishSecretsInteractionView) << "Error creating in-process ui view:" << component->errors();
        Result result(Result::InteractionViewError,
                                         QStringLiteral("QML file failed to compile: %1").arg(component->errors().first().toString()));
        InteractionResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Result, result),
                                  Q_ARG(InteractionResponse, response));
        return;
    } else {
        QObject *childObject = component->beginCreate(qmlContext(parent));
        m_childItem = qobject_cast<QQuickItem*>(childObject);
        if (!m_childItem) {
            qCWarning(lcSailfishSecretsInteractionView) << "Error creating in-process ui view child item:" << component->errors();
            Result result(Result::InteractionViewChildError,
                                             QStringLiteral("Could not instantiate QML child item"));
            InteractionResponse response;
            QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                      Q_ARG(Result, result),
                                      Q_ARG(InteractionResponse, response));
            return;
        } else {
            qCDebug(lcSailfishSecretsInteractionView) << "Successfully created in-process child item with parent:"
                                                << this << "and embed parent:" << this->parent();
            m_childItem->setParent(this);
            m_childItem->setParentItem(this);
            qmlEngine(parent)->rootContext()->setContextProperty("adapter", m_adapter);
            component->completeCreate();
        }
    }
}

void Plugin::ApplicationInteractionView::continueRequest(const InteractionRequest &request)
{
    // TODO
    Q_UNUSED(request)
}

void Plugin::ApplicationInteractionView::cancelRequest()
{
    if (m_childItem) {
        m_childItem->deleteLater();
        m_childItem = 0;
    }
    emit cancelled();
}

void Plugin::ApplicationInteractionView::finishRequest()
{
    if (m_childItem) {
        m_childItem->deleteLater();
        m_childItem = 0;
    }
    emit finished();
}


Plugin::ApplicationInteractionViewPrivate::ApplicationInteractionViewPrivate(ApplicationInteractionView *parent)
    : QObject(parent)
    , m_parent(parent)
    , m_secretManager(Q_NULLPTR)
    , m_requestType(InteractionRequest::InvalidRequest)
    , m_confirmation(Plugin::ApplicationInteractionView::Unknown)
    , m_ready(false)
{
}

void Plugin::ApplicationInteractionViewPrivate::sendResponse(bool confirmed)
{
    Result result(Result::Succeeded);
    InteractionResponse response(static_cast<InteractionRequest::Type>(requestType()));
    response.setConfirmation(confirmed);
    QMetaObject::invokeMethod(m_parent, "sendResponseHelper", Qt::QueuedConnection,
                              Q_ARG(Sailfish::Secrets::Result, result),
                              Q_ARG(Sailfish::Secrets::InteractionResponse, response));
}

void Plugin::ApplicationInteractionViewPrivate::sendResponse(const QByteArray &authenticationKey)
{
    Result result(Result::Succeeded);
    InteractionResponse response(static_cast<InteractionRequest::Type>(requestType()));
    response.setAuthenticationKey(authenticationKey);
    QMetaObject::invokeMethod(m_parent, "sendResponseHelper", Qt::QueuedConnection,
                              Q_ARG(Sailfish::Secrets::Result, result),
                              Q_ARG(Sailfish::Secrets::InteractionResponse, response));
}

// Helper slot which can be invoked via QueuedConnection.
void Sailfish::Secrets::Plugin::ApplicationInteractionView::sendResponseHelper(
        const Sailfish::Secrets::Result &error,
        const Sailfish::Secrets::InteractionResponse &response)
{
    Sailfish::Secrets::InteractionView::sendResponse(error, response);
}

