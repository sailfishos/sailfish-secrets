/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "inprocessinteractionview.h"
#include "inprocessinteractionview_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/result.h"
#include "Secrets/interactionrequest.h"

#include <QtQml/QQmlComponent>
#include <QtQml/QQmlContext>
#include <QtQml/QQmlEngine>

#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsInteractionView, "org.sailfishos.secrets.interaction.view")

Sailfish::Secrets::Plugin::InProcessInteractionView::InProcessInteractionView(QQuickItem *parent)
    : QQuickItem(parent), Sailfish::Secrets::InteractionView()
    , m_childItem(Q_NULLPTR)
    , m_adapter(new Sailfish::Secrets::Plugin::InProcessInteractionViewPrivate(this))
{
}

Sailfish::Secrets::Plugin::InProcessInteractionView::~InProcessInteractionView()
{
    if (m_childItem) {
        m_childItem->setParentItem(Q_NULLPTR);
        m_childItem->deleteLater();
    }
}

QObject *Sailfish::Secrets::Plugin::InProcessInteractionView::adapter() const
{
    return m_adapter;
}

void Sailfish::Secrets::Plugin::InProcessInteractionView::setSecretManager(QObject *manager)
{
    Sailfish::Secrets::SecretManager *secretManager = qobject_cast<Sailfish::Secrets::SecretManager*>(manager);
    if (secretManager) {
        m_adapter->m_secretManager = secretManager;
        Sailfish::Secrets::InteractionView::registerWithSecretManager(secretManager);
        emit secretManagerChanged();
    }
}

QObject *Sailfish::Secrets::Plugin::InProcessInteractionView::secretManager() const
{
    return qobject_cast<QObject*>(m_adapter->m_secretManager);
}

void Sailfish::Secrets::Plugin::InProcessInteractionView::parentSizeChanged()
{
    QQuickItem *parent = parentItem();
    if (parent) {
        setWidth(parent->width());
        setHeight(parent->height());
    }
}

void Sailfish::Secrets::Plugin::InProcessInteractionView::performRequest(const Sailfish::Secrets::InteractionRequest &request)
{
    if (request.type() == Sailfish::Secrets::InteractionRequest::InvalidRequest) {
        qCWarning(lcSailfishSecretsInteractionView) << "InProcessInteractionView unable to perform invalid request!";
        Sailfish::Secrets::Result result(Sailfish::Secrets::Result::InteractionViewRequestError,
                                         QStringLiteral("Unable to perform invalid request"));
        Sailfish::Secrets::InteractionResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Sailfish::Secrets::Result, result),
                                  Q_ARG(Sailfish::Secrets::InteractionResponse, response));
        return;
    }

    QQuickItem *parent = parentItem();
    if (!parent) {
        qCWarning(lcSailfishSecretsInteractionView) << "Error creating in-process ui view: invalid parent item";
        Sailfish::Secrets::Result result(Sailfish::Secrets::Result::InteractionViewParentError,
                                         QStringLiteral("Invalid parent item, view cannot be shown"));
        Sailfish::Secrets::InteractionResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Sailfish::Secrets::Result, result),
                                  Q_ARG(Sailfish::Secrets::InteractionResponse, response));
        return;
    }

    // fill the parent item
    setHeight(parent->height());
    setWidth(parent->width());
    connect(parent, &QQuickItem::widthChanged, this, &InProcessInteractionView::parentSizeChanged);
    connect(parent, &QQuickItem::heightChanged, this, &InProcessInteractionView::parentSizeChanged);

    // create the in-process view as a child item
    QUrl sourceUrl = request.interactionViewQmlFileUrl().isEmpty()
            ? QUrl(QStringLiteral("qrc:/defaultInteractionView.qml"))
            : QUrl::fromLocalFile(request.interactionViewQmlFileUrl());
    m_adapter->setRequestType(request.type());

    qCDebug(lcSailfishSecretsInteractionView) << "Creating InProcessInteractionView with source url:" << sourceUrl;
    QQmlComponent *component = new QQmlComponent(qmlEngine(parent), sourceUrl, parent);
    if (!component->errors().isEmpty()) {
        qCWarning(lcSailfishSecretsInteractionView) << "Error creating in-process ui view:" << component->errors();
        Sailfish::Secrets::Result result(Sailfish::Secrets::Result::InteractionViewError,
                                         QStringLiteral("QML file failed to compile: %1").arg(component->errors().first().toString()));
        Sailfish::Secrets::InteractionResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Sailfish::Secrets::Result, result),
                                  Q_ARG(Sailfish::Secrets::InteractionResponse, response));
        return;
    } else {
        QObject *childObject = component->beginCreate(qmlContext(parent));
        m_childItem = qobject_cast<QQuickItem*>(childObject);
        if (!m_childItem) {
            qCWarning(lcSailfishSecretsInteractionView) << "Error creating in-process ui view child item:" << component->errors();
            Sailfish::Secrets::Result result(Sailfish::Secrets::Result::InteractionViewChildError,
                                             QStringLiteral("Could not instantiate QML child item"));
            Sailfish::Secrets::InteractionResponse response;
            QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                      Q_ARG(Sailfish::Secrets::Result, result),
                                      Q_ARG(Sailfish::Secrets::InteractionResponse, response));
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

void Sailfish::Secrets::Plugin::InProcessInteractionView::continueRequest(const Sailfish::Secrets::InteractionRequest &request)
{
    // TODO
    Q_UNUSED(request)
}

void Sailfish::Secrets::Plugin::InProcessInteractionView::cancelRequest()
{
    if (m_childItem) {
        m_childItem->deleteLater();
        m_childItem = 0;
    }
    emit cancelled();
}

void Sailfish::Secrets::Plugin::InProcessInteractionView::finishRequest()
{
    if (m_childItem) {
        m_childItem->deleteLater();
        m_childItem = 0;
    }
    emit finished();
}


Sailfish::Secrets::Plugin::InProcessInteractionViewPrivate::InProcessInteractionViewPrivate(InProcessInteractionView *parent)
    : QObject(parent)
    , m_parent(parent)
    , m_secretManager(Q_NULLPTR)
    , m_requestType(Sailfish::Secrets::InteractionRequest::InvalidRequest)
    , m_confirmation(Sailfish::Secrets::Plugin::InProcessInteractionView::Unknown)
    , m_ready(false)
{
}

void Sailfish::Secrets::Plugin::InProcessInteractionViewPrivate::sendResponse(bool confirmed)
{
    Sailfish::Secrets::Result result(Sailfish::Secrets::Result::Succeeded);
    Sailfish::Secrets::InteractionResponse response(static_cast<Sailfish::Secrets::InteractionRequest::Type>(requestType()));
    response.setConfirmation(confirmed);
    QMetaObject::invokeMethod(m_parent, "sendResponseHelper", Qt::QueuedConnection,
                              Q_ARG(Sailfish::Secrets::Result, result),
                              Q_ARG(Sailfish::Secrets::InteractionResponse, response));
}

void Sailfish::Secrets::Plugin::InProcessInteractionViewPrivate::sendResponse(const QByteArray &authenticationKey)
{
    Sailfish::Secrets::Result result(Sailfish::Secrets::Result::Succeeded);
    Sailfish::Secrets::InteractionResponse response(static_cast<Sailfish::Secrets::InteractionRequest::Type>(requestType()));
    response.setAuthenticationKey(authenticationKey);
    QMetaObject::invokeMethod(m_parent, "sendResponseHelper", Qt::QueuedConnection,
                              Q_ARG(Sailfish::Secrets::Result, result),
                              Q_ARG(Sailfish::Secrets::InteractionResponse, response));
}

// Helper slot which can be invoked via QueuedConnection.
void Sailfish::Secrets::Plugin::InProcessInteractionView::sendResponseHelper(
        const Sailfish::Secrets::Result &error,
        const Sailfish::Secrets::InteractionResponse &response)
{
    Sailfish::Secrets::InteractionView::sendResponse(error, response);
}

