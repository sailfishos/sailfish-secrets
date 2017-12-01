/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "inprocessuiview.h"
#include "inprocessuiview_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/result.h"
#include "Secrets/uirequest.h"

#include <QtQml/QQmlComponent>
#include <QtQml/QQmlContext>
#include <QtQml/QQmlEngine>

#include <QtCore/QLoggingCategory>

Q_LOGGING_CATEGORY(lcSailfishSecretsUiView, "org.sailfishos.secrets.ui.view")

Sailfish::Secrets::Plugin::InProcessUiView::InProcessUiView(QQuickItem *parent)
    : QQuickItem(parent), Sailfish::Secrets::UiView()
    , m_childItem(Q_NULLPTR)
    , m_adapter(new Sailfish::Secrets::Plugin::InProcessUiViewPrivate(this))
{
}

Sailfish::Secrets::Plugin::InProcessUiView::~InProcessUiView()
{
    if (m_childItem) {
        m_childItem->setParentItem(Q_NULLPTR);
        m_childItem->deleteLater();
    }
}

QObject *Sailfish::Secrets::Plugin::InProcessUiView::adapter() const
{
    return m_adapter;
}

void Sailfish::Secrets::Plugin::InProcessUiView::setSecretManager(QObject *manager)
{
    Sailfish::Secrets::SecretManager *secretManager = qobject_cast<Sailfish::Secrets::SecretManager*>(manager);
    if (secretManager) {
        m_adapter->m_secretManager = secretManager;
        Sailfish::Secrets::UiView::registerWithSecretManager(secretManager);
        emit secretManagerChanged();
    }
}

QObject *Sailfish::Secrets::Plugin::InProcessUiView::secretManager() const
{
    return qobject_cast<QObject*>(m_adapter->m_secretManager);
}

void Sailfish::Secrets::Plugin::InProcessUiView::parentSizeChanged()
{
    QQuickItem *parent = parentItem();
    if (parent) {
        setWidth(parent->width());
        setHeight(parent->height());
    }
}

void Sailfish::Secrets::Plugin::InProcessUiView::performRequest(const Sailfish::Secrets::UiRequest &request)
{
    if (request.type() == Sailfish::Secrets::UiRequest::InvalidRequest) {
        qCWarning(lcSailfishSecretsUiView) << "InProcessUiView unable to perform invalid request!";
        Sailfish::Secrets::Result result(Sailfish::Secrets::Result::UiViewRequestError,
                                         QStringLiteral("Unable to perform invalid request"));
        Sailfish::Secrets::UiResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Sailfish::Secrets::Result, result),
                                  Q_ARG(Sailfish::Secrets::UiResponse, response));
        return;
    }

    QQuickItem *parent = parentItem();
    if (!parent) {
        qCWarning(lcSailfishSecretsUiView) << "Error creating in-process ui view: invalid parent item";
        Sailfish::Secrets::Result result(Sailfish::Secrets::Result::UiViewParentError,
                                         QStringLiteral("Invalid parent item, view cannot be shown"));
        Sailfish::Secrets::UiResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Sailfish::Secrets::Result, result),
                                  Q_ARG(Sailfish::Secrets::UiResponse, response));
        return;
    }

    // fill the parent item
    setHeight(parent->height());
    setWidth(parent->width());
    connect(parent, &QQuickItem::widthChanged, this, &InProcessUiView::parentSizeChanged);
    connect(parent, &QQuickItem::heightChanged, this, &InProcessUiView::parentSizeChanged);

    // create the in-process view as a child item
    QUrl sourceUrl = request.uiViewQmlFileUrl().isEmpty()
            ? QUrl(QStringLiteral("qrc:/defaultUiView.qml"))
            : QUrl::fromLocalFile(request.uiViewQmlFileUrl());
    m_adapter->setRequestType(request.type());

    qCDebug(lcSailfishSecretsUiView) << "Creating InProcessUiView with source url:" << sourceUrl;
    QQmlComponent *component = new QQmlComponent(qmlEngine(parent), sourceUrl, parent);
    if (!component->errors().isEmpty()) {
        qCWarning(lcSailfishSecretsUiView) << "Error creating in-process ui view:" << component->errors();
        Sailfish::Secrets::Result result(Sailfish::Secrets::Result::UiViewError,
                                         QStringLiteral("QML file failed to compile: %1").arg(component->errors().first().toString()));
        Sailfish::Secrets::UiResponse response;
        QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                  Q_ARG(Sailfish::Secrets::Result, result),
                                  Q_ARG(Sailfish::Secrets::UiResponse, response));
        return;
    } else {
        QObject *childObject = component->beginCreate(qmlContext(parent));
        m_childItem = qobject_cast<QQuickItem*>(childObject);
        if (!m_childItem) {
            qCWarning(lcSailfishSecretsUiView) << "Error creating in-process ui view child item:" << component->errors();
            Sailfish::Secrets::Result result(Sailfish::Secrets::Result::UiViewChildError,
                                             QStringLiteral("Could not instantiate QML child item"));
            Sailfish::Secrets::UiResponse response;
            QMetaObject::invokeMethod(this, "sendResponseAsync", Qt::QueuedConnection,
                                      Q_ARG(Sailfish::Secrets::Result, result),
                                      Q_ARG(Sailfish::Secrets::UiResponse, response));
            return;
        } else {
            qCDebug(lcSailfishSecretsUiView) << "Successfully created in-process child item with parent:"
                                                << this << "and embed parent:" << this->parent();
            m_childItem->setParent(this);
            m_childItem->setParentItem(this);
            qmlEngine(parent)->rootContext()->setContextProperty("adapter", m_adapter);
            component->completeCreate();
        }
    }
}

void Sailfish::Secrets::Plugin::InProcessUiView::continueRequest(const Sailfish::Secrets::UiRequest &request)
{
    // TODO
    Q_UNUSED(request)
}

void Sailfish::Secrets::Plugin::InProcessUiView::cancelRequest()
{
    if (m_childItem) {
        m_childItem->deleteLater();
        m_childItem = 0;
    }
    emit cancelled();
}

void Sailfish::Secrets::Plugin::InProcessUiView::finishRequest()
{
    if (m_childItem) {
        m_childItem->deleteLater();
        m_childItem = 0;
    }
    emit finished();
}


Sailfish::Secrets::Plugin::InProcessUiViewPrivate::InProcessUiViewPrivate(InProcessUiView *parent)
    : QObject(parent)
    , m_parent(parent)
    , m_secretManager(Q_NULLPTR)
    , m_requestType(Sailfish::Secrets::UiRequest::InvalidRequest)
    , m_confirmation(Sailfish::Secrets::Plugin::InProcessUiView::Unknown)
    , m_ready(false)
{
}

void Sailfish::Secrets::Plugin::InProcessUiViewPrivate::sendResponse(bool confirmed)
{
    Sailfish::Secrets::Result result(Sailfish::Secrets::Result::Succeeded);
    Sailfish::Secrets::UiResponse response(static_cast<Sailfish::Secrets::UiRequest::Type>(requestType()));
    response.setConfirmation(confirmed);
    QMetaObject::invokeMethod(m_parent, "sendResponseHelper", Qt::QueuedConnection,
                              Q_ARG(Sailfish::Secrets::Result, result),
                              Q_ARG(Sailfish::Secrets::UiResponse, response));
}

void Sailfish::Secrets::Plugin::InProcessUiViewPrivate::sendResponse(const QByteArray &authenticationKey)
{
    Sailfish::Secrets::Result result(Sailfish::Secrets::Result::Succeeded);
    Sailfish::Secrets::UiResponse response(static_cast<Sailfish::Secrets::UiRequest::Type>(requestType()));
    response.setAuthenticationKey(authenticationKey);
    QMetaObject::invokeMethod(m_parent, "sendResponseHelper", Qt::QueuedConnection,
                              Q_ARG(Sailfish::Secrets::Result, result),
                              Q_ARG(Sailfish::Secrets::UiResponse, response));
}

// Helper slot which can be invoked via QueuedConnection.
void Sailfish::Secrets::Plugin::InProcessUiView::sendResponseHelper(
        const Sailfish::Secrets::Result &error,
        const Sailfish::Secrets::UiResponse &response)
{
    Sailfish::Secrets::UiView::sendResponse(error, response);
}

