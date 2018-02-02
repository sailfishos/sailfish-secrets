/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/deletecollectionrequest.h"
#include "Secrets/deletecollectionrequest_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Secrets;

DeleteCollectionRequestPrivate::DeleteCollectionRequestPrivate(SecretManager *manager)
    : m_manager(manager)
    , m_userInteractionMode(SecretManager::PreventInteraction)
    , m_status(Request::Inactive)
{
}

/*!
 * \class DeleteCollectionRequest
 * \brief Allows a client request that the system secrets service delete a collection from secrets storage
 *
 * This class allows clients to request the Secrets service to delete a collection
 * with the particular collectionName().
 *
 * If the calling application is the creator of the collection, or alternatively
 * if the user has granted the application permission to delete the collection,
 * then the Secrets service will instruct the storage plugin to delete the
 * collection and any secrets it contains.
 *
 * If the application is not the creator of the collection and the user has not yet
 * been asked if the application should have permission to delete the collection,
 * a system-mediated access control UI flow may be triggered to obtain the user's
 * permission (unless the given \a userInteractionMode is \a PreventInteraction
 * in which case the request will fail).
 *
 * An example of deleting a collection is as follows:
 *
 * \code
 * Sailfish::Secrets::DeleteCollectionRequest dcr(&sm);
 * dcr.setCollectionName(QLatin1String("ExampleCollection"));
 * dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
 * dcr.startRequest(); // status() will change to Finished when complete
 * \endcode
}
\endcode
 */

/*!
 * \brief Constructs a new DeleteCollectionRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
DeleteCollectionRequest::DeleteCollectionRequest(SecretManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new DeleteCollectionRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the DeleteCollectionRequest
 */
DeleteCollectionRequest::~DeleteCollectionRequest()
{
}

/*!
 * \brief Returns the name of the collection which the client wishes delete
 */
QString DeleteCollectionRequest::collectionName() const
{
    Q_D(const DeleteCollectionRequest);
    return d->m_collectionName;
}

/*!
 * \brief Sets the name of the collection which the client wishes to delete to \a name
 */
void DeleteCollectionRequest::setCollectionName(const QString &name)
{
    Q_D(DeleteCollectionRequest);
    if (d->m_status != Request::Active && d->m_collectionName != name) {
        d->m_collectionName = name;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit collectionNameChanged();
    }
}

/*!
 * \brief Returns the user interaction mode required when deleting the collection (e.g. if a custom lock code must be requested from the user)
 */
SecretManager::UserInteractionMode DeleteCollectionRequest::userInteractionMode() const
{
    Q_D(const DeleteCollectionRequest);
    return d->m_userInteractionMode;
}

/*!
 * \brief Sets the user interaction mode required when deleting the collection (e.g. if a custom lock code must be requested from the user) to \a mode
 */
void DeleteCollectionRequest::setUserInteractionMode(SecretManager::UserInteractionMode mode)
{
    Q_D(DeleteCollectionRequest);
    if (d->m_status != Request::Active && d->m_userInteractionMode != mode) {
        d->m_userInteractionMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit userInteractionModeChanged();
    }
}

Request::Status DeleteCollectionRequest::status() const
{
    Q_D(const DeleteCollectionRequest);
    return d->m_status;
}

Result DeleteCollectionRequest::result() const
{
    Q_D(const DeleteCollectionRequest);
    return d->m_result;
}

void DeleteCollectionRequest::startRequest()
{
    Q_D(DeleteCollectionRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result> reply = d->m_manager->d_ptr->deleteCollection(
                                                    d->m_collectionName,
                                                    d->m_userInteractionMode);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            emit statusChanged();
            emit resultChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
            });
        }
    }
}

void DeleteCollectionRequest::waitForFinished()
{
    Q_D(DeleteCollectionRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
