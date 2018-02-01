/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/findsecretsrequest.h"
#include "Secrets/findsecretsrequest_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Secrets;

FindSecretsRequestPrivate::FindSecretsRequestPrivate(SecretManager *manager)
    : m_manager(manager)
    , m_userInteractionMode(SecretManager::PreventInteraction)
    , m_status(Request::Inactive)
{
}

/*!
 * \class FindSecretsRequest
 * \brief Allows a client find the identifiers of secrets which match a specific filter
 *        from the system's secure secret storage service
 */

/*!
 * \brief Constructs a new FindSecretsRequest object which interfaces to the system
 *        crypto service via the given \a manager, with the given \a parent.
 */
FindSecretsRequest::FindSecretsRequest(SecretManager *manager, QObject *parent)
    : Request(parent)
    , d_ptr(new FindSecretsRequestPrivate(manager))
{
}

/*!
 * \brief Destroys the FindSecretsRequest
 */
FindSecretsRequest::~FindSecretsRequest()
{
}

/*!
 * \brief Returns the name of the collection that the client wishes to search for secrets matching some filter
 */
QString FindSecretsRequest::collectionName() const
{
    Q_D(const FindSecretsRequest);
    return d->m_collectionName;
}

/*!
 * \brief Sets the name of the collection that the client wishes to search for secrets matching some filter to \a name
 *
 * Note: if the \a name is empty, then standalone secrets will be searched instead.
 */
void FindSecretsRequest::setCollectionName(const QString &name)
{
    Q_D(FindSecretsRequest);
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
 * \brief Returns the filter which will be used when searching for matching secrets
 */
Sailfish::Secrets::Secret::FilterData FindSecretsRequest::filter() const
{
    Q_D(const FindSecretsRequest);
    return d->m_filter;
}

/*!
 * \brief Sets the filter which will be used when searching for matching secrets to \a filter
 *
 * The filter consists of key/value pairs which will be matched according to the
 * specified filterOperation().
 */
void FindSecretsRequest::setFilter(const Sailfish::Secrets::Secret::FilterData &filter)
{
    Q_D(FindSecretsRequest);
    if (d->m_status != Request::Active && d->m_filter != filter) {
        d->m_filter = filter;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit filterChanged();
    }
}

/*!
 * \brief Returns the filter operator which will be used when searching for matching secrets
 */
Sailfish::Secrets::SecretManager::FilterOperator FindSecretsRequest::filterOperator() const
{
    Q_D(const FindSecretsRequest);
    return d->m_filterOperator;
}

/*!
 * \brief Sets the filter operator which will be used when searching for matching secrets to \a op
 *
 * If the filter operator is AND then all keys must exist in the filter data stored for the secret,
 * and all values for those keys must match the values specified in the input filter.
 *
 * If the filter operator is OR then at least one of the keys must exist in the filter data stored
 * for the secret, where that key's value must match the value specified for that key in the
 * input filter.
 */
void FindSecretsRequest::setFilterOperator(Sailfish::Secrets::SecretManager::FilterOperator op)
{
    Q_D(FindSecretsRequest);
    if (d->m_status != Request::Active && d->m_filterOperator != op) {
        d->m_filterOperator = op;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit filterOperatorChanged();
    }
}

/*!
 * \brief Returns the user interaction mode required when filtering the secrets (e.g. if a custom lock code must be requested from the user)
 */
SecretManager::UserInteractionMode FindSecretsRequest::userInteractionMode() const
{
    Q_D(const FindSecretsRequest);
    return d->m_userInteractionMode;
}

/*!
 * \brief Sets the user interaction mode required when filtering the secrets (e.g. if a custom lock code must be requested from the user) to \a mode
 */
void FindSecretsRequest::setUserInteractionMode(SecretManager::UserInteractionMode mode)
{
    Q_D(FindSecretsRequest);
    if (d->m_status != Request::Active && d->m_userInteractionMode != mode) {
        d->m_userInteractionMode = mode;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit userInteractionModeChanged();
    }
}

/*!
 * \brief Returns the identifiers of secrets which matched the filter.
 */
QVector<Secret::Identifier> FindSecretsRequest::identifiers() const
{
    Q_D(const FindSecretsRequest);
    return d->m_identifiers;
}

Request::Status FindSecretsRequest::status() const
{
    Q_D(const FindSecretsRequest);
    return d->m_status;
}

Result FindSecretsRequest::result() const
{
    Q_D(const FindSecretsRequest);
    return d->m_result;
}

void FindSecretsRequest::startRequest()
{
    Q_D(FindSecretsRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QVector<Secret::Identifier> > reply;
        if (d->m_collectionName.isEmpty()) {
            reply = d->m_manager->findSecrets(d->m_filter,
                                              d->m_filterOperator,
                                              d->m_userInteractionMode);
        } else {
            reply = d->m_manager->findSecrets(d->m_collectionName,
                                              d->m_filter,
                                              d->m_filterOperator,
                                              d->m_userInteractionMode);
        }

        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_identifiers = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit identifiersChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QVector<Secret::Identifier> > reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_identifiers = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->identifiersChanged();
            });
        }
    }
}

void FindSecretsRequest::waitForFinished()
{
    Q_D(FindSecretsRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
