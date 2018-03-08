/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Secrets/lockcoderequest.h"
#include "Secrets/lockcoderequest_p.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Secrets;

LockCodeRequestPrivate::LockCodeRequestPrivate()
    : m_lockCodeRequestType(LockCodeRequest::ModifyLockCode)
    , m_userInteractionMode(SecretManager::SystemInteraction)
    , m_status(Request::Inactive)
{
}

/*!
 * \class LockCodeRequest
 * \brief Allows a client to request that the system service either
 *        unlock, lock, or modify the lock code associated with a secret or
 *        collection.
 *
 * \b{Note: most clients will never need to use this class, as the
 * other request types automatically trigger locking and relocking
 * flows as required.}
 *
 * The operation will be applied to the custom-locked collection or
 * standalone secret specified by the \l{collectionName()} or
 * \l{secretName()} parameter respectively.  This operation is only valid for
 * custom-locked collections or secrets, when performed by a non-privileged
 * application.  It is an error to provide both a \l{secretName()} and
 * \l{collectionName()}.
 *
 * If both the collection and secret name are empty, this will be interpreted
 * as a request to modify, provide or forget the master lock code (an
 * operation which is forbidden to all applications other than the system
 * settings application and the device lock daemon).
 *
 * If the \l{lockCodeRequestType()} specified is \l{ModifyLockCode}
 * then the user will be prompted (via a system-mediated user interaction
 * flow) for the current lock code, and if that matches the existing
 * lock code, they will then be prompted for the new lock code.  The
 * datum will then be re-encrypted with a key derived from the new lock code.
 *
 * If the \l{lockCodeRequestType()} specified is \l{ProvideLockCode}
 * then the user will be prompted (via a system-mediated user interaction
 * flow) for the current lock code, which will be used to unlock the datum.
 *
 * If the \l{lockCodeRequestType()} specified is \l{ForgetLockCode}
 * then if the datum is currently unlocked, the user will be prompted (via a
 * system-mediated user interaction flow) for the current lock code, and if
 * it matches the actual lock code, the datum will be locked.
 *
 * An example of modifying the lock code used for a custom-locked collection
 * follows:
 *
 * \code
 * // Require an alpha-numeric lock code to be provided
 * Sailfish::Secrets::InteractionParameters uiParams;
 * uiParams.setInputType(Sailfish::Secrets::InteractionParameters::AlphaNumericInput);
 * uiParams.setEchoMode(Sailfish::Secrets::InteractionParameters::PasswordEcho);
 *
 * // Request that the collection be re-keyed.
 * Sailfish::Secrets::SecretManager sm;
 * Sailfish::Secrets::LockCodeRequest lcr;
 * lcr.setManager(&sm);
 * lcr.setLockCodeRequestType(Sailfish::Secrets::LockCodeRequest::ModifyLockCode);
 * lcr.setCollectionName(QLatin1String("Some custom-locked collection"));
 * lcr.setInteractionParameters(uiParams);
 * lcr.startRequest(); // status() will change to Finished when complete
 * \endcode
 */

/*!
 * \brief Constructs a new LockCodeRequest object with the given \a parent.
 */
LockCodeRequest::LockCodeRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new LockCodeRequestPrivate)
{
}

/*!
 * \brief Destroys the LockCodeRequest
 */
LockCodeRequest::~LockCodeRequest()
{
}

/*!
 * \brief Returns the type of lock code operation being requested
 */
LockCodeRequest::LockCodeRequestType LockCodeRequest::lockCodeRequestType() const
{
    Q_D(const LockCodeRequest);
    return d->m_lockCodeRequestType;
}

/*!
 * \brief Sets the type of lock code operation being requested to \a type
 */
void LockCodeRequest::setLockCodeRequestType(LockCodeRequest::LockCodeRequestType type)
{
    Q_D(LockCodeRequest);
    if (d->m_status != Request::Active && d->m_lockCodeRequestType != type) {
        d->m_lockCodeRequestType = type;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit lockCodeRequestTypeChanged();
    }
}

/*!
 * \brief Returns the user interaction mode required when retrieving lock codes from the user
 */
SecretManager::UserInteractionMode LockCodeRequest::userInteractionMode() const
{
    Q_D(const LockCodeRequest);
    return d->m_userInteractionMode;
}

/*!
 * \brief Sets the user interaction mode required when retrieving lock codes from the user to \a mode
 *
 * This should only (and must be) be set to
 * \l{SecretManager::ApplicationInteraction} if the collection or standalone
 * secret is owned by the caller application and its original user interaction
 * mode was already set to \c{ApplicationInteraction}, otherwise an error will
 * be returned.
 *
 * Note that if \l{interactionParameters()} are provided then the \a mode
 * will be ignored, which may result in an error being returned to the client
 * (that is, if the collection or standalone secret is owned by the caller
 * application and its original user interaction mode was set to
 * \c{ApplicationInteraction}).
 */
void LockCodeRequest::setUserInteractionMode(SecretManager::UserInteractionMode mode)
{
    Q_D(LockCodeRequest);
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
 * \brief Returns the user input parameters which should be used when requesting the secret data from the user
 */
InteractionParameters LockCodeRequest::interactionParameters() const
{
    Q_D(const LockCodeRequest);
    return d->m_interactionParameters;
}

/*!
 * \brief Sets the user input parameters which should be used when requesting the lock code from the user to \a params
 *
 * Note: specifying user input parameters implies that system-mediated user interaction
 * flows are allowed by the calling application, and are required by the collection
 * or standalone secret for which the lock code is being requested.
 */
void LockCodeRequest::setInteractionParameters(const InteractionParameters &params)
{
    Q_D(LockCodeRequest);
    if (d->m_status != Request::Active && d->m_interactionParameters != params) {
        d->m_interactionParameters = params;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit interactionParametersChanged();
    }
}

// TODO: in the future support oldLockCodeInteractionParameters also?
// e.g. to allow changing the type of lock code (from PIN to ALPHANUM, etc)?

/*!
 * \brief Returns the name of the custom-locked standalone secret to which to apply the lock code operation
 */
QString LockCodeRequest::secretName() const
{
    Q_D(const LockCodeRequest);
    return d->m_secretName;
}

/*!
 * \brief Sets the name of the custom-locked standalone secret to which to apply the lock code operation to \a name
 */
void LockCodeRequest::setSecretName(const QString &name)
{
    Q_D(LockCodeRequest);
    if (d->m_status != Request::Active && d->m_secretName != name) {
        d->m_secretName = name;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit secretNameChanged();
    }
}

/*!
 * \brief Returns the name of the custom-locked collection to which to apply the lock code operation
 */
QString LockCodeRequest::collectionName() const
{
    Q_D(const LockCodeRequest);
    return d->m_collectionName;
}

/*!
 * \brief Sets the name of the custom-locked collection to which to apply the lock code operation to \a name
 */
void LockCodeRequest::setCollectionName(const QString &name)
{
    Q_D(LockCodeRequest);
    if (d->m_status != Request::Active && d->m_collectionName != name) {
        d->m_collectionName = name;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit collectionNameChanged();
    }
}

Request::Status LockCodeRequest::status() const
{
    Q_D(const LockCodeRequest);
    return d->m_status;
}

Result LockCodeRequest::result() const
{
    Q_D(const LockCodeRequest);
    return d->m_result;
}

SecretManager *LockCodeRequest::manager() const
{
    Q_D(const LockCodeRequest);
    return d->m_manager.data();
}

void LockCodeRequest::setManager(SecretManager *manager)
{
    Q_D(LockCodeRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void LockCodeRequest::startRequest()
{
    Q_D(LockCodeRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result> reply;
        if (d->m_lockCodeRequestType == LockCodeRequest::ModifyLockCode) {
            reply = d->m_manager->d_ptr->modifyLockCode(d->m_secretName,
                                                          d->m_collectionName,
                                                          d->m_interactionParameters,
                                                          d->m_userInteractionMode);
        } else if (d->m_lockCodeRequestType == LockCodeRequest::ProvideLockCode) {
            reply = d->m_manager->d_ptr->provideLockCode(d->m_secretName,
                                                           d->m_collectionName,
                                                           d->m_interactionParameters,
                                                           d->m_userInteractionMode);
        } else { // ForgetLockCode
            reply = d->m_manager->d_ptr->forgetLockCode(d->m_secretName,
                                                          d->m_collectionName,
                                                          d->m_interactionParameters,
                                                          d->m_userInteractionMode);
        }

        if (!reply.isValid() && !reply.error().message().isEmpty()) {
            d->m_status = Request::Finished;
            d->m_result = Result(Result::SecretManagerNotInitialisedError,
                                 reply.error().message());
            emit statusChanged();
            emit resultChanged();
        } else if (reply.isFinished()
                // work around a bug in QDBusAbstractInterface / QDBusConnection...
                && reply.argumentAt<0>().code() != Sailfish::Secrets::Result::Succeeded) {
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

void LockCodeRequest::waitForFinished()
{
    Q_D(LockCodeRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
