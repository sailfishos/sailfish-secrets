/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/request.h"

#include <QtCore/QObject>

using namespace Sailfish::Crypto;

/*!
 * \class Request
 * \brief Base-class of specific crypto service requests.
 */

/*!
 * \brief Construct a new Request object with the given \a parent
 */
Request::Request(QObject *parent)
    : QObject(parent)
{
}

/*!
 * \brief Destroys the Request
 */
Request::~Request()
{
}

/*!
 * \enum Request::Status
 *
 * This enum defines the possible states of a Request object
 *
 * \value Inactive The Request is inactive and has not been started
 * \value Active The Request is active and currently being processed
 * \value Finished The Request has been completed
 */

/*!
 * \fn Request::setManager(CryptoManager *manager)
 * \brief Sets the manager through which the request interfaces to the system crypto service to \a manager
 */

/*!
 * \fn Request::manager() const
 * \brief Returns the manager through which the request interfaces to the system crypto service
 */

/*!
 * \fn Request::setCustomParameters(const QVariantMap &params)
 * \brief Sets plugin-specific custom parameters associated with the request to \a params
 *
 * Note that in most cases, custom parameters set by the client will be ignored,
 * unless the plugin they are requesting functionality from specifically requires
 * a parameter to be passed via the custom parameters.  Plugins must document
 * any such requirements, in their user documentation.
 */

/*!
 * \fn Request::customParameters() const
 * \brief Returns the plugin-specific custom parameters associated with the request
 */

/*!
 * \fn Request::status() const
 * \brief Returns the current status of the Request
 */

/*!
 * \fn Request::result() const
 * \brief Returns the result of the Request
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 */

/*!
 * \fn Request::startRequest()
 * \brief Starts the request
 */

/*!
 * \fn Request::waitForFinished()
 * \brief Blocks the current thread of execution until the status of the request is Request::Finished.
 *
 * Note: this method is generally unsafe and should be avoided.
 */

/*!
 * \signal Request::statusChanged()
 * \brief This signal is emitted whenever the status of the request is changed
 */

/*!
 * \signal Request::resultChanged()
 * \brief This signal is emitted whenever the result of the request is changed
 */
