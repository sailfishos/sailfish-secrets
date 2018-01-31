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
