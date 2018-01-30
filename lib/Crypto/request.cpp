/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/request.h"

#include <QtCore/QObject>

using namespace Sailfish::Crypto;

Request::Request(QObject *parent)
    : QObject(parent)
{
}

Request::~Request()
{
}
