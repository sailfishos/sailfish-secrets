/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_PLUGININFO_P_H
#define LIBSAILFISHSECRETS_PLUGININFO_P_H

#include "Secrets/result.h"

#include <QtCore/QString>
#include <QtCore/QSharedData>

namespace Sailfish {

namespace Secrets {

class PluginInfoPrivate : public QSharedData
{
public:
    PluginInfoPrivate();
    PluginInfoPrivate(const PluginInfoPrivate &other);
    ~PluginInfoPrivate();

    QString m_name;
    int m_version;
};

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_PLUGININFO_P_H
