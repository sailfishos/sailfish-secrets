/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin_p.h"

using namespace Sailfish::Secrets;

Daemon::ApiImpl::PluginHelper::PluginHelper(const QString &fileName,
                                            const bool autotestMode,
                                            const QVariantMap &initialisationParameters)
    : QPluginLoader(fileName)
    , m_failureType(NoFailure)
    , m_autotestMode(autotestMode)
    , m_initialisationParameters(initialisationParameters)
{
}

Daemon::ApiImpl::PluginHelper::~PluginHelper()
{
}

Daemon::ApiImpl::PluginHelper::FailureType
Daemon::ApiImpl::PluginHelper::failureType() const
{
    return m_failureType;
}

void Daemon::ApiImpl::PluginHelper::reportFailure(
        const QLoggingCategory &category())
{
    if (m_failureType != PluginLoadFailure
            && m_failureType != PluginTypeFailure) {
        // already reported this error
        return;
    }

    if (!isLoaded()) {
        qCWarning(category) << "cannot load plugin:"
                            << fileName() << errorString();
        return;
    }

    qCWarning(category) << "ignoring plugin:" << fileName()
                        << "- not a valid plugin or Qt version mismatch";
    unload();
}
