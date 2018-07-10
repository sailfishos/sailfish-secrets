/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "plugin.h"

#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif
#include "gpgme.h"

Sailfish::Crypto::Daemon::Plugins::SMimePlugin::SMimePlugin(QObject *parent)
: QObject(parent)
    , GnuPGPlugin(GPGME_PROTOCOL_CMS)
    , GnuPGStoragePlugin(GPGME_PROTOCOL_CMS)
{
}

Sailfish::Crypto::Daemon::Plugins::SMimePlugin::~SMimePlugin()
{
}
