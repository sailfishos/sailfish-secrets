/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "exampleusbtokenplugin.h"

#include <QStandardPaths>
#include <QString>
#include <QByteArray>

#include <QtDebug>

Q_PLUGIN_METADATA(IID Sailfish_Secrets_EncryptedStoragePlugin_IID)

using namespace Sailfish::Secrets::Daemon::Plugins;

ExampleUsbTokenPlugin::ExampleUsbTokenPlugin(QObject *parent)
    : QObject(parent)
    , m_usbInterface(this)
{
}

ExampleUsbTokenPlugin::~ExampleUsbTokenPlugin()
{
}

bool ExampleUsbTokenPlugin::isLocked() const
{
    return m_usbTokenKey.publicKey().isEmpty();
}

bool ExampleUsbTokenPlugin::setLockCode(const QByteArray &oldLockCode, const QByteArray &newLockCode)
{
    // we don't support changing the lock code in this example.
    Q_UNUSED(oldLockCode)
    Q_UNUSED(newLockCode)
    return false;
}

bool ExampleUsbTokenPlugin::lock()
{
    m_usbTokenKey = Sailfish::Crypto::Key();
    return true;
}

bool ExampleUsbTokenPlugin::unlock(const QByteArray &lockCode)
{
    // This is merely an example.  In a real USB token-backed plugin,
    // this method would pass the lock code to the USB token.

    // The passphrase for the following RSA key.pem is "12345" which must
    // be passed as the lockCode in order for the unlock operation to succeed.
    const QByteArray pemData(
       "-----BEGIN RSA PRIVATE KEY-----\n"
       "Proc-Type: 4,ENCRYPTED\n"
       "DEK-Info: AES-128-CBC,58909F0499FB07748B8159C42B84CA75\n"
       "\n"
       "DJyGd3AQ53uz0mwfuLZ7uQr+7W7TeS54nn7jvBfFS0MtDd5FtaKbir2FurW3fWet\n"
       "HebFzg8fUCrhY+/cGN5WfKjGoCHo5hsKxuKgowoBMwsgnU0khkjQMz3Jw6h6F7KT\n"
       "4SAhI02OPKQZD9g8YBzx4ui+LXpcBLS4pHf5KhY1WMq5CuPzafrqwl3jUdz1Qaiv\n"
       "JBePjlCBEXlUGemDNkNR4lzk8RuCs8kZKZo1iJd3W3YHpBhs9DyErBVbTkpCT7yA\n"
       "ELZ6w28pyFUbFFXm7GXhiokqjSfLFQH3MbPCUKVIbEVkHSP4FqoTDPnBdGlW+Fvq\n"
       "sALyqS9/NTsJ5jXF0CV2gEum4bRMalTyqQhHVihEWkuX8CRpmAP7/eoOjhN+ydVU\n"
       "ggkzxVyXRicpDBzt8r7MjmpO6zwuYmrsRwagaEh+aUokHU+Z++WelFXXai5b1uEO\n"
       "wjRxsjOmPP8R+VhFyyG4VvpzPT3yU4lMav+U3Z7hsaD0UzuJAmxMOMtatl3A6Pt6\n"
       "ME9p/B3ofcE0m1g9EhH7sBo6jMkrgG+pwtkIJ1xMbvYBjCPr2fTzhGgUuTkln1fp\n"
       "XrwNZeYIBhYhZ95imXfzZVEQOyJc8QHS0iJciodJDkbnlwenb2TccWkhJyxtoeF9\n"
       "RBmqJn5bbLjCVHRgmXj7OePAgQiYFoirQ6F/J1eKrVBSgLlR/gsPzqPisIlto9tx\n"
       "GaGsstuq6TLejSa8WEq1HzPaxccjOpR6tA0f2+xc9LweLB7nEnm82EvKFukk5e0i\n"
       "hVe/u6XQWw0FW11Wio2y87437BF93oytlPcHWQyB/fkS7FvMHxfnrnt2ybGbPnTL\n"
       "qODt2g4IziyNQF3PiMJOzYWSJ5JG0L0A8W0FK+Pb9G2jnQBAuPIpRSqQ7yUtBGh0\n"
       "slrxEGapCPZY3mccS1pLEzHBLFEUudWqhaNU8tmeBw48QBLrK2DE+kzr7bzLsdvH\n"
       "b27QEkGWvF+KgPbEqBKC3d9u4z4cWNHYuLRuiaE/2MbxAQ4yGcr4acahm2gjTPZg\n"
       "ajTbk50NZBj0L0AzHusODCssypnREnY/40v0VdIYNBcUf+fbSUXV5LNqblrnf6ra\n"
       "B2pzk+tKqE9QOBYz7HZ3Pkq9GeIVMGKDM71jczw5dFRPY58doU22C9fQzBQuasVn\n"
       "sSUusNkHOm0OM6VX2hXH/lhhZYLgvy5MSzpnSSwTv+4wFa1mzuvUJkyL4SPgZ2Nx\n"
       "XQr1ss88t7qAw0bQeLNmBIbQDVtlhQ3E/5qUuhNY8/P50vt8LmiCXJ/IvGxecJgS\n"
       "NtNAno1XcQ73A8Ri5d1zdu2+4GXkHUrSwVlFMZGmC3cXlO5nA8pkcVLl7vSQmib4\n"
       "tzR2wfVvj1X0W/NYrcnAQ6ooymhpE8yVCKKLw94YABOtiDP89YB4hdtzbfHOsEXP\n"
       "iHZB5uURv2uwE0s0f2zVRt3ryZZoF/Dgc9BD+6wcN8z/uK4ucaXuDmVJW8EX6V5U\n"
       "F3LPsdi3w2rx/pauRNQpTTIFpqtIrogSkTpWmQv3kIM4+Z62Y3X9Cr/61RpTZIF5\n"
       "6obcnqDfdVsOcLZIjLpXeoW3GQ7dakwe3gPwVvCEEDqNzTPosxKNCUKlzVasRECQ\n"
       "-----END RSA PRIVATE KEY-----\n");

    Sailfish::Crypto::Key importedKey;
    Sailfish::Crypto::Result result = m_usbInterface.importKey(
                pemData, lockCode, QVariantMap(), &importedKey);
    if (result.code() == Crypto::Result::Succeeded) {
        m_usbTokenKey = importedKey;
    }

    return result.code() == Crypto::Result::Succeeded;
}
