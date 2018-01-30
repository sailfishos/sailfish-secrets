/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHCRYPTO_SERIALISATION_H
#define LIBSAILFISHCRYPTO_SERIALISATION_H

// WARNING!
//
// This is private API, used for internal implementation only!
// No BC/SC guarantees are made for the methods in this file!

#include "Crypto/cryptoglobal.h"

#include "Crypto/certificate.h"
#include "Crypto/extensionplugins.h"
#include "Crypto/key.h"
#include "Crypto/result.h"

#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

namespace Sailfish {

namespace Crypto {

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Certificate &certificate) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Certificate &certificate) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key &key) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key &key) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Identifier &identifier) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Identifier &identifier) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::FilterData &filterData) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::FilterData &filterData) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Origin origin) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Origin &origin) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Algorithm algorithm) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Algorithm &algorithm) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::BlockMode mode) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::BlockMode &mode) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::EncryptionPadding padding) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::EncryptionPadding &padding) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::SignaturePadding padding) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::SignaturePadding &padding) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Digest digest) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Digest &digest) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Operation operation) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Operation &operation) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::BlockModes modes) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::BlockModes &modes) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::EncryptionPaddings paddings) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::EncryptionPaddings &paddings) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::SignaturePaddings paddings) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::SignaturePaddings &paddings) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Digests digests) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Digests &digests) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Operations operations) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Operations &operations) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Result &result) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Result &result) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoPluginInfo &pluginInfo) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoPluginInfo &pluginInfo) SAILFISH_CRYPTO_API;

} // Crypto

} // Sailfish

#endif // LIBSAILFISHCRYPTO_SERIALISATION_H
