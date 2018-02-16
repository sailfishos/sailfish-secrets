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
#include "Crypto/storedkeyrequest.h"
#include "Crypto/cipherrequest.h"
#include "Crypto/interactionparameters.h"
#include "Crypto/symmetrickeyderivationparameters.h"

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
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::Algorithm algorithm) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::Algorithm &algorithm) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::BlockMode mode) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::BlockMode &mode) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::EncryptionPadding padding) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::EncryptionPadding &padding) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::SignaturePadding padding) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::SignaturePadding &padding) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::DigestFunction digest) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::DigestFunction &digest) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::MessageAuthenticationCode mac) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::MessageAuthenticationCode &mac) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::KeyDerivationFunction kdf) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::KeyDerivationFunction &kdf) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::Operation operation) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::Operation &operation) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoManager::Operations operations) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoManager::Operations &operations) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Component component) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Component &component) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Key::Components components) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Key::Components &components) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::Result &result) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::Result &result) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CryptoPluginInfo &pluginInfo) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CryptoPluginInfo &pluginInfo) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::CipherRequest::CipherMode mode) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::CipherRequest::CipherMode &mode) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::InteractionParameters::InputType &type) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::InteractionParameters::InputType &type) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::InteractionParameters::EchoMode &mode) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::InteractionParameters::EchoMode &mode) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::InteractionParameters::Operation &op) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::InteractionParameters::Operation &op) SAILFISH_CRYPTO_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::InteractionParameters &request) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::InteractionParameters &request) SAILFISH_CRYPTO_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Crypto::SymmetricKeyDerivationParameters &skdfParams) SAILFISH_CRYPTO_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Crypto::SymmetricKeyDerivationParameters &skdfParams) SAILFISH_CRYPTO_API;

} // Crypto

} // Sailfish

#endif // LIBSAILFISHCRYPTO_SERIALISATION_H
