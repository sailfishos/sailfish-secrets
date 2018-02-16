/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef LIBSAILFISHSECRETS_SERIALISATION_H
#define LIBSAILFISHSECRETS_SERIALISATION_H

// WARNING!
//
// This is private API, used for internal implementation only!
// No BC/SC guarantees are made for the methods in this file!

#include "Secrets/secretsglobal.h"
#include "Secrets/result.h"
#include "Secrets/secret.h"
#include "Secrets/extensionplugins.h"
#include "Secrets/secretmanager.h"
#include "Secrets/interactionrequest.h"

#include <QtDBus/QDBusArgument>
#include <QtDBus/QDBusMetaType>

namespace Sailfish {

namespace Secrets {


QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::Result &result) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::Result &result) SAILFISH_SECRETS_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::Secret &secret) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::Secret &secret) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::Secret::Identifier &identifier) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::Secret::Identifier &identifier) SAILFISH_SECRETS_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::UserInteractionMode mode) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::UserInteractionMode &mode) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::AccessControlMode mode) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::AccessControlMode &mode) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic semantic) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::DeviceLockUnlockSemantic &semantic) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic semantic) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::CustomLockUnlockSemantic &semantic) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::SecretManager::FilterOperator filterOperator) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::SecretManager::FilterOperator &filterOperator) SAILFISH_SECRETS_API;

QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::EncryptionPluginInfo &info) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::EncryptionPluginInfo &info) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::StoragePluginInfo &info) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::StoragePluginInfo &info) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::EncryptedStoragePluginInfo &info) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::EncryptedStoragePluginInfo &info) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const Sailfish::Secrets::AuthenticationPluginInfo &info) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, Sailfish::Secrets::AuthenticationPluginInfo &info) SAILFISH_SECRETS_API;

QDBusArgument &operator<<(QDBusArgument &argument, const InteractionRequest &request) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionRequest &request) SAILFISH_SECRETS_API;
QDBusArgument &operator<<(QDBusArgument &argument, const InteractionResponse &response) SAILFISH_SECRETS_API;
const QDBusArgument &operator>>(const QDBusArgument &argument, InteractionResponse &response) SAILFISH_SECRETS_API;

} // namespace Secrets

} // namespace Sailfish

#endif // LIBSAILFISHSECRETS_SERIALISATION_H
