/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/importstoredkeyrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

ImportStoredKeyRequestPrivate::ImportStoredKeyRequestPrivate()
    : m_status(Request::Inactive)
{
}

/*!
 * \class ImportKeyRequest
 * \brief Allows a client request that the system crypto service import and secure store a key.
 *
 * The imported key will be stored securely by the crypto daemon into the storage
 * plugin identified by the storage plugin specified in the key template's
 * identifier, and the returned key reference will not contain any private or secret
 * key data.
 *
 * Available storage providers can be enumerated from the Sailfish Secrets API.
 *
 * If the cryptoPluginName() and the identifier's storage plugin are the
 * same, then the key will be stored in storage managed by the
 * crypto provider plugin, if that plugin supports storing keys.
 * In that case, the crypto plugin must also be a Sailfish::Secrets::EncryptedStoragePlugin.
 * Such crypto storage plugins can enforce key component readability constraints,
 * and allow cryptographic operations to occur in the most secure manner possible.
 */

/*!
 * \brief Constructs a new ImportStoredKeyRequest object with the given \a parent.
 */
ImportStoredKeyRequest::ImportStoredKeyRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new ImportStoredKeyRequestPrivate)
{
}

/*!
 * \brief Destroys the ImportStoredKeyRequest
 */
ImportStoredKeyRequest::~ImportStoredKeyRequest()
{
}

/*!
 * \brief Returns the name of the crypto plugin which the client wishes to perform the key generation operation
 */
QString ImportStoredKeyRequest::cryptoPluginName() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_cryptoPluginName;
}

/*!
 * \brief Sets the name of the crypto plugin which the client wishes to perform the key generation operation to \a pluginName
 */
void ImportStoredKeyRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(ImportStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_cryptoPluginName != pluginName) {
        d->m_cryptoPluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit cryptoPluginNameChanged();
    }
}

/*!
 * \brief Returns the user input parameters which should be used when requesting the input data from the user
 *
 * If specified, the user may be prompted to enter a pass phrase needed to decrypt the imported
 * key.
 */
Sailfish::Crypto::InteractionParameters
ImportStoredKeyRequest::interactionParameters() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_uiParams;
}

/*!
 * \brief Sets the user input parameters which should be used when requesting the input data from the user to \a uiParams
 */
void ImportStoredKeyRequest::setInteractionParameters(
        const Sailfish::Crypto::InteractionParameters &uiParams)
{
    Q_D(ImportStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_uiParams != uiParams) {
        d->m_uiParams = uiParams;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit interactionParametersChanged();
    }
}

/*!
 * \brief Returns the key which should be imported.
 */
Key ImportStoredKeyRequest::key() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_key;
}

/*!
 * \brief Sets the \a key which should be imported.
 */
void ImportStoredKeyRequest::setKey(const Key &key)
{
    Q_D(ImportStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_key != key) {
        d->m_key = key;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyChanged();
    }
}

/*!
 * \brief Returns a key reference to the securely-stored imported key
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 *
 * The key reference will contain metadata and a valid identifier, but no private or secret key data.
 */
Key ImportStoredKeyRequest::importedKeyReference() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_importedKeyReference;
}

Request::Status ImportStoredKeyRequest::status() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_status;
}

Result ImportStoredKeyRequest::result() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_result;
}

QVariantMap ImportStoredKeyRequest::customParameters() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_customParameters;
}

void ImportStoredKeyRequest::setCustomParameters(const QVariantMap &params)
{
    Q_D(ImportStoredKeyRequest);
    if (d->m_customParameters != params) {
        d->m_customParameters = params;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit customParametersChanged();
    }
}

CryptoManager *ImportStoredKeyRequest::manager() const
{
    Q_D(const ImportStoredKeyRequest);
    return d->m_manager.data();
}

void ImportStoredKeyRequest::setManager(CryptoManager *manager)
{
    Q_D(ImportStoredKeyRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void ImportStoredKeyRequest::startRequest()
{
    Q_D(ImportStoredKeyRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, Key> reply =
                d->m_manager->d_ptr->importStoredKey(d->m_key,
                                                     d->m_uiParams,
                                                     d->m_customParameters,
                                                     d->m_cryptoPluginName);
        if (reply.isError()) {
            d->m_status = Request::Finished;
            d->m_result = Result(Result::CryptoManagerNotInitializedError,
                                 reply.error().message());
            emit statusChanged();
            emit resultChanged();
        } else if (reply.isFinished()
                // work around a bug in QDBusAbstractInterface / QDBusConnection...
                && reply.argumentAt<0>().code() != Sailfish::Crypto::Result::Succeeded) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_importedKeyReference = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit importedKeyReferenceChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, Key> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                if (reply.isError()) {
                    this->d_ptr->m_result = Result(Result::CryptoManagerNotInitializedError,
                                         reply.error().message());
                    this->d_ptr->m_importedKeyReference = Key();
                } else {
                    this->d_ptr->m_result = reply.argumentAt<0>();
                    this->d_ptr->m_importedKeyReference = reply.argumentAt<1>();
                }
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->importedKeyReferenceChanged();
            });
        }
    }
}

void ImportStoredKeyRequest::waitForFinished()
{
    Q_D(ImportStoredKeyRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
