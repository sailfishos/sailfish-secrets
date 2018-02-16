/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/generatestoredkeyrequest.h"
#include "Crypto/generatestoredkeyrequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

GenerateStoredKeyRequestPrivate::GenerateStoredKeyRequestPrivate()
    : m_status(Request::Inactive)
{
}

/*!
 * \class GenerateKeyRequest
 * \brief Allows a client request that the system crypto service generate and secure store a key based on a template.
 *
 * The generated key will be stored securely by the crypto daemon via the storage
 * plugin identified by the given storagePluginName(), and the returned
 * key will not contain any private or secret key data.
 *
 * Available storage providers can be enumerated from the Sailfish Secrets API.
 *
 * If the cryptoPluginName() and \a storagePluginName() are the
 * same, then the key will be stored in storage managed by the
 * crypto provider plugin, if that plugin supports storing keys.
 * In that case, the crypto plugin must also be a Sailfish::Secrets::EncryptedStoragePlugin.
 */

/*!
 * \brief Constructs a new GenerateStoredKeyRequest object with the given \a parent.
 */
GenerateStoredKeyRequest::GenerateStoredKeyRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new GenerateStoredKeyRequestPrivate)
{
}

/*!
 * \brief Destroys the GenerateStoredKeyRequest
 */
GenerateStoredKeyRequest::~GenerateStoredKeyRequest()
{
}

/*!
 * \brief Returns the name of the crypto plugin which the client wishes to perform the key generation operation
 */
QString GenerateStoredKeyRequest::cryptoPluginName() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_cryptoPluginName;
}

/*!
 * \brief Sets the name of the crypto plugin which the client wishes to perform the key generation operation to \a pluginName
 */
void GenerateStoredKeyRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(GenerateStoredKeyRequest);
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
 * \brief Returns the name of the storage plugin which the client wishes the generated key to be stored in
 */
QString GenerateStoredKeyRequest::storagePluginName() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_storagePluginName;
}

/*!
 * \brief Sets the name of the storage plugin which the client wishes the generated key to be stored in to \a pluginName
 */
void GenerateStoredKeyRequest::setStoragePluginName(const QString &pluginName)
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_storagePluginName != pluginName) {
        d->m_storagePluginName = pluginName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit storagePluginNameChanged();
    }
}

/*!
 * \brief Returns the user input parameters which should be used when requesting the input data from the user
 *
 * These interaction parameters are only meaningful if the template key
 * algorithm is a symmetric cipher algorithm, and if a set of valid
 * symmetric key derivation parameters are also specified for the request.
 *
 * If specified, the user will be prompted to enter some data
 * (for example, a passphrase or PIN) which will then be used as input data
 * to the key derivation function, which will produce the key data.
 */
Sailfish::Crypto::InteractionParameters
GenerateStoredKeyRequest::interactionParameters() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_uiParams;
}

/*!
 * \brief Sets the user input parameters which should be used when requesting the input data from the user to \a uiParams
 */
void GenerateStoredKeyRequest::setInteractionParameters(
        const Sailfish::Crypto::InteractionParameters &uiParams)
{
    Q_D(GenerateStoredKeyRequest);
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
 * \brief Returns the symmetric key derivation parameters which should be used to generate the secret key data
 *
 * These interaction parameters are only meaningful if the template key
 * algorithm is a symmetric cipher algorithm.
 */
Sailfish::Crypto::SymmetricKeyDerivationParameters
GenerateStoredKeyRequest::symmetricKeyDerivationParameters() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_skdfParams;
}

/*!
 * \brief Sets the symmetric key derivation parameters which should be used to generate the secret key data to \a params
 */
void GenerateStoredKeyRequest::setSymmetricKeyDerivationParameters(
        const Sailfish::Crypto::SymmetricKeyDerivationParameters &params)
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_skdfParams != params) {
        d->m_skdfParams = params;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit symmetricKeyDerivationParametersChanged();
    }
}

/*!
 * \brief Returns the key which should be used as a template when generating the full key
 */
Key GenerateStoredKeyRequest::keyTemplate() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_keyTemplate;
}

/*!
 * \brief Sets the key which should be used as a template when generating the full key to \a key
 */
void GenerateStoredKeyRequest::setKeyTemplate(const Key &key)
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && d->m_keyTemplate != key) {
        d->m_keyTemplate = key;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit keyTemplateChanged();
    }
}

/*!
 * \brief Returns a key reference to the securely-stored generated key
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 *
 * The key reference will contain metadata and a valid identifier, but no private or secret key data.
 */
Key GenerateStoredKeyRequest::generatedKeyReference() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_generatedKeyReference;
}

Request::Status GenerateStoredKeyRequest::status() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_status;
}

Result GenerateStoredKeyRequest::result() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_result;
}

CryptoManager *GenerateStoredKeyRequest::manager() const
{
    Q_D(const GenerateStoredKeyRequest);
    return d->m_manager.data();
}

void GenerateStoredKeyRequest::setManager(CryptoManager *manager)
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void GenerateStoredKeyRequest::startRequest()
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, Key> reply =
                d->m_manager->d_ptr->generateStoredKey(d->m_keyTemplate,
                                                       d->m_skdfParams,
                                                       d->m_uiParams,
                                                       d->m_cryptoPluginName,
                                                       d->m_storagePluginName);
        if (reply.isFinished()
                // work around a bug in QDBusAbstractInterface / QDBusConnection...
                && reply.argumentAt<0>().code() != Sailfish::Crypto::Result::Succeeded) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_generatedKeyReference = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit generatedKeyReferenceChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, Key> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_generatedKeyReference = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->generatedKeyReferenceChanged();
            });
        }
    }
}

void GenerateStoredKeyRequest::waitForFinished()
{
    Q_D(GenerateStoredKeyRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
