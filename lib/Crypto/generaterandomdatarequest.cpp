/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "Crypto/generaterandomdatarequest.h"
#include "Crypto/generaterandomdatarequest_p.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialisation_p.h"

#include <QtDBus/QDBusPendingReply>
#include <QtDBus/QDBusPendingCallWatcher>

using namespace Sailfish::Crypto;

const QString GenerateRandomDataRequest::DefaultCsprngEngineName = QStringLiteral("default");

GenerateRandomDataRequestPrivate::GenerateRandomDataRequestPrivate()
    : m_csprngEngineName(GenerateRandomDataRequest::DefaultCsprngEngineName)
    , m_numberBytes(0)
    , m_status(Request::Inactive)
{
}

/*!
 * \class GenerateRandomDataRequest
 * \brief Allows a client request that the system crypto service generate random data.
 *
 * The random data will be generated using the cryptographically-secure random number
 * generator engine specified by the client.  The engines which are supported by the
 * plugin should be documented by that plugin.  The default crypto plugin supports
 * two engines: "default" and "/dev/urandom".
 *
 * If you need a random number, you can use data from this method to create a random
 * number.  For example, to return a random number between 30 and 7777 you could do
 * something like the following:
 *
 * \code
 * Sailfish::Crypto::GenerateRandomDataRequest rd;
 * rd.setManager(cryptoManager);
 * rd.setCryptoPluginName(Sailfish::Crypto::CryptoManager::DefaultCryptoStoragePluginName);
 * rd.setCsprngEngineName(QStringLiteral("/dev/urandom"));
 * rd.setNumberBytes(8);
 * rd.startRequest();
 * rd.waitForFinished(); // in real code, you would not do this, but react to statusChanged()
 * QByteArray randomBytes = rd.generatedData();
 * quint64 randomU64 = 0;
 * memcpy(&randomU64, randomBytes.constData(), 8);
 * double randomDouble = (randomU64 >> 11) * (1.0/9007199254740992.0); // 53 bits / 2**53
 * int randomInRange = qRound((7777 - 30) * randomDouble) + 30;
 * \endcode
 */

/*!
 * \brief Constructs a new GenerateRandomDataRequest object with the given \a parent.
 */
GenerateRandomDataRequest::GenerateRandomDataRequest(QObject *parent)
    : Request(parent)
    , d_ptr(new GenerateRandomDataRequestPrivate)
{
}

/*!
 * \brief Destroys the GenerateRandomDataRequest
 */
GenerateRandomDataRequest::~GenerateRandomDataRequest()
{
}

/*!
 * \brief Returns the name of the crypto plugin which the client wishes to perform the key generation operation
 */
QString GenerateRandomDataRequest::cryptoPluginName() const
{
    Q_D(const GenerateRandomDataRequest);
    return d->m_cryptoPluginName;
}

/*!
 * \brief Sets the name of the crypto plugin which the client wishes to perform the key generation operation to \a pluginName
 */
void GenerateRandomDataRequest::setCryptoPluginName(const QString &pluginName)
{
    Q_D(GenerateRandomDataRequest);
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
 * \brief Returns the name of the cryptographically secure random number generator engine
 *        offered by the crypto plugin which the client wishes to be used to generate
 *        the random data
 */
QString GenerateRandomDataRequest::csprngEngineName() const
{
    Q_D(const GenerateRandomDataRequest);
    return d->m_csprngEngineName;
}

/*!
 * \brief Sets the name of the cryptographically secure random number generator engine
 *        offered by the crypto plugin which the client wishes to be used to generate
 *        the random data to \a engineName
 *
 * Usually, the default engine offered by the plugin is the correct CSPRNG engine
 * to use (and in fact, most plugins will only offer that one engine), so clients
 * should not have to set this parameter in the majority of cases.
 */
void GenerateRandomDataRequest::setCsprngEngineName(const QString &engineName)
{
    Q_D(GenerateRandomDataRequest);
    if (d->m_status != Request::Active && d->m_csprngEngineName != engineName) {
        d->m_csprngEngineName = engineName;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit csprngEngineNameChanged();
    }
}

/*!
 * \brief Returns the number of bytes of random data that the client wishes to be generated
 */
quint64 GenerateRandomDataRequest::numberBytes() const
{
    Q_D(const GenerateRandomDataRequest);
    return d->m_numberBytes;
}

/*!
 * \brief Sets the number of bytes of random data that the client wishes to be generated to \a nbrBytes
 */
void GenerateRandomDataRequest::setNumberBytes(quint64 nbrBytes)
{
    Q_D(GenerateRandomDataRequest);
    if (d->m_status != Request::Active && d->m_numberBytes != nbrBytes) {
        d->m_numberBytes = nbrBytes;
        if (d->m_status == Request::Finished) {
            d->m_status = Request::Inactive;
            emit statusChanged();
        }
        emit numberBytesChanged();
    }
}

/*!
 * \brief Returns the generated random data
 *
 * Note: this value is only valid if the status of the request is Request::Finished.
 */
QByteArray GenerateRandomDataRequest::generatedData() const
{
    Q_D(const GenerateRandomDataRequest);
    return d->m_generatedData;
}

Request::Status GenerateRandomDataRequest::status() const
{
    Q_D(const GenerateRandomDataRequest);
    return d->m_status;
}

Result GenerateRandomDataRequest::result() const
{
    Q_D(const GenerateRandomDataRequest);
    return d->m_result;
}

CryptoManager *GenerateRandomDataRequest::manager() const
{
    Q_D(const GenerateRandomDataRequest);
    return d->m_manager.data();
}

void GenerateRandomDataRequest::setManager(CryptoManager *manager)
{
    Q_D(GenerateRandomDataRequest);
    if (d->m_manager.data() != manager) {
        d->m_manager = manager;
        emit managerChanged();
    }
}

void GenerateRandomDataRequest::startRequest()
{
    Q_D(GenerateRandomDataRequest);
    if (d->m_status != Request::Active && !d->m_manager.isNull()) {
        d->m_status = Request::Active;
        emit statusChanged();
        if (d->m_result.code() != Result::Pending) {
            d->m_result = Result(Result::Pending);
            emit resultChanged();
        }

        QDBusPendingReply<Result, QByteArray> reply =
                d->m_manager->d_ptr->generateRandomData(d->m_numberBytes,
                                                        d->m_csprngEngineName,
                                                        d->m_cryptoPluginName);
        if (reply.isFinished()) {
            d->m_status = Request::Finished;
            d->m_result = reply.argumentAt<0>();
            d->m_generatedData = reply.argumentAt<1>();
            emit statusChanged();
            emit resultChanged();
            emit generatedDataChanged();
        } else {
            d->m_watcher.reset(new QDBusPendingCallWatcher(reply));
            connect(d->m_watcher.data(), &QDBusPendingCallWatcher::finished,
                    [this] {
                QDBusPendingCallWatcher *watcher = this->d_ptr->m_watcher.take();
                QDBusPendingReply<Result, QByteArray> reply = *watcher;
                this->d_ptr->m_status = Request::Finished;
                this->d_ptr->m_result = reply.argumentAt<0>();
                this->d_ptr->m_generatedData = reply.argumentAt<1>();
                watcher->deleteLater();
                emit this->statusChanged();
                emit this->resultChanged();
                emit this->generatedDataChanged();
            });
        }
    }
}

void GenerateRandomDataRequest::waitForFinished()
{
    Q_D(GenerateRandomDataRequest);
    if (d->m_status == Request::Active && !d->m_watcher.isNull()) {
        d->m_watcher->waitForFinished();
    }
}
