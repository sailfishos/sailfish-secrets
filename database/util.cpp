/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "util_p.h"

#include <QtCore/QCryptographicHash>
#include <QtCore/QString>
#include <QtCore/QByteArray>

namespace {
    QByteArray rehashHash(const QByteArray &hash) {
        QCryptographicHash rehash(QCryptographicHash::QCryptographicHash::Sha3_256);
        rehash.addData(hash);
        return rehash.result();
    }
}

QString Sailfish::Secrets::Daemon::Util::generateHashedSecretName(
        const QString &collectionName,
        const QString &secretName)
{
    QCryptographicHash keyHash(QCryptographicHash::QCryptographicHash::Sha3_256);
    QByteArray data = collectionName.toUtf8() + secretName.toUtf8();
    keyHash.addData(data);
    QByteArray hashed = keyHash.result();

    // do PBKDF style repeated hashing
    for (int i = 0; i < 1000; ++i) {
        hashed = rehashHash(hashed);
    }

    return QString::fromLatin1(hashed.toBase64());
}

