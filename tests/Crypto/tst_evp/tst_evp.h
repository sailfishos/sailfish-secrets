/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QProcess>
#include <QtCore/QByteArray>
#include <QtCore/QFile>
#include <QtCore/QDebug>

#include "evp_p.h"

class tst_evp : public QObject
{
    Q_OBJECT
    static constexpr const char *privateKeyFileName = "private_key.pem";
    static constexpr const char *publicKeyFileName = "public_key.pem";
    QByteArray privateKey;
    QByteArray publicKey;

public slots:
    void init();
    void cleanup();

private slots:
    void testDigest();
    void testSign();
    void testVerifyCorrect();
    void testVerifyIncorrect();

private:
    QByteArray generateTestData(size_t size);
    QByteArray signWithCommandLine(const QByteArray &data);
    QByteArray signWithEvp(const QByteArray &data);
    bool verifyWithCommandLine(const QByteArray &data, const QByteArray &signature);
    bool verifyWithEvp(const QByteArray &data, const QByteArray &signature);
    QByteArray digestWithCommandLine(const QByteArray &data);
    QByteArray digestWithEvp(const QByteArray &data);
};
