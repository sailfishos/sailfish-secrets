/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Timur Kristóf <timur.kristof@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QtCore/QObject>
#include <QtCore/QString>
#include <QtCore/QByteArray>
#include <QtCore/QFile>
#include <QtCore/QDebug>

class tst_dataprotection : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void testWriteAndRead_checkData();
    void testRewrite_checkOldDeletedAndNewDataIntact();
    void testWriteThenCorruptOneFile_expectSuccess();

private:
    QByteArray createTestData();

};
