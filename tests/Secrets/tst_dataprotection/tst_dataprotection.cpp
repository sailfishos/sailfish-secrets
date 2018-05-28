/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Timur Kristóf <timur.kristof@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "tst_dataprotection.h"
#include "../../../daemon/SecretsImpl/dataprotector_p.h"

#include <QtCore/QDir>

#define TEST_PATH QStringLiteral("/tmp/secrets_tst_dataprotection/")
#define TESTCASE_PATH QString(TEST_PATH + QString(__func__))

QTEST_MAIN(tst_dataprotection)
Q_LOGGING_CATEGORY(lcSailfishSecretsDaemon, "org.sailfishos.secrets.daemon", QtWarningMsg)

using namespace Sailfish::Secrets::Daemon::ApiImpl;

QByteArray tst_dataprotection::createTestData()
{
    QFile urandom("/dev/urandom");
    urandom.open(QIODevice::ReadOnly);
    QByteArray result = urandom.read(768);

    if (result.isEmpty()) {
        qWarning() << "Could not generate random data!";
    }

    return result;
}

void tst_dataprotection::init()
{
    cleanup();
}

void tst_dataprotection::cleanup()
{
    QDir dir(TEST_PATH);
    if (dir.exists()) {
        if (!dir.removeRecursively()) {
            qWarning() << "Could not cleanup test directory.";
        }
    }
}

void tst_dataprotection::testWriteAndRead_checkData()
{
    DataProtector dp(TESTCASE_PATH);
    QByteArray actualData;
    DataProtector::Status s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(actualData.isEmpty(), "protector should not have any data at the beginning");

    QByteArray testData = createTestData();
    s = dp.putData(testData);
    QCOMPARE(s, DataProtector::Success);

    s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(testData == actualData, "Data read should match the test data");
}

void tst_dataprotection::testRewrite_checkOldDeletedAndNewDataIntact()
{
    DataProtector dp(TESTCASE_PATH);
    QByteArray actualData;
    DataProtector::Status s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(actualData.isEmpty(), "protector should not have any data at the beginning");

    QByteArray testData = createTestData();
    s = dp.putData(testData);
    QCOMPARE(s, DataProtector::Success);

    s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(testData == actualData, "Data read should match the test data");

    QByteArray secondTestData = createTestData();
    while (secondTestData == testData) {
        secondTestData = createTestData();
    }
    s = dp.putData(secondTestData);
    QCOMPARE(s, DataProtector::Success);

    s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(secondTestData == actualData, "Data read should match the second test data");
}

void tst_dataprotection::testWriteThenCorruptOneFile_expectSuccess()
{
    DataProtector dp(TESTCASE_PATH);
    QByteArray actualData;
    DataProtector::Status s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(actualData.isEmpty(), "protector should not have any data at the beginning");

    QByteArray testData = createTestData();
    s = dp.putData(testData);
    QCOMPARE(s, DataProtector::Success);

    s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(testData == actualData, "Data read should match the test data");

    QDir protectedRoot(TESTCASE_PATH);
    QVERIFY2(protectedRoot.exists(), "Protected root directory should exist");
    QFileInfoList dataDirs = protectedRoot.entryInfoList(QDir::Dirs | QDir::NoDotAndDotDot, QDir::Time);
    QVERIFY2(dataDirs.size() == 1, "There should be exactly one data dir");
    QDir dataDir(dataDirs.at(0).absoluteFilePath());
    QFileInfoList dataFiles = dataDir.entryInfoList(QDir::Files, QDir::Name);
    QVERIFY2(dataFiles.size() == 3, "There should be exactly 3 data files");
    QFile dataFile0(dataFiles.at(0).absoluteFilePath());
    QVERIFY(dataFile0.open(QIODevice::WriteOnly | QIODevice::Truncate));
    dataFile0.write(QByteArray("totally not valid data"));
    dataFile0.close();

    s = dp.getData(&actualData);
    QCOMPARE(s, DataProtector::Success);
    QVERIFY2(testData == actualData, "Data read should still match the test data, despite the corruption");
}
