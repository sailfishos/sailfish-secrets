/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QObject>
#include <QDBusReply>
#include <QQuickView>
#include <QQuickItem>

#include "Secrets/secretmanager.h"
#include "Secrets/secret.h"

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dbusreply)       \
    do {                                                    \
        int maxWait = 10000;                                \
        while (!dbusreply.isFinished() && maxWait > 0) {    \
            QTest::qWait(100);                              \
            maxWait -= 100;                                 \
        }                                                   \
    } while (0)

class tst_secrets : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void createDeleteDeviceLockCollection();
    void writeReadDeleteDeviceLockCollectionSecret();
    void writeReadDeleteStandaloneDeviceLockSecret();

    void createDeleteCustomLockCollection();
    void writeReadDeleteCustomLockCollectionSecret();
    void writeReadDeleteStandaloneCustomLockSecret();

private:
    Sailfish::Secrets::SecretManager m;
};

void tst_secrets::init()
{
}

void tst_secrets::cleanup()
{
}

void tst_secrets::createDeleteDeviceLockCollection()
{
    QDBusPendingReply<Sailfish::Secrets::Result> reply = m.createCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    reply = m.deleteCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_secrets::writeReadDeleteDeviceLockCollectionSecret()
{
    QDBusPendingReply<Sailfish::Secrets::Result> reply = m.createCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    Sailfish::Secrets::Secret testSecret(
                Sailfish::Secrets::Secret::Identifier(
                    QLatin1String("testsecretname"),
                    QLatin1String("testcollection")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Sailfish::Secrets::Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    reply = m.setSecret(
                testSecret,
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = m.getSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());
    QCOMPARE(secretReply.argumentAt<1>().filterData(), testSecret.filterData());

    // delete the secret
    reply = m.deleteSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.getSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);

    reply = m.deleteCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}


void tst_secrets::writeReadDeleteStandaloneDeviceLockSecret()
{
    // write the secret
    Sailfish::Secrets::Secret testSecret(Sailfish::Secrets::Secret::Identifier("testsecretname"));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Sailfish::Secrets::Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    QDBusPendingReply<Sailfish::Secrets::Result> reply = m.setSecret(
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                testSecret,
                Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode,
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // read the secret
    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = m.getSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());

    // delete the secret
    reply = m.deleteSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.getSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);
}

void tst_secrets::createDeleteCustomLockCollection()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secrets.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *uiView = v.rootObject()->findChild<QObject*>("uiview");
    QVERIFY(uiView);
    QMetaObject::invokeMethod(uiView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &m));

    QDBusPendingReply<Sailfish::Secrets::Result> reply = m.createCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName,
                Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked,
                0,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode,
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    reply = m.deleteCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}

void tst_secrets::writeReadDeleteCustomLockCollectionSecret()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secrets.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *uiView = v.rootObject()->findChild<QObject*>("uiview");
    QVERIFY(uiView);
    QMetaObject::invokeMethod(uiView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &m));

    QDBusPendingReply<Sailfish::Secrets::Result> reply = m.createCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName,
                Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked,
                0,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode,
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    Sailfish::Secrets::Secret testSecret(
                Sailfish::Secrets::Secret::Identifier(
                    QLatin1String("testsecretname"),
                    QLatin1String("testcollection")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Sailfish::Secrets::Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    reply = m.setSecret(
                testSecret,
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = m.getSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());

    reply = m.deleteSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.getSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);

    reply = m.deleteCollection(
                QLatin1String("testcollection"),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
}


void tst_secrets::writeReadDeleteStandaloneCustomLockSecret()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secrets.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *uiView = v.rootObject()->findChild<QObject*>("uiview");
    QVERIFY(uiView);
    QMetaObject::invokeMethod(uiView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &m));

    Sailfish::Secrets::Secret testSecret(Sailfish::Secrets::Secret::Identifier(QLatin1String("testsecretname")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Sailfish::Secrets::Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    QDBusPendingReply<Sailfish::Secrets::Result> reply = m.setSecret(
                Sailfish::Secrets::SecretManager::DefaultStoragePluginName,
                Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName,
                Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName,
                testSecret,
                Sailfish::Secrets::SecretManager::CustomLockKeepUnlocked,
                0,
                Sailfish::Secrets::SecretManager::OwnerOnlyMode,
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    QDBusPendingReply<Sailfish::Secrets::Result, Sailfish::Secrets::Secret> secretReply = m.getSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());

    reply = m.deleteSecret(
                testSecret.identifier(),
                Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.getSecret(
                    testSecret.identifier(),
                    Sailfish::Secrets::SecretManager::InProcessUserInteractionMode);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Sailfish::Secrets::Result::Failed);
}

#include "tst_secrets.moc"
QTEST_MAIN(tst_secrets)
