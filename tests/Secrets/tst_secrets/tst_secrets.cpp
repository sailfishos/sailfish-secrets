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
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialisation_p.h"

using namespace Sailfish::Secrets;

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dbusreply)       \
    do {                                                    \
        int maxWait = 10000;                                \
        while (!dbusreply.isFinished() && maxWait > 0) {    \
            QTest::qWait(100);                              \
            maxWait -= 100;                                 \
        }                                                   \
    } while (0)

class TestSecretManager : public Sailfish::Secrets::SecretManager
{
    Q_OBJECT

public:
    TestSecretManager(QObject *parent = Q_NULLPTR)
        : Sailfish::Secrets::SecretManager(parent) {}
    ~TestSecretManager() {}
    Sailfish::Secrets::SecretManagerPrivate *d_ptr() const { return Sailfish::Secrets::SecretManager::pimpl(); }
};

class tst_secrets : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void devicelockCollection();
    void devicelockCollectionSecret();
    void devicelockStandaloneSecret();

    void customlockCollection();
    void customlockCollectionSecret();
    void customlockStandaloneSecret();

    void encryptedStorageCollection();

    void accessControl();

private:
    TestSecretManager m;
};

void tst_secrets::init()
{
}

void tst_secrets::cleanup()
{
}

void tst_secrets::devicelockCollection()
{
    QDBusPendingReply<Result> reply = m.d_ptr()->createCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                SecretManager::DeviceLockKeepUnlocked,
                SecretManager::OwnerOnlyMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    reply = m.d_ptr()->deleteCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
}

void tst_secrets::devicelockCollectionSecret()
{
    QDBusPendingReply<Result> reply = m.d_ptr()->createCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                SecretManager::DeviceLockKeepUnlocked,
                SecretManager::OwnerOnlyMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    Secret testSecret(
                Secret::Identifier(
                    QLatin1String("testsecretname"),
                    QLatin1String("testcollection"),
                    SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    reply = m.d_ptr()->setSecret(
                testSecret,
                InteractionParameters(),
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    QDBusPendingReply<Result, Secret> secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());
    QCOMPARE(secretReply.argumentAt<1>().filterData(), testSecret.filterData());

    // test filtering, first with AND with both matching metadata field values, expect match
    Secret::FilterData filter;
    filter.insert(QLatin1String("domain"), testSecret.filterData(QLatin1String("domain")));
    filter.insert(QLatin1String("test"), testSecret.filterData(QLatin1String("test")));
    QDBusPendingReply<Result, QVector<Secret::Identifier> > filterReply = m.d_ptr()->findSecrets(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                filter,
                SecretManager::OperatorAnd,
                SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 1);
    QCOMPARE(filterReply.argumentAt<1>().at(0), testSecret.identifier());

    // now test filtering with AND with one matching and one non-matching value, expect no-match
    filter.insert(QLatin1String("test"), QLatin1String("false"));
    filterReply = m.d_ptr()->findSecrets(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                filter,
                SecretManager::OperatorAnd,
                SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 0);

    // test filtering with OR with one matching and one non-matching value, expect match
    filterReply = m.d_ptr()->findSecrets(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                filter,
                SecretManager::OperatorOr,
                SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 1);
    QCOMPARE(filterReply.argumentAt<1>().at(0), testSecret.identifier());

    // test filtering with OR with zero matching values, expect no-match
    filter.insert(QLatin1String("domain"), QLatin1String("jolla.com"));
    filterReply = m.d_ptr()->findSecrets(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                filter,
                SecretManager::OperatorOr,
                SecretManager::PreventInteraction);
    filterReply.waitForFinished();
    QVERIFY(filterReply.isValid());
    QCOMPARE(filterReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(filterReply.argumentAt<1>().size(), 0);

    // delete the secret
    reply = m.d_ptr()->deleteSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Failed);

    reply = m.d_ptr()->deleteCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
}


void tst_secrets::devicelockStandaloneSecret()
{
    // write the secret
    Secret testSecret(Secret::Identifier(
            QStringLiteral("testsecretname"),
            QString(),
            SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    QDBusPendingReply<Result> reply = m.d_ptr()->setSecret(
                testSecret,
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                InteractionParameters(),
                SecretManager::DeviceLockKeepUnlocked,
                SecretManager::OwnerOnlyMode,
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // read the secret
    QDBusPendingReply<Result, Secret> secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());

    // delete the secret
    reply = m.d_ptr()->deleteSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    secretReply.waitForFinished();
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Failed);
}

void tst_secrets::customlockCollection()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secrets.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &m));

    QDBusPendingReply<Result> reply = m.d_ptr()->createCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                SecretManager::InAppAuthenticationPluginName + QLatin1String(".test"),
                SecretManager::CustomLockKeepUnlocked,
                SecretManager::OwnerOnlyMode,
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    reply = m.d_ptr()->deleteCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
}

void tst_secrets::customlockCollectionSecret()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secrets.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &m));

    QDBusPendingReply<Result> reply = m.d_ptr()->createCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                SecretManager::InAppAuthenticationPluginName + QLatin1String(".test"),
                SecretManager::CustomLockKeepUnlocked,
                SecretManager::OwnerOnlyMode,
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    Secret testSecret(
                Secret::Identifier(
                    QLatin1String("testsecretname"),
                    QLatin1String("testcollection"),
                    SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    reply = m.d_ptr()->setSecret(
                testSecret,
                InteractionParameters(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    QDBusPendingReply<Result, Secret> secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());

    reply = m.d_ptr()->deleteSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Failed);

    reply = m.d_ptr()->deleteCollection(
                QLatin1String("testcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
}


void tst_secrets::customlockStandaloneSecret()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secrets.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &m));

    Secret testSecret(Secret::Identifier(
            QStringLiteral("testsecretname"),
            QString(),
            SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    QDBusPendingReply<Result> reply = m.d_ptr()->setSecret(
                testSecret,
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                SecretManager::InAppAuthenticationPluginName + QLatin1String(".test"),
                InteractionParameters(),
                SecretManager::CustomLockKeepUnlocked,
                SecretManager::OwnerOnlyMode,
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    QDBusPendingReply<Result, Secret> secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());

    reply = m.d_ptr()->deleteSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.d_ptr()->getSecret(
                    testSecret.identifier(),
                    SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Failed);
}

void tst_secrets::encryptedStorageCollection()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secrets.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &m));

    QDBusPendingReply<Result> reply = m.d_ptr()->createCollection(
                QLatin1String("testencryptedcollection"),
                SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                SecretManager::InAppAuthenticationPluginName + QLatin1String(".test"),
                SecretManager::CustomLockKeepUnlocked,
                SecretManager::OwnerOnlyMode,
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    Secret testSecret(
                Secret::Identifier(
                    QLatin1String("testsecretname"),
                    QLatin1String("testencryptedcollection"),
                    SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    reply = m.d_ptr()->setSecret(
                testSecret,
                InteractionParameters(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    QDBusPendingReply<Result, Secret> secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Succeeded);
    QCOMPARE(secretReply.argumentAt<1>().data(), testSecret.data());

    reply = m.d_ptr()->deleteSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    secretReply = m.d_ptr()->getSecret(
                testSecret.identifier(),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(secretReply);
    QVERIFY(secretReply.isValid());
    QCOMPARE(secretReply.argumentAt<0>().code(), Result::Failed);

    reply = m.d_ptr()->deleteCollection(
                QLatin1String("testencryptedcollection"),
                SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test"),
                SecretManager::ApplicationInteraction);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(reply);
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
}

void tst_secrets::accessControl()
{
    // This test is meant to be run first, with tst_secretsrequests::accessControls() run second.
    // This test must be run as non-privileged, to avoid being classified as a platform app.
    // Artifacts from the test will have to be removed manually from the filesystem.
    QSKIP("This test should only be run manually, as it is not stand-alone!");

    // the following collection should not be readable/writable/deletable by another process
    QDBusPendingReply<Result> reply = m.d_ptr()->createCollection(
                QLatin1String("owneronlycollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                SecretManager::DeviceLockKeepUnlocked,
                SecretManager::OwnerOnlyMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // the following secret should not be able to be read or deleted by another process
    Secret unreadableSecret(
                Secret::Identifier(
                    QLatin1String("unreadablesecret"),
                    QLatin1String("owneronlycollection"),
                    SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    unreadableSecret.setData("unreadablesecretvalue");
    unreadableSecret.setType(Secret::TypeBlob);
    unreadableSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    unreadableSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    reply = m.d_ptr()->setSecret(
                unreadableSecret,
                InteractionParameters(),
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // while the following collection should be readable/writable/deletable by another process.
    reply = m.d_ptr()->createCollection(
                QLatin1String("noaccesscontrolcollection"),
                SecretManager::DefaultStoragePluginName + QLatin1String(".test"),
                SecretManager::DefaultEncryptionPluginName + QLatin1String(".test"),
                SecretManager::DeviceLockKeepUnlocked,
                SecretManager::NoAccessControlMode);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);

    // and the following secret should be readable and deletable by another process.
    Secret readableSecret(
                Secret::Identifier(
                    QLatin1String("readablesecret"),
                    QLatin1String("noaccesscontrolcollection"),
                    SecretManager::DefaultStoragePluginName + QLatin1String(".test")));
    readableSecret.setData("readablesecretvalue");
    readableSecret.setType(Secret::TypeBlob);
    readableSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    readableSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    reply = m.d_ptr()->setSecret(
                readableSecret,
                InteractionParameters(),
                SecretManager::ApplicationInteraction);
    reply.waitForFinished();
    QVERIFY(reply.isValid());
    QCOMPARE(reply.argumentAt<0>().code(), Result::Succeeded);
}

#include "tst_secrets.moc"
QTEST_MAIN(tst_secrets)
