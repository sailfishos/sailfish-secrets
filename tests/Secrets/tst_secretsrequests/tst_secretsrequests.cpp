/*
 * Copyright (C) 2018 Jolla Ltd.
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
#include "Secrets/interactionparameters.h"
#include "Secrets/collectionnamesrequest.h"
#include "Secrets/createcollectionrequest.h"
#include "Secrets/deletecollectionrequest.h"
#include "Secrets/deletesecretrequest.h"
#include "Secrets/findsecretsrequest.h"
#include "Secrets/interactionrequest.h"
#include "Secrets/plugininforequest.h"
#include "Secrets/storedsecretrequest.h"
#include "Secrets/storesecretrequest.h"

using namespace Sailfish::Secrets;

#define DEFAULT_TEST_STORAGE_PLUGIN SecretManager::DefaultStoragePluginName + QLatin1String(".test")
#define DEFAULT_TEST_ENCRYPTION_PLUGIN SecretManager::DefaultEncryptionPluginName + QLatin1String(".test")
#define DEFAULT_TEST_ENCRYPTEDSTORAGE_PLUGIN SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")
#define IN_APP_TEST_AUTHENTICATION_PLUGIN SecretManager::InAppAuthenticationPluginName + QLatin1String(".test")

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                     \
    do {                                                                \
        int maxWait = 10000;                                            \
        while (request.status() != Request::Finished && maxWait > 0) {  \
            QTest::qWait(100);                                          \
            maxWait -= 100;                                             \
        }                                                               \
    } while (0)

class tst_secretsrequests : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void getPluginInfo();

    void devicelockCollection();
    void devicelockCollectionSecret();
    void devicelockStandaloneSecret();

    void customlockCollection();
    void customlockCollectionSecret();
    void customlockStandaloneSecret();

    void encryptedStorageCollection();

    void storeUserSecret();

    void requestUserInput();

    void accessControl();

private:
    SecretManager sm;
};

void tst_secretsrequests::init()
{
}

void tst_secretsrequests::cleanup()
{
}

void tst_secretsrequests::getPluginInfo()
{
    PluginInfoRequest r;
    r.setManager(&sm);
    QSignalSpy ss(&r, &PluginInfoRequest::statusChanged);
    QSignalSpy sps(&r, &PluginInfoRequest::storagePluginsChanged);
    QSignalSpy eps(&r, &PluginInfoRequest::encryptionPluginsChanged);
    QSignalSpy esps(&r, &PluginInfoRequest::encryptedStoragePluginsChanged);
    QSignalSpy aps(&r, &PluginInfoRequest::authenticationPluginsChanged);
    QCOMPARE(r.status(), Request::Inactive);
    r.startRequest();
    QCOMPARE(ss.count(), 1);
    QCOMPARE(r.status(), Request::Active);
    QCOMPARE(r.result().code(), Result::Pending);
    r.waitForFinished();
    QCOMPARE(ss.count(), 2);
    QCOMPARE(r.status(), Request::Finished);
    QCOMPARE(r.result().code(), Result::Succeeded);
    QCOMPARE(sps.count(), 1);
    QCOMPARE(eps.count(), 1);
    QCOMPARE(esps.count(), 1);
    QCOMPARE(aps.count(), 1);

    QVERIFY(r.storagePlugins().size());
    QStringList storagePluginNames;
    for (auto p : r.storagePlugins()) {
        storagePluginNames.append(p.name());
    }
    QVERIFY(storagePluginNames.contains(DEFAULT_TEST_STORAGE_PLUGIN));

    QVERIFY(r.encryptionPlugins().size());
    QStringList encryptionPluginNames;
    for (auto p : r.encryptionPlugins()) {
        encryptionPluginNames.append(p.name());
    }
    QVERIFY(encryptionPluginNames.contains(DEFAULT_TEST_ENCRYPTION_PLUGIN));

    QVERIFY(r.encryptedStoragePlugins().size());
    QStringList encryptedStoragePluginNames;
    for (auto p : r.encryptedStoragePlugins()) {
        encryptedStoragePluginNames.append(p.name());
    }
    QVERIFY(encryptedStoragePluginNames.contains(DEFAULT_TEST_ENCRYPTEDSTORAGE_PLUGIN));

    QVERIFY(r.authenticationPlugins().size());
    QStringList authenticationPluginNames;
    for (auto p : r.authenticationPlugins()) {
        authenticationPluginNames.append(p.name());
    }
    QVERIFY(authenticationPluginNames.contains(IN_APP_TEST_AUTHENTICATION_PLUGIN));
}

void tst_secretsrequests::devicelockCollection()
{
    // create a new collection
    CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    QSignalSpy ccrss(&ccr, &CreateCollectionRequest::statusChanged);
    ccr.setCollectionLockType(CreateCollectionRequest::DeviceLock);
    QCOMPARE(ccr.collectionLockType(), CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(ccr.collectionName(), QLatin1String("testcollection"));
    ccr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
    QCOMPARE(ccr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
    ccr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    QCOMPARE(ccr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked);
    QCOMPARE(ccr.deviceLockUnlockSemantic(), SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(SecretManager::OwnerOnlyMode);
    QCOMPARE(ccr.accessControlMode(), SecretManager::OwnerOnlyMode);
    QCOMPARE(ccr.status(), Request::Inactive);
    ccr.startRequest();
    QCOMPARE(ccrss.count(), 1);
    QCOMPARE(ccr.status(), Request::Active);
    QCOMPARE(ccr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccrss.count(), 2);
    QCOMPARE(ccr.status(), Request::Finished);
    QCOMPARE(ccr.result().code(), Result::Succeeded);

    // ensure that the name of the collection is returned from a CollectionNamesRequest
    CollectionNamesRequest cnr;
    cnr.setManager(&sm);
    QSignalSpy cnrss(&cnr, &CollectionNamesRequest::statusChanged);
    QCOMPARE(cnr.status(), Request::Inactive);
    cnr.startRequest();
    QCOMPARE(cnrss.count(), 1);
    QCOMPARE(cnr.status(), Request::Active);
    QCOMPARE(cnr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(cnr);
    QCOMPARE(cnrss.count(), 2);
    QCOMPARE(cnr.status(), Request::Finished);
    QCOMPARE(cnr.result().code(), Result::Succeeded);
    QCOMPARE(cnr.collectionNames(), QStringList() << QLatin1String("testcollection"));

    // delete the collection
    DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    QSignalSpy dcrss(&dcr, &DeleteCollectionRequest::statusChanged);
    dcr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(dcr.collectionName(), QLatin1String("testcollection"));
    dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.status(), Request::Inactive);
    dcr.startRequest();
    QCOMPARE(dcrss.count(), 1);
    QCOMPARE(dcr.status(), Request::Active);
    QCOMPARE(dcr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcrss.count(), 2);
    QCOMPARE(dcr.status(), Request::Finished);
    QCOMPARE(dcr.result().code(), Result::Succeeded);

    // ensure that it is no longer returned.
    cnr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(cnr);
    QVERIFY(cnr.collectionNames().isEmpty());
}

void tst_secretsrequests::devicelockCollectionSecret()
{
    // create a collection
    CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    QSignalSpy ccrss(&ccr, &CreateCollectionRequest::statusChanged);
    ccr.setCollectionLockType(CreateCollectionRequest::DeviceLock);
    QCOMPARE(ccr.collectionLockType(), CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(ccr.collectionName(), QLatin1String("testcollection"));
    ccr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
    QCOMPARE(ccr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
    ccr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    QCOMPARE(ccr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked);
    QCOMPARE(ccr.deviceLockUnlockSemantic(), SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(SecretManager::OwnerOnlyMode);
    QCOMPARE(ccr.accessControlMode(), SecretManager::OwnerOnlyMode);
    QCOMPARE(ccr.status(), Request::Inactive);
    ccr.startRequest();
    QCOMPARE(ccrss.count(), 1);
    QCOMPARE(ccr.status(), Request::Active);
    QCOMPARE(ccr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccrss.count(), 2);
    QCOMPARE(ccr.status(), Request::Finished);
    QCOMPARE(ccr.result().code(), Result::Succeeded);

    // store a new secret into the collection
    Secret testSecret(Secret::Identifier(
                        QLatin1String("testsecretname"),
                        QLatin1String("testcollection")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

    StoreSecretRequest ssr;
    ssr.setManager(&sm);
    QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
    ssr.setSecretStorageType(StoreSecretRequest::CollectionSecret);
    QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::CollectionSecret);
    ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
    ssr.setSecret(testSecret);
    QCOMPARE(ssr.secret(), testSecret);
    QCOMPARE(ssr.status(), Request::Inactive);
    ssr.startRequest();
    QCOMPARE(ssrss.count(), 1);
    QCOMPARE(ssr.status(), Request::Active);
    QCOMPARE(ssr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
    QCOMPARE(ssrss.count(), 2);
    QCOMPARE(ssr.status(), Request::Finished);
    QCOMPARE(ssr.result().code(), Result::Succeeded);

    // retrieve the secret, ensure it matches
    StoredSecretRequest gsr;
    gsr.setManager(&sm);
    QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
    gsr.setIdentifier(testSecret.identifier());
    QCOMPARE(gsr.identifier(), testSecret.identifier());
    gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.status(), Request::Inactive);
    gsr.startRequest();
    QCOMPARE(gsrss.count(), 1);
    QCOMPARE(gsr.status(), Request::Active);
    QCOMPARE(gsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsrss.count(), 2);
    QCOMPARE(gsr.status(), Request::Finished);
    QCOMPARE(gsr.result().code(), Result::Succeeded);
    QCOMPARE(gsr.secret(), testSecret);

    // test filtering, first with AND with both matching metadata field values, expect match
    Secret::FilterData filter;
    filter.insert(QLatin1String("domain"), testSecret.filterData(QLatin1String("domain")));
    filter.insert(QLatin1String("test"), testSecret.filterData(QLatin1String("test")));

    FindSecretsRequest fsr;
    fsr.setManager(&sm);
    QSignalSpy fsrss(&fsr, &FindSecretsRequest::statusChanged);
    fsr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(fsr.collectionName(), QLatin1String("testcollection"));
    fsr.setFilter(filter);
    QCOMPARE(fsr.filter(), filter);
    fsr.setFilterOperator(SecretManager::OperatorAnd);
    QCOMPARE(fsr.filterOperator(), SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(SecretManager::PreventInteraction);
    QCOMPARE(fsr.userInteractionMode(), SecretManager::PreventInteraction);
    QCOMPARE(fsr.status(), Request::Inactive);
    fsr.startRequest();
    QCOMPARE(fsrss.count(), 1);
    QCOMPARE(fsr.status(), Request::Active);
    QCOMPARE(fsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsrss.count(), 2);
    QCOMPARE(fsr.status(), Request::Finished);
    QCOMPARE(fsr.result().code(), Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 1);
    QCOMPARE(fsr.identifiers().at(0), testSecret.identifier());

    // now test filtering with AND with one matching and one non-matching value, expect no-match
    filter.insert(QLatin1String("test"), QLatin1String("false"));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Request::Finished);
    QCOMPARE(fsr.result().code(), Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 0);

    // test filtering with OR with one matching and one non-matching value, expect match
    fsr.setFilterOperator(SecretManager::OperatorOr);
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Request::Finished);
    QCOMPARE(fsr.result().code(), Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 1);
    QCOMPARE(fsr.identifiers().at(0), testSecret.identifier());

    // test filtering with OR with zero matching values, expect no-match
    filter.insert(QLatin1String("domain"), QLatin1String("jolla.com"));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Request::Finished);
    QCOMPARE(fsr.result().code(), Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 0);

    // delete the secret
    DeleteSecretRequest dsr;
    dsr.setManager(&sm);
    QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
    dsr.setIdentifier(testSecret.identifier());
    QCOMPARE(dsr.identifier(), testSecret.identifier());
    dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.status(), Request::Inactive);
    dsr.startRequest();
    QCOMPARE(dsrss.count(), 1);
    QCOMPARE(dsr.status(), Request::Active);
    QCOMPARE(dsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
    QCOMPARE(dsrss.count(), 2);
    QCOMPARE(dsr.status(), Request::Finished);
    QCOMPARE(dsr.result().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Result::Failed);

    // finally, clean up the collection
    DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    QSignalSpy dcrss(&dcr, &DeleteCollectionRequest::statusChanged);
    dcr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(dcr.collectionName(), QLatin1String("testcollection"));
    dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.status(), Request::Inactive);
    dcr.startRequest();
    QCOMPARE(dcrss.count(), 1);
    QCOMPARE(dcr.status(), Request::Active);
    QCOMPARE(dcr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcrss.count(), 2);
    QCOMPARE(dcr.status(), Request::Finished);
    QCOMPARE(dcr.result().code(), Result::Succeeded);
}


void tst_secretsrequests::devicelockStandaloneSecret()
{
    // write the secret
    Secret testSecret(Secret::Identifier("testsecretname"));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

    StoreSecretRequest ssr;
    ssr.setManager(&sm);
    QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
    ssr.setSecretStorageType(StoreSecretRequest::StandaloneDeviceLockSecret);
    QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::StandaloneDeviceLockSecret);
    ssr.setDeviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked);
    QCOMPARE(ssr.deviceLockUnlockSemantic(), SecretManager::DeviceLockKeepUnlocked);
    ssr.setAccessControlMode(SecretManager::OwnerOnlyMode);
    QCOMPARE(ssr.accessControlMode(), SecretManager::OwnerOnlyMode);
    ssr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
    QCOMPARE(ssr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
    ssr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    QCOMPARE(ssr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
    ssr.setSecret(testSecret);
    QCOMPARE(ssr.secret(), testSecret);
    QCOMPARE(ssr.status(), Request::Inactive);
    ssr.startRequest();
    QCOMPARE(ssrss.count(), 1);
    QCOMPARE(ssr.status(), Request::Active);
    QCOMPARE(ssr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
    QCOMPARE(ssrss.count(), 2);
    QCOMPARE(ssr.status(), Request::Finished);
    QCOMPARE(ssr.result().code(), Result::Succeeded);

    // read the secret
    StoredSecretRequest gsr;
    gsr.setManager(&sm);
    QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
    gsr.setIdentifier(testSecret.identifier());
    QCOMPARE(gsr.identifier(), testSecret.identifier());
    gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.status(), Request::Inactive);
    gsr.startRequest();
    QCOMPARE(gsrss.count(), 1);
    QCOMPARE(gsr.status(), Request::Active);
    QCOMPARE(gsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsrss.count(), 2);
    QCOMPARE(gsr.status(), Request::Finished);
    QCOMPARE(gsr.result().code(), Result::Succeeded);
    QCOMPARE(gsr.secret(), testSecret);

    // delete the secret
    DeleteSecretRequest dsr;
    dsr.setManager(&sm);
    QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
    dsr.setIdentifier(testSecret.identifier());
    QCOMPARE(dsr.identifier(), testSecret.identifier());
    dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.status(), Request::Inactive);
    dsr.startRequest();
    QCOMPARE(dsrss.count(), 1);
    QCOMPARE(dsr.status(), Request::Active);
    QCOMPARE(dsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
    QCOMPARE(dsrss.count(), 2);
    QCOMPARE(dsr.status(), Request::Finished);
    QCOMPARE(dsr.result().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Result::Failed);
}

void tst_secretsrequests::customlockCollection()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secretsrequests.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &sm));

    // create a new custom-lock collection
    CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    QSignalSpy ccrss(&ccr, &CreateCollectionRequest::statusChanged);
    ccr.setCollectionLockType(CreateCollectionRequest::CustomLock);
    QCOMPARE(ccr.collectionLockType(), CreateCollectionRequest::CustomLock);
    ccr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(ccr.collectionName(), QLatin1String("testcollection"));
    ccr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
    QCOMPARE(ccr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
    ccr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    QCOMPARE(ccr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    QCOMPARE(ccr.authenticationPluginName(), IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setCustomLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked);
    QCOMPARE(ccr.customLockUnlockSemantic(), SecretManager::CustomLockKeepUnlocked);
    ccr.setAccessControlMode(SecretManager::OwnerOnlyMode);
    QCOMPARE(ccr.accessControlMode(), SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ccr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(ccr.status(), Request::Inactive);
    ccr.startRequest();
    QCOMPARE(ccrss.count(), 1);
    QCOMPARE(ccr.status(), Request::Active);
    QCOMPARE(ccr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccrss.count(), 2);
    QCOMPARE(ccr.status(), Request::Finished);
    QCOMPARE(ccr.result().code(), Result::Succeeded);

    // delete the collection
    DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    QSignalSpy dcrss(&dcr, &DeleteCollectionRequest::statusChanged);
    dcr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(dcr.collectionName(), QLatin1String("testcollection"));
    dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.status(), Request::Inactive);
    dcr.startRequest();
    QCOMPARE(dcrss.count(), 1);
    QCOMPARE(dcr.status(), Request::Active);
    QCOMPARE(dcr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcrss.count(), 2);
    QCOMPARE(dcr.status(), Request::Finished);
    QCOMPARE(dcr.result().code(), Result::Succeeded);
}

void tst_secretsrequests::customlockCollectionSecret()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secretsrequests.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &sm));

    // create a new custom-lock collection
    CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    QSignalSpy ccrss(&ccr, &CreateCollectionRequest::statusChanged);
    ccr.setCollectionLockType(CreateCollectionRequest::CustomLock);
    QCOMPARE(ccr.collectionLockType(), CreateCollectionRequest::CustomLock);
    ccr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(ccr.collectionName(), QLatin1String("testcollection"));
    ccr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
    QCOMPARE(ccr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
    ccr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    QCOMPARE(ccr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    QCOMPARE(ccr.authenticationPluginName(), IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setCustomLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked);
    QCOMPARE(ccr.customLockUnlockSemantic(), SecretManager::CustomLockKeepUnlocked);
    ccr.setAccessControlMode(SecretManager::OwnerOnlyMode);
    QCOMPARE(ccr.accessControlMode(), SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ccr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(ccr.status(), Request::Inactive);
    ccr.startRequest();
    QCOMPARE(ccrss.count(), 1);
    QCOMPARE(ccr.status(), Request::Active);
    QCOMPARE(ccr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccrss.count(), 2);
    QCOMPARE(ccr.status(), Request::Finished);
    QCOMPARE(ccr.result().code(), Result::Succeeded);

    // store a new secret into that collection
    Secret testSecret(
                Secret::Identifier(
                    QLatin1String("testsecretname"),
                    QLatin1String("testcollection")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

    StoreSecretRequest ssr;
    ssr.setManager(&sm);
    QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
    ssr.setSecretStorageType(StoreSecretRequest::CollectionSecret);
    QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::CollectionSecret);
    ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
    ssr.setSecret(testSecret);
    QCOMPARE(ssr.secret(), testSecret);
    QCOMPARE(ssr.status(), Request::Inactive);
    ssr.startRequest();
    QCOMPARE(ssrss.count(), 1);
    QCOMPARE(ssr.status(), Request::Active);
    QCOMPARE(ssr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
    QCOMPARE(ssrss.count(), 2);
    QCOMPARE(ssr.status(), Request::Finished);
    QCOMPARE(ssr.result().code(), Result::Succeeded);

    // retrieve the secret
    StoredSecretRequest gsr;
    gsr.setManager(&sm);
    QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
    gsr.setIdentifier(testSecret.identifier());
    QCOMPARE(gsr.identifier(), testSecret.identifier());
    gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.status(), Request::Inactive);
    gsr.startRequest();
    QCOMPARE(gsrss.count(), 1);
    QCOMPARE(gsr.status(), Request::Active);
    QCOMPARE(gsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsrss.count(), 2);
    QCOMPARE(gsr.status(), Request::Finished);
    QCOMPARE(gsr.result().code(), Result::Succeeded);
    QCOMPARE(gsr.secret(), testSecret);

    // delete the secret
    DeleteSecretRequest dsr;
    dsr.setManager(&sm);
    QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
    dsr.setIdentifier(testSecret.identifier());
    QCOMPARE(dsr.identifier(), testSecret.identifier());
    dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.status(), Request::Inactive);
    dsr.startRequest();
    QCOMPARE(dsrss.count(), 1);
    QCOMPARE(dsr.status(), Request::Active);
    QCOMPARE(dsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
    QCOMPARE(dsrss.count(), 2);
    QCOMPARE(dsr.status(), Request::Finished);
    QCOMPARE(dsr.result().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Result::Failed);

    // finally, clean up the collection
    DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    QSignalSpy dcrss(&dcr, &DeleteCollectionRequest::statusChanged);
    dcr.setCollectionName(QLatin1String("testcollection"));
    QCOMPARE(dcr.collectionName(), QLatin1String("testcollection"));
    dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.status(), Request::Inactive);
    dcr.startRequest();
    QCOMPARE(dcrss.count(), 1);
    QCOMPARE(dcr.status(), Request::Active);
    QCOMPARE(dcr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcrss.count(), 2);
    QCOMPARE(dcr.status(), Request::Finished);
    QCOMPARE(dcr.result().code(), Result::Succeeded);
}


void tst_secretsrequests::customlockStandaloneSecret()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secretsrequests.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &sm));

    Secret testSecret(Secret::Identifier(QLatin1String("testsecretname")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // store the secret
    StoreSecretRequest ssr;
    ssr.setManager(&sm);
    QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
    ssr.setSecretStorageType(StoreSecretRequest::StandaloneCustomLockSecret);
    QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::StandaloneCustomLockSecret);
    ssr.setCustomLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked);
    QCOMPARE(ssr.customLockUnlockSemantic(), SecretManager::CustomLockKeepUnlocked);
    ssr.setAccessControlMode(SecretManager::OwnerOnlyMode);
    QCOMPARE(ssr.accessControlMode(), SecretManager::OwnerOnlyMode);
    ssr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
    QCOMPARE(ssr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
    ssr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
    QCOMPARE(ssr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
    ssr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    QCOMPARE(ssr.authenticationPluginName(), IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
    ssr.setSecret(testSecret);
    QCOMPARE(ssr.secret(), testSecret);
    QCOMPARE(ssr.status(), Request::Inactive);
    ssr.startRequest();
    QCOMPARE(ssrss.count(), 1);
    QCOMPARE(ssr.status(), Request::Active);
    QCOMPARE(ssr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
    QCOMPARE(ssrss.count(), 2);
    QCOMPARE(ssr.status(), Request::Finished);
    QCOMPARE(ssr.result().code(), Result::Succeeded);

    // retrieve the secret
    StoredSecretRequest gsr;
    gsr.setManager(&sm);
    QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
    gsr.setIdentifier(testSecret.identifier());
    QCOMPARE(gsr.identifier(), testSecret.identifier());
    gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.status(), Request::Inactive);
    gsr.startRequest();
    QCOMPARE(gsrss.count(), 1);
    QCOMPARE(gsr.status(), Request::Active);
    QCOMPARE(gsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsrss.count(), 2);
    QCOMPARE(gsr.status(), Request::Finished);
    QCOMPARE(gsr.result().code(), Result::Succeeded);
    QCOMPARE(gsr.secret(), testSecret);

    // delete the secret
    DeleteSecretRequest dsr;
    dsr.setManager(&sm);
    QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
    dsr.setIdentifier(testSecret.identifier());
    QCOMPARE(dsr.identifier(), testSecret.identifier());
    dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.status(), Request::Inactive);
    dsr.startRequest();
    QCOMPARE(dsrss.count(), 1);
    QCOMPARE(dsr.status(), Request::Active);
    QCOMPARE(dsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
    QCOMPARE(dsrss.count(), 2);
    QCOMPARE(dsr.status(), Request::Finished);
    QCOMPARE(dsr.result().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Result::Failed);
}

void tst_secretsrequests::encryptedStorageCollection()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secretsrequests.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &sm));

    // create a new custom-lock collection stored in by an encrypted storage plugin
    CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    QSignalSpy ccrss(&ccr, &CreateCollectionRequest::statusChanged);
    ccr.setCollectionLockType(CreateCollectionRequest::CustomLock);
    QCOMPARE(ccr.collectionLockType(), CreateCollectionRequest::CustomLock);
    ccr.setCollectionName(QLatin1String("testencryptedcollection"));
    QCOMPARE(ccr.collectionName(), QLatin1String("testencryptedcollection"));
    ccr.setStoragePluginName(DEFAULT_TEST_ENCRYPTEDSTORAGE_PLUGIN);
    QCOMPARE(ccr.storagePluginName(), DEFAULT_TEST_ENCRYPTEDSTORAGE_PLUGIN);
    ccr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTEDSTORAGE_PLUGIN);
    QCOMPARE(ccr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTEDSTORAGE_PLUGIN);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    QCOMPARE(ccr.authenticationPluginName(), IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setCustomLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked);
    QCOMPARE(ccr.customLockUnlockSemantic(), SecretManager::CustomLockKeepUnlocked);
    ccr.setAccessControlMode(SecretManager::OwnerOnlyMode);
    QCOMPARE(ccr.accessControlMode(), SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ccr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(ccr.status(), Request::Inactive);
    ccr.startRequest();
    QCOMPARE(ccrss.count(), 1);
    QCOMPARE(ccr.status(), Request::Active);
    QCOMPARE(ccr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccrss.count(), 2);
    QCOMPARE(ccr.status(), Request::Finished);
    QCOMPARE(ccr.result().code(), Result::Succeeded);

    // store a secret into the collection
    Secret testSecret(
                Secret::Identifier(
                    QLatin1String("testsecretname"),
                    QLatin1String("testencryptedcollection")));
    testSecret.setData("testsecretvalue");
    testSecret.setType(Secret::TypeBlob);
    testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

    StoreSecretRequest ssr;
    ssr.setManager(&sm);
    QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
    ssr.setSecretStorageType(StoreSecretRequest::CollectionSecret);
    QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::CollectionSecret);
    ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
    ssr.setSecret(testSecret);
    QCOMPARE(ssr.secret(), testSecret);
    QCOMPARE(ssr.status(), Request::Inactive);
    ssr.startRequest();
    QCOMPARE(ssrss.count(), 1);
    QCOMPARE(ssr.status(), Request::Active);
    QCOMPARE(ssr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
    QCOMPARE(ssrss.count(), 2);
    QCOMPARE(ssr.status(), Request::Finished);
    QCOMPARE(ssr.result().code(), Result::Succeeded);

    // retrieve the secret, ensure it matches
    StoredSecretRequest gsr;
    gsr.setManager(&sm);
    QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
    gsr.setIdentifier(testSecret.identifier());
    QCOMPARE(gsr.identifier(), testSecret.identifier());
    gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(gsr.status(), Request::Inactive);
    gsr.startRequest();
    QCOMPARE(gsrss.count(), 1);
    QCOMPARE(gsr.status(), Request::Active);
    QCOMPARE(gsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsrss.count(), 2);
    QCOMPARE(gsr.status(), Request::Finished);
    QCOMPARE(gsr.result().code(), Result::Succeeded);
    QCOMPARE(gsr.secret(), testSecret);

    // delete the secret
    DeleteSecretRequest dsr;
    dsr.setManager(&sm);
    QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
    dsr.setIdentifier(testSecret.identifier());
    QCOMPARE(dsr.identifier(), testSecret.identifier());
    dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dsr.status(), Request::Inactive);
    dsr.startRequest();
    QCOMPARE(dsrss.count(), 1);
    QCOMPARE(dsr.status(), Request::Active);
    QCOMPARE(dsr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
    QCOMPARE(dsrss.count(), 2);
    QCOMPARE(dsr.status(), Request::Finished);
    QCOMPARE(dsr.result().code(), Result::Succeeded);

    // ensure that the delete worked properly.
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Result::Failed);

    // finally, clean up the collection
    DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    QSignalSpy dcrss(&dcr, &DeleteCollectionRequest::statusChanged);
    dcr.setCollectionName(QLatin1String("testencryptedcollection"));
    QCOMPARE(dcr.collectionName(), QLatin1String("testencryptedcollection"));
    dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.userInteractionMode(), SecretManager::ApplicationInteraction);
    QCOMPARE(dcr.status(), Request::Inactive);
    dcr.startRequest();
    QCOMPARE(dcrss.count(), 1);
    QCOMPARE(dcr.status(), Request::Active);
    QCOMPARE(dcr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcrss.count(), 2);
    QCOMPARE(dcr.status(), Request::Finished);
    QCOMPARE(dcr.result().code(), Result::Succeeded);
}

void tst_secretsrequests::storeUserSecret()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secretsrequests.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &sm));

    // in this test, the secret data is requested from the user by the secrets service.
    {
        // test storing the secret in a device-locked collection.
        // create a collection
        CreateCollectionRequest ccr;
        ccr.setManager(&sm);
        QSignalSpy ccrss(&ccr, &CreateCollectionRequest::statusChanged);
        ccr.setCollectionLockType(CreateCollectionRequest::DeviceLock);
        QCOMPARE(ccr.collectionLockType(), CreateCollectionRequest::DeviceLock);
        ccr.setCollectionName(QLatin1String("testcollection"));
        QCOMPARE(ccr.collectionName(), QLatin1String("testcollection"));
        ccr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
        QCOMPARE(ccr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
        ccr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
        QCOMPARE(ccr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
        ccr.setDeviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked);
        QCOMPARE(ccr.deviceLockUnlockSemantic(), SecretManager::DeviceLockKeepUnlocked);
        ccr.setAccessControlMode(SecretManager::OwnerOnlyMode);
        QCOMPARE(ccr.accessControlMode(), SecretManager::OwnerOnlyMode);
        QCOMPARE(ccr.status(), Request::Inactive);
        ccr.startRequest();
        QCOMPARE(ccrss.count(), 1);
        QCOMPARE(ccr.status(), Request::Active);
        QCOMPARE(ccr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
        QCOMPARE(ccrss.count(), 2);
        QCOMPARE(ccr.status(), Request::Finished);
        QCOMPARE(ccr.result().code(), Result::Succeeded);

        // store a new secret into the collection, where the secret data is requested from the user.
        Secret testSecret(Secret::Identifier(
                            QLatin1String("testsecretname"),
                            QLatin1String("testcollection")));
        testSecret.setType(Secret::TypeBlob);
        testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
        testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

        InteractionParameters uiParams;
        uiParams.setInputType(InteractionParameters::AlphaNumericInput);
        uiParams.setEchoMode(InteractionParameters::NormalEcho);
        uiParams.setPromptText(tr("Enter the secret data"));
        uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);

        StoreSecretRequest ssr;
        ssr.setManager(&sm);
        QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
        ssr.setSecretStorageType(StoreSecretRequest::CollectionSecret);
        QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::CollectionSecret);
        ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
        ssr.setSecret(testSecret);
        QCOMPARE(ssr.secret(), testSecret);
        ssr.setInteractionParameters(uiParams);
        QCOMPARE(ssr.interactionParameters(), uiParams);
        QCOMPARE(ssr.status(), Request::Inactive);
        ssr.startRequest();
        QCOMPARE(ssrss.count(), 1);
        QCOMPARE(ssr.status(), Request::Active);
        QCOMPARE(ssr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
        QCOMPARE(ssrss.count(), 2);
        QCOMPARE(ssr.status(), Request::Finished);
        QCOMPARE(ssr.result().code(), Result::Succeeded);

        // retrieve the secret, ensure it has the expected data.
        StoredSecretRequest gsr;
        gsr.setManager(&sm);
        QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
        gsr.setIdentifier(testSecret.identifier());
        QCOMPARE(gsr.identifier(), testSecret.identifier());
        gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.status(), Request::Inactive);
        gsr.startRequest();
        QCOMPARE(gsrss.count(), 1);
        QCOMPARE(gsr.status(), Request::Active);
        QCOMPARE(gsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsrss.count(), 2);
        QCOMPARE(gsr.status(), Request::Finished);
        QCOMPARE(gsr.result().code(), Result::Succeeded);
        Secret expectedSecret = testSecret;
        expectedSecret.setData("example custom password");
        QCOMPARE(gsr.secret(), expectedSecret);

        // delete the secret
        DeleteSecretRequest dsr;
        dsr.setManager(&sm);
        QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
        dsr.setIdentifier(testSecret.identifier());
        QCOMPARE(dsr.identifier(), testSecret.identifier());
        dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.status(), Request::Inactive);
        dsr.startRequest();
        QCOMPARE(dsrss.count(), 1);
        QCOMPARE(dsr.status(), Request::Active);
        QCOMPARE(dsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
        QCOMPARE(dsrss.count(), 2);
        QCOMPARE(dsr.status(), Request::Finished);
        QCOMPARE(dsr.result().code(), Result::Succeeded);

        // ensure that the delete worked properly.
        gsr.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsr.result().code(), Result::Failed);

        // finally, clean up the collection
        DeleteCollectionRequest dcr;
        dcr.setManager(&sm);
        QSignalSpy dcrss(&dcr, &DeleteCollectionRequest::statusChanged);
        dcr.setCollectionName(QLatin1String("testcollection"));
        QCOMPARE(dcr.collectionName(), QLatin1String("testcollection"));
        dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(dcr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(dcr.status(), Request::Inactive);
        dcr.startRequest();
        QCOMPARE(dcrss.count(), 1);
        QCOMPARE(dcr.status(), Request::Active);
        QCOMPARE(dcr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
        QCOMPARE(dcrss.count(), 2);
        QCOMPARE(dcr.status(), Request::Finished);
        QCOMPARE(dcr.result().code(), Result::Succeeded);
    }

    {
        // now a standalone device-locked secret.
        // write the secret
        Secret testSecret(Secret::Identifier("testsecretname"));
        testSecret.setType(Secret::TypeBlob);
        testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
        testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

        InteractionParameters uiParams;
        uiParams.setInputType(InteractionParameters::AlphaNumericInput);
        uiParams.setEchoMode(InteractionParameters::NormalEcho);
        uiParams.setPromptText(tr("Enter the secret data"));
        uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);

        StoreSecretRequest ssr;
        ssr.setManager(&sm);
        QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
        ssr.setSecretStorageType(StoreSecretRequest::StandaloneDeviceLockSecret);
        QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::StandaloneDeviceLockSecret);
        ssr.setDeviceLockUnlockSemantic(SecretManager::DeviceLockKeepUnlocked);
        QCOMPARE(ssr.deviceLockUnlockSemantic(), SecretManager::DeviceLockKeepUnlocked);
        ssr.setAccessControlMode(SecretManager::OwnerOnlyMode);
        QCOMPARE(ssr.accessControlMode(), SecretManager::OwnerOnlyMode);
        ssr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
        QCOMPARE(ssr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
        ssr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
        QCOMPARE(ssr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
        ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
        ssr.setSecret(testSecret);
        QCOMPARE(ssr.secret(), testSecret);
        ssr.setInteractionParameters(uiParams);
        QCOMPARE(ssr.interactionParameters(), uiParams);
        QCOMPARE(ssr.status(), Request::Inactive);
        ssr.startRequest();
        QCOMPARE(ssrss.count(), 1);
        QCOMPARE(ssr.status(), Request::Active);
        QCOMPARE(ssr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
        QCOMPARE(ssrss.count(), 2);
        QCOMPARE(ssr.status(), Request::Finished);
        QCOMPARE(ssr.result().code(), Result::Succeeded);

        // read the secret
        StoredSecretRequest gsr;
        gsr.setManager(&sm);
        QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
        gsr.setIdentifier(testSecret.identifier());
        QCOMPARE(gsr.identifier(), testSecret.identifier());
        gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.status(), Request::Inactive);
        gsr.startRequest();
        QCOMPARE(gsrss.count(), 1);
        QCOMPARE(gsr.status(), Request::Active);
        QCOMPARE(gsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsrss.count(), 2);
        QCOMPARE(gsr.status(), Request::Finished);
        QCOMPARE(gsr.result().code(), Result::Succeeded);
        Secret expectedSecret(testSecret);
        expectedSecret.setData("example custom password");
        QCOMPARE(gsr.secret(), expectedSecret);

        // delete the secret
        DeleteSecretRequest dsr;
        dsr.setManager(&sm);
        QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
        dsr.setIdentifier(testSecret.identifier());
        QCOMPARE(dsr.identifier(), testSecret.identifier());
        dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.status(), Request::Inactive);
        dsr.startRequest();
        QCOMPARE(dsrss.count(), 1);
        QCOMPARE(dsr.status(), Request::Active);
        QCOMPARE(dsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
        QCOMPARE(dsrss.count(), 2);
        QCOMPARE(dsr.status(), Request::Finished);
        QCOMPARE(dsr.result().code(), Result::Succeeded);

        // ensure that the delete worked properly.
        gsr.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsr.result().code(), Result::Failed);
    }

    {
        // now a custom-locked collection secret.
        // create a new custom-lock collection
        CreateCollectionRequest ccr;
        ccr.setManager(&sm);
        QSignalSpy ccrss(&ccr, &CreateCollectionRequest::statusChanged);
        ccr.setCollectionLockType(CreateCollectionRequest::CustomLock);
        QCOMPARE(ccr.collectionLockType(), CreateCollectionRequest::CustomLock);
        ccr.setCollectionName(QLatin1String("testcollection"));
        QCOMPARE(ccr.collectionName(), QLatin1String("testcollection"));
        ccr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
        QCOMPARE(ccr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
        ccr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
        QCOMPARE(ccr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
        ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
        QCOMPARE(ccr.authenticationPluginName(), IN_APP_TEST_AUTHENTICATION_PLUGIN);
        ccr.setCustomLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked);
        QCOMPARE(ccr.customLockUnlockSemantic(), SecretManager::CustomLockKeepUnlocked);
        ccr.setAccessControlMode(SecretManager::OwnerOnlyMode);
        QCOMPARE(ccr.accessControlMode(), SecretManager::OwnerOnlyMode);
        ccr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(ccr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(ccr.status(), Request::Inactive);
        ccr.startRequest();
        QCOMPARE(ccrss.count(), 1);
        QCOMPARE(ccr.status(), Request::Active);
        QCOMPARE(ccr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
        QCOMPARE(ccrss.count(), 2);
        QCOMPARE(ccr.status(), Request::Finished);
        QCOMPARE(ccr.result().code(), Result::Succeeded);

        // store a new secret into that collection
        Secret testSecret(
                    Secret::Identifier(
                        QLatin1String("testsecretname"),
                        QLatin1String("testcollection")));
        testSecret.setData("testsecretvalue");
        testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
        testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

        InteractionParameters uiParams;
        uiParams.setInputType(InteractionParameters::AlphaNumericInput);
        uiParams.setEchoMode(InteractionParameters::NormalEcho);
        uiParams.setPromptText(tr("Enter the secret data"));
        uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);

        StoreSecretRequest ssr;
        ssr.setManager(&sm);
        QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
        ssr.setSecretStorageType(StoreSecretRequest::CollectionSecret);
        QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::CollectionSecret);
        ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
        ssr.setSecret(testSecret);
        QCOMPARE(ssr.secret(), testSecret);
        ssr.setInteractionParameters(uiParams);
        QCOMPARE(ssr.interactionParameters(), uiParams);
        QCOMPARE(ssr.status(), Request::Inactive);
        ssr.startRequest();
        QCOMPARE(ssrss.count(), 1);
        QCOMPARE(ssr.status(), Request::Active);
        QCOMPARE(ssr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
        QCOMPARE(ssrss.count(), 2);
        QCOMPARE(ssr.status(), Request::Finished);
        QCOMPARE(ssr.result().code(), Result::Succeeded);

        // retrieve the secret
        StoredSecretRequest gsr;
        gsr.setManager(&sm);
        QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
        gsr.setIdentifier(testSecret.identifier());
        QCOMPARE(gsr.identifier(), testSecret.identifier());
        gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.status(), Request::Inactive);
        gsr.startRequest();
        QCOMPARE(gsrss.count(), 1);
        QCOMPARE(gsr.status(), Request::Active);
        QCOMPARE(gsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsrss.count(), 2);
        QCOMPARE(gsr.status(), Request::Finished);
        QCOMPARE(gsr.result().code(), Result::Succeeded);
        Secret expectedSecret(testSecret);
        expectedSecret.setData("example custom password");
        QCOMPARE(gsr.secret(), expectedSecret);

        // delete the secret
        DeleteSecretRequest dsr;
        dsr.setManager(&sm);
        QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
        dsr.setIdentifier(testSecret.identifier());
        QCOMPARE(dsr.identifier(), testSecret.identifier());
        dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.status(), Request::Inactive);
        dsr.startRequest();
        QCOMPARE(dsrss.count(), 1);
        QCOMPARE(dsr.status(), Request::Active);
        QCOMPARE(dsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
        QCOMPARE(dsrss.count(), 2);
        QCOMPARE(dsr.status(), Request::Finished);
        QCOMPARE(dsr.result().code(), Result::Succeeded);

        // ensure that the delete worked properly.
        gsr.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsr.result().code(), Result::Failed);

        // finally, clean up the collection
        DeleteCollectionRequest dcr;
        dcr.setManager(&sm);
        QSignalSpy dcrss(&dcr, &DeleteCollectionRequest::statusChanged);
        dcr.setCollectionName(QLatin1String("testcollection"));
        QCOMPARE(dcr.collectionName(), QLatin1String("testcollection"));
        dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(dcr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(dcr.status(), Request::Inactive);
        dcr.startRequest();
        QCOMPARE(dcrss.count(), 1);
        QCOMPARE(dcr.status(), Request::Active);
        QCOMPARE(dcr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
        QCOMPARE(dcrss.count(), 2);
        QCOMPARE(dcr.status(), Request::Finished);
        QCOMPARE(dcr.result().code(), Result::Succeeded);
    }

    {
        // now a standalone custom-locked secret.
        Secret testSecret(Secret::Identifier(QLatin1String("testsecretname")));
        testSecret.setType(Secret::TypeBlob);
        testSecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
        testSecret.setFilterData(QLatin1String("test"), QLatin1String("true"));

        InteractionParameters uiParams;
        uiParams.setInputType(InteractionParameters::AlphaNumericInput);
        uiParams.setEchoMode(InteractionParameters::NormalEcho);
        uiParams.setPromptText(tr("Enter the secret data"));
        uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);

        // store the secret
        StoreSecretRequest ssr;
        ssr.setManager(&sm);
        QSignalSpy ssrss(&ssr, &StoreSecretRequest::statusChanged);
        ssr.setSecretStorageType(StoreSecretRequest::StandaloneCustomLockSecret);
        QCOMPARE(ssr.secretStorageType(), StoreSecretRequest::StandaloneCustomLockSecret);
        ssr.setCustomLockUnlockSemantic(SecretManager::CustomLockKeepUnlocked);
        QCOMPARE(ssr.customLockUnlockSemantic(), SecretManager::CustomLockKeepUnlocked);
        ssr.setAccessControlMode(SecretManager::OwnerOnlyMode);
        QCOMPARE(ssr.accessControlMode(), SecretManager::OwnerOnlyMode);
        ssr.setStoragePluginName(DEFAULT_TEST_STORAGE_PLUGIN);
        QCOMPARE(ssr.storagePluginName(), DEFAULT_TEST_STORAGE_PLUGIN);
        ssr.setEncryptionPluginName(DEFAULT_TEST_ENCRYPTION_PLUGIN);
        QCOMPARE(ssr.encryptionPluginName(), DEFAULT_TEST_ENCRYPTION_PLUGIN);
        ssr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
        QCOMPARE(ssr.authenticationPluginName(), IN_APP_TEST_AUTHENTICATION_PLUGIN);
        ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(ssr.userInteractionMode(), SecretManager::ApplicationInteraction);
        ssr.setSecret(testSecret);
        QCOMPARE(ssr.secret(), testSecret);
        ssr.setInteractionParameters(uiParams);
        QCOMPARE(ssr.interactionParameters(), uiParams);
        QCOMPARE(ssr.status(), Request::Inactive);
        ssr.startRequest();
        QCOMPARE(ssrss.count(), 1);
        QCOMPARE(ssr.status(), Request::Active);
        QCOMPARE(ssr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
        QCOMPARE(ssrss.count(), 2);
        QCOMPARE(ssr.status(), Request::Finished);
        QCOMPARE(ssr.result().code(), Result::Succeeded);

        // retrieve the secret
        StoredSecretRequest gsr;
        gsr.setManager(&sm);
        QSignalSpy gsrss(&gsr, &StoredSecretRequest::statusChanged);
        gsr.setIdentifier(testSecret.identifier());
        QCOMPARE(gsr.identifier(), testSecret.identifier());
        gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(gsr.status(), Request::Inactive);
        gsr.startRequest();
        QCOMPARE(gsrss.count(), 1);
        QCOMPARE(gsr.status(), Request::Active);
        QCOMPARE(gsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsrss.count(), 2);
        QCOMPARE(gsr.status(), Request::Finished);
        QCOMPARE(gsr.result().code(), Result::Succeeded);
        Secret expectedSecret(testSecret);
        expectedSecret.setData("example custom password");
        QCOMPARE(gsr.secret(), expectedSecret);

        // delete the secret
        DeleteSecretRequest dsr;
        dsr.setManager(&sm);
        QSignalSpy dsrss(&dsr, &DeleteSecretRequest::statusChanged);
        dsr.setIdentifier(testSecret.identifier());
        QCOMPARE(dsr.identifier(), testSecret.identifier());
        dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.userInteractionMode(), SecretManager::ApplicationInteraction);
        QCOMPARE(dsr.status(), Request::Inactive);
        dsr.startRequest();
        QCOMPARE(dsrss.count(), 1);
        QCOMPARE(dsr.status(), Request::Active);
        QCOMPARE(dsr.result().code(), Result::Pending);
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
        QCOMPARE(dsrss.count(), 2);
        QCOMPARE(dsr.status(), Request::Finished);
        QCOMPARE(dsr.result().code(), Result::Succeeded);

        // ensure that the delete worked properly.
        gsr.startRequest();
        WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
        QCOMPARE(gsr.result().code(), Result::Failed);
    }
}

void tst_secretsrequests::requestUserInput()
{
    // construct the in-process authentication key UI.
    QQuickView v(QUrl::fromLocalFile(QStringLiteral("%1/tst_secretsrequests.qml").arg(QCoreApplication::applicationDirPath())));
    v.show();
    QObject *interactionView = v.rootObject()->findChild<QObject*>("interactionview");
    QVERIFY(interactionView);
    QMetaObject::invokeMethod(interactionView, "setSecretManager", Qt::DirectConnection, Q_ARG(QObject*, &sm));

    // define the interaction parameters
    InteractionParameters uiParams;
    uiParams.setInputType(InteractionParameters::AlphaNumericInput);
    uiParams.setEchoMode(InteractionParameters::NormalEcho);
    uiParams.setPromptText(QLatin1String("Enter the passphrase for the unit test"));
    uiParams.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);

    // request input from the user
    InteractionRequest ir;
    ir.setManager(&sm);
    QSignalSpy irss(&ir, &CreateCollectionRequest::statusChanged);
    ir.setInteractionParameters(uiParams);
    QCOMPARE(ir.interactionParameters(), uiParams);
    QCOMPARE(ir.status(), Request::Inactive);
    ir.startRequest();
    QCOMPARE(irss.count(), 1);
    QCOMPARE(ir.status(), Request::Active);
    QCOMPARE(ir.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ir);
    QCOMPARE(irss.count(), 2);
    QCOMPARE(ir.status(), Request::Finished);
    QCOMPARE(ir.result().code(), Result::Succeeded);
    QCOMPARE(ir.userInput(), QByteArray("example passphrase for unit test"));
}

void tst_secretsrequests::accessControl()
{
    // This test is meant to be run second, with tst_secrets::accessControl() run second.
    // This test must be run as non-privileged, to avoid being classified as a platform app.
    // Artifacts from the test will have to be removed manually from the filesystem.
    QSKIP("This test should only be run manually, as it is not stand-alone!");

    Secret unreadableSecret(Secret::Identifier(
                QLatin1String("unreadablesecret"),
                QLatin1String("owneronlycollection")));
    Secret readableSecret(Secret::Identifier(
                QLatin1String("readablesecret"),
                QLatin1String("noaccesscontrolcollection")));

    // attempt to read a secret in an owner-only collection created by another process.
    // this should fail.
    StoredSecretRequest gsr;
    gsr.setManager(&sm);
    gsr.setIdentifier(unreadableSecret.identifier());
    gsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.status(), Request::Finished);
    QCOMPARE(gsr.result().code(), Result::Failed);
    QCOMPARE(gsr.result().errorCode(), Result::PermissionsError);

    // attempt to delete a secret in an owner-only collection created by another process.
    // this should fail.
    DeleteSecretRequest dsr;
    dsr.setManager(&sm);
    dsr.setIdentifier(unreadableSecret.identifier());
    dsr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    dsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
    QCOMPARE(dsr.status(), Request::Finished);
    QCOMPARE(dsr.result().code(), Result::Failed);
    QCOMPARE(dsr.result().errorCode(), Result::PermissionsError);

    // attempt to store a secret in an owner-only collection created by another process.
    // this should fail.
    Secret failsecret(Secret::Identifier(
                QLatin1String("failsecret"),
                QLatin1String("owneronlycollection")));
    failsecret.setData("failsecretvalue");
    failsecret.setType(Secret::TypeBlob);
    failsecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    failsecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    StoreSecretRequest ssr;
    ssr.setManager(&sm);
    ssr.setSecretStorageType(StoreSecretRequest::CollectionSecret);
    ssr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    ssr.setSecret(failsecret);
    ssr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
    QCOMPARE(ssr.status(), Request::Finished);
    QCOMPARE(ssr.result().code(), Result::Failed);
    QCOMPARE(ssr.result().errorCode(), Result::PermissionsError);

    // attempt to delete an owner-only collection created by another process.
    // this should fail.
    DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("owneronlycollection"));
    dcr.setUserInteractionMode(SecretManager::ApplicationInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Request::Finished);
    QCOMPARE(dcr.result().code(), Result::Failed);
    QCOMPARE(dcr.result().errorCode(), Result::PermissionsError);

    // attempt to read a secret in an owner-only collection created by another process.
    // this should succeed.
    gsr.setIdentifier(readableSecret.identifier());
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.status(), Request::Finished);
    QCOMPARE(gsr.result().code(), Result::Succeeded);
    QCOMPARE(gsr.secret().data(), QByteArray("readablesecretvalue"));

    // attempt to delete a secret in an owner-only collection created by another process.
    // this should succeed.
    dsr.setIdentifier(readableSecret.identifier());
    dsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dsr);
    QCOMPARE(dsr.status(), Request::Finished);
    QCOMPARE(dsr.result().code(), Result::Succeeded);

    // attempt to store a secret in an owner-only collection created by another process.
    // this should succeed.
    Secret succeedsecret(Secret::Identifier(
                QLatin1String("succeedsecret"),
                QLatin1String("noaccesscontrolcollection")));
    succeedsecret.setData("succeedsecretvalue");
    succeedsecret.setType(Secret::TypeBlob);
    succeedsecret.setFilterData(QLatin1String("domain"), QLatin1String("sailfishos.org"));
    succeedsecret.setFilterData(QLatin1String("test"), QLatin1String("true"));
    ssr.setSecret(succeedsecret);
    ssr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ssr);
    QCOMPARE(ssr.status(), Request::Finished);
    QCOMPARE(ssr.result().code(), Result::Succeeded);

    // attempt to delete a no-access-control collection created by another process.
    // this should succeed.
    dcr.setCollectionName(QLatin1String("noaccesscontrolcollection"));
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Request::Finished);
    QCOMPARE(dcr.result().code(), Result::Succeeded);
}

#include "tst_secretsrequests.moc"
QTEST_MAIN(tst_secretsrequests)

