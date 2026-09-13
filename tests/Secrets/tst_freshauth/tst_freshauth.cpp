/* Copyright (C) 2026 Jolla Mobile Ltd
 * BSD 3-Clause License, see LICENSE.
 */
#include <QtTest>
#include <QProcess>
#include <QTemporaryDir>
#include <QUuid>
#include <Secrets/storesecretrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/deletesecretrequest.h>
#include <Secrets/createcollectionrequest.h>
using namespace Sailfish::Secrets;
static Secret::Identifier identifier(const QString &name)
{
    return Secret::Identifier(name, QString(),
                             QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite"));
}
class FreshAuthTest : public QObject
{
    Q_OBJECT
private slots:
    void standalonePolicy()
    {
        SecretManager manager;
        const QString name = QStringLiteral("fresh-auth-test-") + QUuid::createUuid().toString();
        Secret secret(identifier(name));
        secret.setData("non-sensitive test payload");
        StoreSecretRequest store;
        store.setManager(&manager);
        store.setSecretStorageType(StoreSecretRequest::StandaloneDeviceLockSecret);
        store.setSecret(secret);
        store.setEncryptionPluginName(QStringLiteral("org.sailfishos.secrets.plugin.encryption.openssl"));
        store.setDeviceLockUnlockSemantic(SecretManager::DeviceLockAccessRelock);
        store.setAccessControlMode(SecretManager::OwnerOnlyMode);
        store.startRequest();
        QTRY_COMPARE(store.status(), Request::Finished);
        QCOMPARE(store.result().errorCode(), Result::OperationNotSupportedError);
        store.setAccessControlMode(SecretManager::ExactApplicationOwnerMode);
        store.startRequest();
        QTRY_COMPARE(store.status(), Request::Finished);
        QVERIFY2(store.result().code() == Result::Succeeded, qPrintable(store.result().errorMessage()));

        // Always clean up our synthetic record, including on assertion failure.
        struct Cleanup {
            SecretManager *manager;
            Secret::Identifier id;
            ~Cleanup() {
                DeleteSecretRequest request;
                request.setManager(manager);
                request.setIdentifier(id);
                request.setUserInteractionMode(SecretManager::PreventInteraction);
                request.startRequest();
                request.waitForFinished();
            }
        } cleanup { &manager, secret.identifier() };

        StoredSecretRequest read;
        read.setManager(&manager);
        read.setIdentifier(secret.identifier());
        read.setUserInteractionMode(SecretManager::PreventInteraction);
        for (int i = 0; i < 2; ++i) {
            read.startRequest();
            QTRY_COMPARE(read.status(), Request::Finished);
            QCOMPARE(read.result().errorCode(), Result::CollectionIsLockedError);
            QVERIFY(read.secret().data().isEmpty());
        }

        // A distinct executable must fail before any authentication UI.
        QTemporaryDir directory;
        QVERIFY(directory.isValid());
        const QString foreign = directory.path() + QStringLiteral("/foreign-reader");
        QVERIFY(QFile::copy(QCoreApplication::applicationFilePath(), foreign));
        QProcess process;
        process.start(foreign, { QStringLiteral("--foreign-read"), name });
        QVERIFY(process.waitForFinished(15000));
        QCOMPARE(process.exitStatus(), QProcess::NormalExit);
        QCOMPARE(process.exitCode(), 0);

        if (qEnvironmentVariableIsSet("FRESHAUTH_INTERACTIVE")) {
            // Requires a fresh physical authentication for each iteration.
            for (int i = 0; i < 2; ++i) {
                read.setUserInteractionMode(SecretManager::SystemInteraction);
                read.startRequest();
                QTRY_COMPARE_WITH_TIMEOUT(read.status(), Request::Finished, 130000);
                QVERIFY2(read.result().code() == Result::Succeeded, qPrintable(read.result().errorMessage()));
                QCOMPARE(read.secret().data(), secret.data());
                // A successful read must not create a reusable authorization.
                StoredSecretRequest silent;
                silent.setManager(&manager);
                silent.setIdentifier(secret.identifier());
                silent.setUserInteractionMode(SecretManager::PreventInteraction);
                silent.startRequest();
                QTRY_COMPARE(silent.status(), Request::Finished);
                QCOMPARE(silent.result().errorCode(), Result::CollectionIsLockedError);
                QVERIFY(silent.secret().data().isEmpty());
            }
        }
    }
    void collectionPolicyRejected()
    {
        SecretManager manager;
        CreateCollectionRequest request;
        request.setManager(&manager);
        request.setCollectionName(QStringLiteral("fresh-auth-unsupported-collection"));
        request.setStoragePluginName(QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite"));
        request.setEncryptionPluginName(QStringLiteral("org.sailfishos.secrets.plugin.encryption.openssl"));
        request.setDeviceLockUnlockSemantic(SecretManager::DeviceLockAccessRelock);
        request.startRequest();
        QTRY_COMPARE(request.status(), Request::Finished);
        QCOMPARE(request.result().errorCode(), Result::OperationNotSupportedError);
    }
};
int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    if (app.arguments().size() == 3 && app.arguments().at(1) == QLatin1String("--foreign-read")) {
        SecretManager manager;
        StoredSecretRequest request;
        request.setManager(&manager);
        request.setIdentifier(identifier(app.arguments().at(2)));
        request.setUserInteractionMode(SecretManager::PreventInteraction);
        request.startRequest();
        request.waitForFinished();
        return request.result().errorCode() == Result::PermissionsError
                && request.secret().data().isEmpty() ? 0 : 1;
    }
    FreshAuthTest test;
    return QTest::qExec(&test, argc, argv);
}
#include "tst_freshauth.moc"
