/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Bea Lam <bea.lam@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#ifndef SAILFISHSECRETS_CRYPTOTEST_H
#define SAILFISHSECRETS_CRYPTOTEST_H

#include "Crypto/cryptomanager.h"
#include "Crypto/cryptomanager_p.h"
#include "Crypto/serialization_p.h"
#include "Crypto/key.h"
#include "Crypto/result.h"

#include "Secrets/secretmanager.h"
#include "Secrets/secretmanager_p.h"
#include "Secrets/serialization_p.h"
#include "Secrets/result.h"

#include <QtTest>
#include <QDBusReply>
#include <QVariantMap>
#include <QFile>

#define DEFAULT_TEST_CRYPTO_PLUGIN_NAME CryptoManager::DefaultCryptoPluginName + QLatin1String(".test")
#define DEFAULT_PLUGIN_CRYPTO_STORAGE CryptoManager::DefaultCryptoStoragePluginName + QLatin1String(".test")
#define DEFAULT_TEST_STORAGE_PLUGIN Sailfish::Secrets::SecretManager::DefaultStoragePluginName + QLatin1String(".test")
#define DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")
#define PASSWORD_AGENT_TEST_AUTH_PLUGIN Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName + QLatin1String(".test")
#define IN_APP_TEST_AUTHENTICATION_PLUGIN Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName + QLatin1String(".test")
#define DEFAULT_TEST_ENCRYPTION_PLUGIN Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName + QLatin1String(".test")
#define TEST_USB_TOKEN_PLUGIN_NAME QStringLiteral("org.sailfishos.secrets.plugin.cryptostorage.exampleusbtoken.test")

#define WAIT_FOR_DBUS_REPLY(reply) \
    QTRY_VERIFY_WITH_TIMEOUT(reply.isFinished(), 10 * 1000);

#define WAIT_FOR_DBUS_REPLY_SUCCEEDED(reply) \
    WAIT_FOR_DBUS_REPLY(reply); \
    QVERIFY(reply.isValid()); \
    if (reply.argumentAt<0>().code() != (int)Sailfish::Crypto::Result::Succeeded) { \
        qWarning() << "Request failed:" << reply.argumentAt<0>().errorMessage(); \
    } \
    QCOMPARE((int)reply.argumentAt<0>().code(), (int)Sailfish::Crypto::Result::Succeeded); \
    QCOMPARE(reply.argumentAt<0>().errorMessage(), QString());

#define WAIT_FOR_DBUS_REPLY_FAILED(reply) \
    WAIT_FOR_DBUS_REPLY(reply); \
    QVERIFY(reply.isValid()); \
    QCOMPARE((int)reply.argumentAt<0>().code(), (int)Sailfish::Crypto::Result::Failed);


#define WAIT_FOR_REQUEST(request, resultCode, resultError, timeout) \
    if ((int)resultCode == (int)Sailfish::Crypto::Result::Succeeded) { \
        QCOMPARE((int)request.status(), (int)Sailfish::Crypto::Request::Active); \
        QCOMPARE((int)request.result().code(), (int)Sailfish::Crypto::Result::Pending); \
        QCOMPARE(request.result().errorMessage(), QString()); \
    } \
    QTRY_COMPARE_WITH_TIMEOUT((int)request.status(), (int)Sailfish::Crypto::Request::Finished, timeout); \
    QCOMPARE((int)request.status(), (int)Sailfish::Crypto::Request::Finished); \
    if ((int)resultCode == (int)Sailfish::Crypto::Result::Succeeded) { \
        if ((int)request.result().code() != (int)Sailfish::Crypto::Result::Succeeded) { \
            qWarning() << "Request failed:" << request.result().errorMessage(); \
        } \
    } \
    QCOMPARE((int)request.result().code(), (int)resultCode); \
    if ((int)resultCode == (int)Sailfish::Crypto::Result::Succeeded) { \
        QCOMPARE(request.result().errorMessage(), QString()); \
    } \

#define WAIT_FOR_REQUEST_SUCCEEDED(request) \
    WAIT_FOR_REQUEST(request, (int)Sailfish::Crypto::Result::Succeeded, (int)Sailfish::Crypto::Result::NoError, 10 * 1000)

#define WAIT_FOR_REQUEST_FAILED(request, errorCode) \
    WAIT_FOR_REQUEST(request, (int)Sailfish::Crypto::Result::Failed, (int)errorCode, 10 * 1000)

#define WAIT_FOR_REQUEST_RESULT(request, testRequests, key) \
    WAIT_FOR_REQUEST(request, testRequests.value(key).resultCode, testRequests.value(key).resultError, 10 * 1000)

#define WAIT_LONG_FOR_REQUEST_RESULT(request, testRequests, key) \
    WAIT_FOR_REQUEST(request, testRequests.value(key).resultCode, testRequests.value(key).resultError, 60 * 1000)


#define START_AND_WAIT_FOR_REQUEST(request, statusSignalSpy, resultCode, resultError, timeout) \
    m_requestTestCount = statusSignalSpy.count(); \
    QCOMPARE((int)request.status(), (int)Sailfish::Crypto::Request::Inactive); \
    request.startRequest(); \
    if ((int)resultCode == (int)Sailfish::Crypto::Result::Succeeded) { \
        QCOMPARE(statusSignalSpy.count(), m_requestTestCount + 1); \
    } \
    WAIT_FOR_REQUEST(request, resultCode, resultError, 60 * 1000); \
    QCOMPARE(statusSignalSpy.count(), m_requestTestCount + 2); \

#define START_AND_WAIT_FOR_REQUEST_RESULT(request, statusSignalSpy, testRequests, key) \
    START_AND_WAIT_FOR_REQUEST(request, statusSignalSpy, testRequests.value(key).resultCode, testRequests.value(key).resultError, 10 * 1000)


// Defines the QFETCH() calls for the test data added by addCryptoTestData().
#define FETCH_CRYPTO_TEST_DATA \
    QFETCH(TestPluginMap, plugins); \
    QFETCH(CryptoManager::BlockMode, blockMode); \
    QFETCH(CryptoManager::EncryptionPadding, padding); \
    QFETCH(Key, keyTemplate); \
    QFETCH(QByteArray, authData); \
    QFETCH(QByteArray, plaintext); \
    QFETCH(QByteArray, initVector); \
    QFETCH(CryptoTest::TestRequests, testRequests); \

namespace PluginNameMapping {

// NOTE: this is a copy of Sailfish::Secrets::Daemon::Controller::mappedPluginName()!
#define ENV_PERFORM_PLUGIN_MAPPING "SAILFISH_SECRETSD_PERFORM_PLUGIN_MAPPING"
#define ENV_DEFAULT_CRYPTO_PLUGIN "SAILFISH_SECRETSD_DEFAULT_CRYPTO_PLUGIN"
#define ENV_DEFAULT_CRYPTOSTORAGE_PLUGIN "SAILFISH_SECRETSD_DEFAULT_CRYPTOSTORAGE_PLUGIN"
#define ENV_DEFAULT_STORAGE_PLUGIN "SAILFISH_SECRETSD_DEFAULT_STORAGE_PLUGIN"
#define ENV_DEFAULT_ENCRYPTION_PLUGIN "SAILFISH_SECRETSD_DEFAULT_ENCRYPTION_PLUGIN"
#define ENV_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN "SAILFISH_SECRETSD_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN"
#define ENV_DEFAULT_AUTHENTICATION_PLUGIN "SAILFISH_SECRETSD_DEFAULT_AUTHENTICATION_PLUGIN"
#define ENV_INAPP_AUTHENTICATION_PLUGIN "SAILFISH_SECRETSD_INAPP_AUTHENTICATION_PLUGIN"
inline QString mappedPluginName(const QString &pluginName)
{
    static const QString testPluginSuffix(QStringLiteral(".test"));

    static const QString performMapping(
            (!QString::fromUtf8(qgetenv(ENV_PERFORM_PLUGIN_MAPPING)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_PERFORM_PLUGIN_MAPPING))
                    : QStringLiteral("true"));
    static const QString mappedCryptoPluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTO_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTO_PLUGIN))
                    : QStringLiteral("org.sailfishos.crypto.plugin.crypto.openssl"));
    static const QString mappedCryptoStoragePluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTOSTORAGE_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_CRYPTOSTORAGE_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher"));
    static const QString mappedStoragePluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_STORAGE_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_STORAGE_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.storage.sqlite"));
    static const QString mappedEncryptionPluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTION_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTION_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.encryption.openssl"));
    static const QString mappedEncryptedStoragePluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_ENCRYPTEDSTORAGE_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher"));
    static const QString mappedAuthenticationPluginName(
            (!QString::fromUtf8(qgetenv(ENV_DEFAULT_AUTHENTICATION_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_DEFAULT_AUTHENTICATION_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.authentication.passwordagent"));
    static const QString mappedInAppAuthenticationPluginName(
            (!QString::fromUtf8(qgetenv(ENV_INAPP_AUTHENTICATION_PLUGIN)).isEmpty())
                    ? QString::fromUtf8(qgetenv(ENV_INAPP_AUTHENTICATION_PLUGIN))
                    : QStringLiteral("org.sailfishos.secrets.plugin.authentication.inapp"));

    if (!pluginName.isEmpty()
            && (performMapping == QStringLiteral("1")
                || performMapping == QStringLiteral("true")
                || performMapping == QStringLiteral("yes"))) {
        if (pluginName.startsWith(Sailfish::Crypto::CryptoManager::DefaultCryptoPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedCryptoPluginName+testPluginSuffix)
                    : mappedCryptoPluginName;
        } else if (pluginName.startsWith(Sailfish::Crypto::CryptoManager::DefaultCryptoStoragePluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedCryptoStoragePluginName+testPluginSuffix)
                    : mappedCryptoStoragePluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultStoragePluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedStoragePluginName+testPluginSuffix)
                    : mappedStoragePluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultEncryptionPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedEncryptionPluginName+testPluginSuffix)
                    : mappedEncryptionPluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedEncryptedStoragePluginName+testPluginSuffix)
                    : mappedEncryptedStoragePluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::DefaultAuthenticationPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedAuthenticationPluginName+testPluginSuffix)
                    : mappedAuthenticationPluginName;
        } else if (pluginName.startsWith(Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName)) {
            return pluginName.endsWith(testPluginSuffix)
                    ? (mappedInAppAuthenticationPluginName+testPluginSuffix)
                    : mappedInAppAuthenticationPluginName;
        }
    }

    return pluginName;
}

}

class TestCryptoManager : public Sailfish::Crypto::CryptoManager
{
    Q_OBJECT

public:
    TestCryptoManager(QObject *parent = Q_NULLPTR)
        : Sailfish::Crypto::CryptoManager(parent) {}
    ~TestCryptoManager() {}
    Sailfish::Crypto::CryptoManagerPrivate *priv() const { return Sailfish::Crypto::CryptoManager::pimpl(); }
};


class TestSecretManager : public Sailfish::Secrets::SecretManager
{
    Q_OBJECT

public:
    TestSecretManager(QObject *parent = Q_NULLPTR)
        : Sailfish::Secrets::SecretManager(parent) {}
    ~TestSecretManager() {}
    Sailfish::Secrets::SecretManagerPrivate *priv() const { return Sailfish::Secrets::SecretManager::pimpl(); }
};

class CryptoTest : public QObject
{
    Q_OBJECT

public:
    enum AuthenticationMode {
        NoAuthentication,
        Authentication
    };
    Q_ENUM(AuthenticationMode)

    enum PluginType {
        CryptoPlugin,
        StoragePlugin,
        AuthenticationPlugin,
        InAppAuthenticationPlugin,
        EncryptionPlugin
    };
    Q_ENUM(PluginType)

    typedef QMap<PluginType, QString> TestPluginMap;

    struct TestRequest {
        TestRequest() {}
        TestRequest(Sailfish::Crypto::Result::ResultCode rc,
                    Sailfish::Crypto::Result::ErrorCode err,
                    const QVariantMap &map = QVariantMap())
            : customerParameters(map), resultCode(rc), errorCode(err) {}
        TestRequest(Sailfish::Secrets::Result::ResultCode rc,
                    Sailfish::Secrets::Result::ErrorCode err,
                    const QVariantMap &map = QVariantMap())
            : customerParameters(map), resultCode(rc), errorCode(err) {}

        static TestRequest success(const QVariantMap &map = QVariantMap())
        {
            return TestRequest(Sailfish::Crypto::Result::Succeeded, Sailfish::Crypto::Result::NoError, map);
        }

        static TestRequest fail(Sailfish::Crypto::Result::ErrorCode err, const QVariantMap &map = QVariantMap())
        {
            return TestRequest(Sailfish::Crypto::Result::Failed, err, map);
        }

        QVariantMap customerParameters;
        int resultCode = Sailfish::Crypto::Result::Succeeded;
        int errorCode = Sailfish::Crypto::Result::NoError;
    };
    typedef QMap<QString, TestRequest> TestRequests;

    explicit CryptoTest(QObject *parent = nullptr);

    void qtest_init();
    void qtest_cleanup();

    QByteArray createRandomTestData(int size);
    QByteArray generateInitializationVector(Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                            Sailfish::Crypto::CryptoManager::BlockMode blockMode);
    QByteArray generateRsaPlaintext(Sailfish::Crypto::CryptoManager::EncryptionPadding padding, int keySize);

    bool allCharactersAreNull(const QString &s);

    // Creates Key with filter of test=true, plus the given parameters.
    Sailfish::Crypto::Key createTestKey(int keySize,
                                        Sailfish::Crypto::CryptoManager::Algorithm algorithm,
                                        Sailfish::Crypto::Key::Origin origins,
                                        Sailfish::Crypto::CryptoManager::Operations operations,
                                        Sailfish::Crypto::Key::Identifier keyIdentifier = Sailfish::Crypto::Key::Identifier());

    void addCryptoTestData(const TestPluginMap &plugins,
                           Sailfish::Crypto::Key::Origin keyOrigin,
                           Sailfish::Crypto::CryptoManager::Operations operations,
                           Sailfish::Crypto::Key::Identifier keyIdentifier = Sailfish::Crypto::Key::Identifier(),
                           const QByteArray &plaintext = QByteArray(),
                           const TestRequests &testRequests = TestRequests());

    QFile *m_devRandom;

    TestCryptoManager m_cm;
    Sailfish::Crypto::CryptoManagerPrivate &m_cmp = *(m_cm.priv());

    TestSecretManager m_sm;
    Sailfish::Secrets::SecretManagerPrivate &m_smp = *(m_sm.priv());

    struct TestCollection {
        QString name;
        QString storagePlugin;
        Sailfish::Secrets::SecretManager::UserInteractionMode userInteractionMode;
    };
    QList<TestCollection> m_populatedCollections;

    int m_requestTestCount = 0;
};

Q_DECLARE_METATYPE(Sailfish::Crypto::Result::ResultCode)
Q_DECLARE_METATYPE(Sailfish::Crypto::Result::ErrorCode)
Q_DECLARE_METATYPE(CryptoTest::AuthenticationMode)
Q_DECLARE_METATYPE(CryptoTest::PluginType)
Q_DECLARE_METATYPE(CryptoTest::TestPluginMap)
Q_DECLARE_METATYPE(CryptoTest::TestRequest)
Q_DECLARE_METATYPE(CryptoTest::TestRequests)

#endif  // SAILFISHSECRETS_CRYPTOTEST_H
