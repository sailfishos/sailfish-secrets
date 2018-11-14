/*
 * Copyright (C) 2018 Damien Caliste.
 * Contact: Damien Caliste <dcaliste@free.fr>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include <QtTest>
#include <QSignalSpy>

#include "Crypto/cryptomanager.h"
#include "Crypto/storedkeyidentifiersrequest.h"
#include "Crypto/keypairgenerationparameters.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/deletestoredkeyrequest.h"
#include "Crypto/signrequest.h"
#include "Crypto/verifyrequest.h"
#include "Crypto/encryptrequest.h"
#include "Crypto/decryptrequest.h"
#include "Crypto/key.h"
#include "Crypto/result.h"

using namespace Sailfish::Crypto;

#define OPENPGP_PLUGIN QStringLiteral("org.sailfishos.crypto.plugin.gnupg.openpgp")

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                         \
    do {                                                                    \
        int maxWait = 1000000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(100);                                              \
            maxWait -= 100;                                                 \
        }                                                                   \
    } while (0)
#define SHORT_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                   \
    do {                                                                    \
        int maxWait = 1000000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(1);                                                \
            maxWait -= 1;                                                   \
        }                                                                   \
    } while (0)
#define LONG_WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                    \
    do {                                                                    \
        int maxWait = 3000000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(100);                                              \
            maxWait -= 100;                                                 \
        }                                                                   \
    } while (0)

class TmpKey : public Key
{
    Q_GADGET

public:
    TmpKey(): Key() {};
    TmpKey(const Key &key): Key(key) {};
    ~TmpKey()
    {
        const QString &home(filterData("Ephemeral-Home"));
        if (home.isEmpty())
            return;

        QDir d(home);
        d.removeRecursively();
    };
};

class tst_gnupgplugin : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void addSubKey();
    void encryptDecrypt();
    void encryptDecrypt_data();
    void signVerify();
    void signVerify_data();
    void storedKeyIdentifiers();

private:
    Key  addKey(CryptoManager::Algorithm algorithm,
                CryptoManager::Operation operations);
    CryptoManager cm;
};

void tst_gnupgplugin::init()
{
}

void tst_gnupgplugin::cleanup()
{
}

Key tst_gnupgplugin::addKey(CryptoManager::Algorithm algorithm,
                            CryptoManager::Operation operations)
{
    KeyPairGenerationParameters keyPairGenParams;
    if (algorithm == CryptoManager::AlgorithmDsa)
        keyPairGenParams = DsaKeyPairGenerationParameters();
    else if (algorithm == CryptoManager::AlgorithmRsa)
        keyPairGenParams = RsaKeyPairGenerationParameters();
    QVariantMap customs;
    customs.insert("name", "John Doe");
    customs.insert("email", "john.doe@example.com");
    customs.insert("emptyPassphrase", true);
    //customs.insert("passphrase", "abc");
    keyPairGenParams.setCustomParameters(customs);

    // Generate key for signing
    // ----------------------------

    // Create key template
    Key keyTemplate;
    keyTemplate.setAlgorithm(algorithm);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(operations);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // Create generate key request, execute, make sure it's okay
    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    gkr.setKeyPairGenerationParameters(keyPairGenParams);
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(OPENPGP_PLUGIN);
    gkr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gkr);
    if (gkr.status() != Request::Finished ||
        gkr.result().code() != Result::Succeeded) {
        return Key();
    }

    return gkr.generatedKey();
}

void tst_gnupgplugin::addSubKey()
{
    TmpKey fullKey(addKey(CryptoManager::AlgorithmDsa, CryptoManager::OperationSign));
    QVERIFY(fullKey.identifier().isValid());

    // Create key template
    Key keyTemplate;
    keyTemplate.setAlgorithm(CryptoManager::AlgorithmDsa);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setOperations(CryptoManager::OperationSign);
    keyTemplate.setCollectionName(fullKey.collectionName());
    keyTemplate.setFilterData(QStringLiteral("Ephemeral-Home"),
                              fullKey.filterData("Ephemeral-Home"));
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    // Create generate key request, execute, make sure it's okay
    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    gkr.setKeyPairGenerationParameters(DsaKeyPairGenerationParameters());
    gkr.setKeyTemplate(keyTemplate);
    gkr.setCryptoPluginName(OPENPGP_PLUGIN);
    gkr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gkr);
    QCOMPARE(gkr.status(), Request::Finished);
    QCOMPARE(gkr.result().code(), Result::Succeeded);
    Key gk = gkr.generatedKey();
    QVariantMap customs;
    customs.insert("Ephemeral-Home", gk.filterData("Ephemeral-Home"));

    // Verify that the newly created key exists.
    StoredKeyRequest skr;
    skr.setManager(&cm);
    skr.setCustomParameters(customs);
    skr.setIdentifier(Key::Identifier(gk.name(), gk.collectionName(), OPENPGP_PLUGIN));
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.status(), Request::Finished);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().name(), gk.name());
    QCOMPARE(skr.storedKey().collectionName(), gk.collectionName());

    // Delete subkey.
    DeleteStoredKeyRequest dskr;
    dskr.setManager(&cm);
    dskr.setCustomParameters(customs);
    dskr.setIdentifier(Key::Identifier(gk.name(), gk.collectionName(), OPENPGP_PLUGIN));
    dskr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dskr);
    QCOMPARE(dskr.status(), Request::Finished);
    // Currently disabled since the DeleteStoredKeyRequest is not
    // passing the custom parameters where the ephemeral home is defined.
    // QCOMPARE(dskr.result().code(), Result::Succeeded);
}

void tst_gnupgplugin::storedKeyIdentifiers()
{
    StoredKeyIdentifiersRequest req;

    req.setManager(&cm);
    QSignalSpy reqstat(&req, &StoredKeyIdentifiersRequest::statusChanged);
    QSignalSpy reqiden(&req, &StoredKeyIdentifiersRequest::identifiersChanged);

    req.setStoragePluginName(OPENPGP_PLUGIN);
    QCOMPARE(req.storagePluginName(), OPENPGP_PLUGIN);
    QCOMPARE(req.status(), Request::Inactive);

    req.startRequest();
    QCOMPARE(reqstat.count(), 1);
    QCOMPARE(req.status(), Request::Active);
    QCOMPARE(req.result().code(), Result::Pending);
    QCOMPARE(reqiden.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(req);
    QCOMPARE(reqstat.count(), 2);
    QCOMPARE(req.status(), Request::Finished);

    QCOMPARE(req.result().code(), Result::Succeeded);
    QCOMPARE(reqiden.count(), 1);
}

void tst_gnupgplugin::signVerify_data()
{
    QTest::addColumn<CryptoManager::Algorithm>("algorithm");

    QTest::newRow("DSA") << CryptoManager::AlgorithmDsa;
    QTest::newRow("RSA") << CryptoManager::AlgorithmRsa;
}

void tst_gnupgplugin::signVerify()
{
    QFETCH(CryptoManager::Algorithm, algorithm);

    TmpKey fullKey(addKey(algorithm, CryptoManager::OperationSign));
    QVERIFY(fullKey.identifier().isValid());

    // Sign a test plaintext
    // ----------------------------

    QByteArray plaintext = "Test plaintext data";

    SignRequest sr;
    sr.setManager(&cm);
    QSignalSpy srss(&sr, &Request::statusChanged);
    QSignalSpy srvs(&sr, &SignRequest::signatureChanged);

    sr.setKey(fullKey);
    QCOMPARE(sr.key(), *static_cast<Key*>(&fullKey));
    sr.setData(plaintext);
    QCOMPARE(sr.data(), plaintext);
    sr.setCryptoPluginName(OPENPGP_PLUGIN);
    QCOMPARE(sr.cryptoPluginName(), OPENPGP_PLUGIN);
    QCOMPARE(sr.status(), Request::Inactive);

    sr.startRequest();
    QCOMPARE(srss.count(), 1);
    QCOMPARE(sr.status(), Request::Active);
    QCOMPARE(sr.result().code(), Result::Pending);
    QCOMPARE(srvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(sr);
    QCOMPARE(srss.count(), 2);
    QCOMPARE(sr.status(), Request::Finished);

    QCOMPARE(sr.result().code(), Result::Succeeded);
    QCOMPARE(srvs.count(), 1);
    QByteArray signature = sr.signature();

    // Verify the test signature
    // ----------------------------

    VerifyRequest vr;
    vr.setManager(&cm);
    QSignalSpy vrss(&vr, &VerifyRequest::statusChanged);
    QSignalSpy vrvs(&vr, &VerifyRequest::verificationStatusChanged);
    QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationStatusUnknown);
    QCOMPARE(vr.status(), Request::Inactive);
    vr.setKey(fullKey);
    QCOMPARE(vr.key(), *static_cast<Key*>(&fullKey));
    vr.setData(plaintext);
    QCOMPARE(vr.data(), plaintext);
    vr.setSignature(signature);
    QCOMPARE(vr.signature(), signature);
    vr.setCryptoPluginName(OPENPGP_PLUGIN);
    QCOMPARE(vr.cryptoPluginName(), OPENPGP_PLUGIN);

    vr.startRequest();
    QCOMPARE(vrss.count(), 1);
    QCOMPARE(vr.status(), Request::Active);
    QCOMPARE(vr.result().code(), Result::Pending);
    QCOMPARE(vrvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(vr);
    QCOMPARE(vrss.count(), 2);
    QCOMPARE(vr.status(), Request::Finished);

    QCOMPARE(vr.result().code(), Result::Succeeded);
    QCOMPARE(vrvs.count(), 1);
    QCOMPARE(vr.verificationStatus(), CryptoManager::VerificationSucceeded);
}

void tst_gnupgplugin::encryptDecrypt_data()
{
    QTest::addColumn<CryptoManager::Algorithm>("algorithm");

    QTest::newRow("RSA") << CryptoManager::AlgorithmRsa;
}

void tst_gnupgplugin::encryptDecrypt()
{
    QFETCH(CryptoManager::Algorithm, algorithm);

    TmpKey fullKey(addKey(algorithm, CryptoManager::OperationEncrypt));
    QVERIFY(fullKey.identifier().isValid());

    // Encrypt a test plaintext
    // ----------------------------

    QByteArray plaintext = "Test plaintext data";

    EncryptRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er, &Request::statusChanged);
    QSignalSpy ervs(&er, &EncryptRequest::ciphertextChanged);

    er.setKey(fullKey);
    QCOMPARE(er.key(), *static_cast<Key*>(&fullKey));
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setCryptoPluginName(OPENPGP_PLUGIN);
    QCOMPARE(er.cryptoPluginName(), OPENPGP_PLUGIN);
    QCOMPARE(er.status(), Request::Inactive);

    er.startRequest();
    QCOMPARE(erss.count(), 1);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(ervs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);

    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ervs.count(), 1);
    QByteArray cipher = er.ciphertext();

    // Decrypt the cipher data
    // ----------------------------

    DecryptRequest dr;
    dr.setManager(&cm);
    QSignalSpy drss(&dr, &Request::statusChanged);
    QSignalSpy drvs(&dr, &DecryptRequest::verificationStatusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    QCOMPARE(dr.verificationStatus(), CryptoManager::VerificationStatusUnknown);
    QCOMPARE(dr.status(), Request::Inactive);
    QVERIFY(dr.plaintext().isEmpty());
    dr.setKey(fullKey);
    QCOMPARE(dr.key(), *static_cast<Key*>(&fullKey));
    dr.setData(cipher);
    QCOMPARE(dr.data(), cipher);
    dr.setCryptoPluginName(OPENPGP_PLUGIN);
    QCOMPARE(dr.cryptoPluginName(), OPENPGP_PLUGIN);

    dr.startRequest();
    QCOMPARE(drss.count(), 1);
    QCOMPARE(dr.status(), Request::Active);
    QCOMPARE(dr.result().code(), Result::Pending);
    QCOMPARE(drvs.count(), 0);
    QCOMPARE(drps.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), 2);
    QCOMPARE(dr.status(), Request::Finished);

    QCOMPARE(dr.result().code(), Result::Succeeded);
    QCOMPARE(drps.count(), 1);
    QCOMPARE(dr.plaintext(), plaintext);
    QCOMPARE(drvs.count(), 1);
    QCOMPARE(dr.verificationStatus(), CryptoManager::VerificationStatusUnknown);
}

#include "tst_gnupgplugin.moc"
QTEST_MAIN(tst_gnupgplugin)
