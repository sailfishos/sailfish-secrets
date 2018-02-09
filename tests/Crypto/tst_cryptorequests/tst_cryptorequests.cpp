/*
 * Copyright (C) 2018 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

// This test requires linkage to both Crypto and Secrets APIs.

#include <QtTest>
#include <QSignalSpy>
#include <QObject>

#include "Crypto/decryptrequest.h"
#include "Crypto/deletestoredkeyrequest.h"
#include "Crypto/encryptrequest.h"
#include "Crypto/generatekeyrequest.h"
#include "Crypto/generatestoredkeyrequest.h"
#include "Crypto/plugininforequest.h"
#include "Crypto/signrequest.h"
#include "Crypto/storedkeyidentifiersrequest.h"
#include "Crypto/storedkeyrequest.h"
#include "Crypto/validatecertificatechainrequest.h"
#include "Crypto/verifyrequest.h"

#include "Crypto/cryptomanager.h"
#include "Crypto/key.h"
#include "Crypto/result.h"
#include "Crypto/x509certificate.h"

#include "Secrets/result.h"
#include "Secrets/secretmanager.h"
#include "Secrets/createcollectionrequest.h"
#include "Secrets/deletecollectionrequest.h"
#include "Secrets/findsecretsrequest.h"
#include "Secrets/storedsecretrequest.h"

using namespace Sailfish::Crypto;

// Cannot use waitForFinished() for some replies, as ui flows require user interaction / event handling.
#define WAIT_FOR_FINISHED_WITHOUT_BLOCKING(request)                         \
    do {                                                                    \
        int maxWait = 10000;                                                \
        while (request.status() != (int)Request::Finished && maxWait > 0) { \
            QTest::qWait(100);                                              \
            maxWait -= 100;                                                 \
        }                                                                   \
    } while (0)

#define DEFAULT_TEST_CRYPTO_PLUGIN_NAME CryptoManager::DefaultCryptoPluginName + QLatin1String(".test")
#define DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName + QLatin1String(".test")
#define IN_APP_TEST_AUTHENTICATION_PLUGIN Sailfish::Secrets::SecretManager::InAppAuthenticationPluginName + QLatin1String(".test")

class tst_cryptorequests : public QObject
{
    Q_OBJECT

public slots:
    void init();
    void cleanup();

private slots:
    void getPluginInfo();
    void generateKeyEncryptDecrypt();
    void validateCertificateChain();
    void signVerify();
    void storedKeyRequests();

private:
    CryptoManager cm;
    Sailfish::Secrets::SecretManager sm;
};

void tst_cryptorequests::init()
{
}

void tst_cryptorequests::cleanup()
{
}

void tst_cryptorequests::getPluginInfo()
{
    PluginInfoRequest r;
    r.setManager(&cm);
    QSignalSpy ss(&r, &PluginInfoRequest::statusChanged);
    QSignalSpy cs(&r, &PluginInfoRequest::cryptoPluginsChanged);
    QCOMPARE(r.status(), Request::Inactive);
    r.startRequest();
    QCOMPARE(ss.count(), 1);
    QCOMPARE(r.status(), Request::Active);
    QCOMPARE(r.result().code(), Result::Pending);
    r.waitForFinished();
    QCOMPARE(ss.count(), 2);
    QCOMPARE(r.status(), Request::Finished);
    QCOMPARE(r.result().code(), Result::Succeeded);
    QCOMPARE(cs.count(), 1);
    QVERIFY(r.cryptoPlugins().size());
    QStringList cryptoPluginNames;
    for (auto p : r.cryptoPlugins()) {
        cryptoPluginNames.append(p.name());
    }
    QVERIFY(cryptoPluginNames.contains(DEFAULT_TEST_CRYPTO_PLUGIN_NAME));
}

void tst_cryptorequests::generateKeyEncryptDecrypt()
{
    // test generating a symmetric cipher key
    Key keyTemplate;
    keyTemplate.setAlgorithm(Key::Aes256);
    keyTemplate.setOrigin(Key::OriginDevice);
    keyTemplate.setBlockModes(Key::BlockModeCBC);
    keyTemplate.setEncryptionPaddings(Key::EncryptionPaddingNone);
    keyTemplate.setSignaturePaddings(Key::SignaturePaddingNone);
    keyTemplate.setDigests(Key::DigestSha256);
    keyTemplate.setOperations(Key::Encrypt | Key::Decrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));

    GenerateKeyRequest gkr;
    gkr.setManager(&cm);
    QSignalSpy gkrss(&gkr, &GenerateKeyRequest::statusChanged);
    QSignalSpy gkrks(&gkr, &GenerateKeyRequest::generatedKeyChanged);
    gkr.setKeyTemplate(keyTemplate);
    QCOMPARE(gkr.keyTemplate(), keyTemplate);
    gkr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(gkr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(gkr.status(), Request::Inactive);
    gkr.startRequest();
    QCOMPARE(gkrss.count(), 1);
    QCOMPARE(gkr.status(), Request::Active);
    QCOMPARE(gkr.result().code(), Result::Pending);
    QCOMPARE(gkrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gkr);
    QCOMPARE(gkrss.count(), 2);
    QCOMPARE(gkr.status(), Request::Finished);
    QCOMPARE(gkr.result().code(), Result::Succeeded);
    QCOMPARE(gkrks.count(), 1);
    Key fullKey = gkr.generatedKey();
    QVERIFY(!fullKey.secretKey().isEmpty());
    QCOMPARE(fullKey.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the generated key
    QByteArray plaintext = "Test plaintext data";
    EncryptRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setKey(fullKey);
    QCOMPARE(er.key(), fullKey);
    er.setBlockMode(Key::BlockModeCBC);
    QCOMPARE(er.blockMode(), Key::BlockModeCBC);
    er.setPadding(Key::EncryptionPaddingNone);
    QCOMPARE(er.padding(), Key::EncryptionPaddingNone);
    er.setDigest(Key::DigestSha256);
    QCOMPARE(er.digest(), Key::DigestSha256);
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.status(), Request::Inactive);
    er.startRequest();
    QCOMPARE(erss.count(), 1);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(ercs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ercs.count(), 1);
    QByteArray ciphertext = er.ciphertext();
    QVERIFY(!ciphertext.isEmpty());
    QVERIFY(ciphertext != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    dr.setManager(&cm);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setKey(fullKey);
    QCOMPARE(dr.key(), fullKey);
    dr.setBlockMode(Key::BlockModeCBC);
    QCOMPARE(dr.blockMode(), Key::BlockModeCBC);
    dr.setPadding(Key::EncryptionPaddingNone);
    QCOMPARE(dr.padding(), Key::EncryptionPaddingNone);
    dr.setDigest(Key::DigestSha256);
    QCOMPARE(dr.digest(), Key::DigestSha256);
    dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.status(), Request::Inactive);
    dr.startRequest();
    QCOMPARE(drss.count(), 1);
    QCOMPARE(dr.status(), Request::Active);
    QCOMPARE(dr.result().code(), Result::Pending);
    QCOMPARE(drps.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(dr.result().code(), Result::Succeeded);
    QCOMPARE(drps.count(), 1);
    QByteArray decrypted = dr.plaintext();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(plaintext, decrypted);
}

void tst_cryptorequests::validateCertificateChain()
{
    // TODO: do this test properly, this currently just tests datatype copy semantics
    QVector<Certificate> chain;
    X509Certificate cert;
    cert.setSignatureValue(QByteArray("testing"));
    chain << cert;

    ValidateCertificateChainRequest vcr;
    vcr.setManager(&cm);
    QSignalSpy vcrss(&vcr, &ValidateCertificateChainRequest::statusChanged);
    QSignalSpy vcrvs(&vcr, &ValidateCertificateChainRequest::validatedChanged);
    vcr.setCertificateChain(chain);
    QCOMPARE(vcr.certificateChain(), chain);
    vcr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(vcr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(vcr.status(), Request::Inactive);
    vcr.startRequest();
    QCOMPARE(vcrss.count(), 1);
    QCOMPARE(vcr.status(), Request::Active);
    QCOMPARE(vcr.result().code(), Result::Pending);
    QCOMPARE(vcrvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(vcr);
    QCOMPARE(vcrss.count(), 2);
    QCOMPARE(vcr.status(), Request::Finished);
    QSKIP("TODO - certificate validation not yet implemented!");
}

void tst_cryptorequests::signVerify()
{
    // TODO: sign/verify not yet implemented in test plugin.
    QByteArray plaintext = "Test plaintext data", signature;

    SignRequest sr;
    sr.setManager(&cm);
    QSignalSpy srss(&sr, &SignRequest::statusChanged);
    QSignalSpy srvs(&sr, &SignRequest::signatureChanged);
    sr.setData(plaintext);
    QCOMPARE(sr.data(), plaintext);
    sr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(sr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(sr.status(), Request::Inactive);
    sr.startRequest();
    QCOMPARE(srss.count(), 1);
    QCOMPARE(sr.status(), Request::Active);
    QCOMPARE(sr.result().code(), Result::Pending);
    QCOMPARE(srvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(sr);
    QCOMPARE(srss.count(), 2);
    QCOMPARE(sr.status(), Request::Finished);
    // NOT YET IMPLEMENTED!
    //QCOMPARE(sr.result().code(), Result::Succeeded);
    //QCOMPARE(srvs.count(), 1);
    //signature = sr.signature();

    VerifyRequest vr;
    vr.setManager(&cm);
    QSignalSpy vrss(&vr, &VerifyRequest::statusChanged);
    QSignalSpy vrvs(&vr, &VerifyRequest::verifiedChanged);
    QCOMPARE(vr.verified(), false);
    vr.setData(plaintext);
    QCOMPARE(vr.data(), plaintext);
    vr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(vr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(vr.status(), Request::Inactive);
    vr.startRequest();
    QCOMPARE(vrss.count(), 1);
    QCOMPARE(vr.status(), Request::Active);
    QCOMPARE(vr.result().code(), Result::Pending);
    QCOMPARE(vrvs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(vr);
    QCOMPARE(vrss.count(), 2);
    QCOMPARE(vr.status(), Request::Finished);
    // NOT YET IMPLEMENTED!
    //QCOMPARE(vr.result().code(), Result::Succeeded);
    //QCOMPARE(vrvs.count(), 1);
    //QCOMPARE(vr.verified(), true);

    QSKIP("TODO - sign/verify not yet implemented!");
}

void tst_cryptorequests::storedKeyRequests()
{
    // test generating a symmetric cipher key and storing securely in the same plugin which produces the key.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setAlgorithm(Sailfish::Crypto::Key::Aes256);
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setBlockModes(Sailfish::Crypto::Key::BlockModeCBC);
    keyTemplate.setEncryptionPaddings(Sailfish::Crypto::Key::EncryptionPaddingNone);
    keyTemplate.setSignaturePaddings(Sailfish::Crypto::Key::SignaturePaddingNone);
    keyTemplate.setDigests(Sailfish::Crypto::Key::DigestSha256);
    keyTemplate.setOperations(Sailfish::Crypto::Key::Encrypt | Sailfish::Crypto::Key::Decrypt);
    keyTemplate.setFilterData(QLatin1String("test"), QLatin1String("true"));
    keyTemplate.setCustomParameters(QVector<QByteArray>() << QByteArray("testparameter"));

    // first, create the collection via the Secrets API.
    Sailfish::Secrets::CreateCollectionRequest ccr;
    ccr.setManager(&sm);
    ccr.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    ccr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    ccr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setEncryptionPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    ccr.setAuthenticationPluginName(IN_APP_TEST_AUTHENTICATION_PLUGIN);
    ccr.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    ccr.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    ccr.setUserInteractionMode(Sailfish::Secrets::SecretManager::ApplicationInteraction);
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // request that the secret key be generated and stored into that collection.
    keyTemplate.setIdentifier(Sailfish::Crypto::Key::Identifier(QLatin1String("storedkey"), QLatin1String("tstcryptosecretsgcsked")));
    // note that the secret key data will never enter the client process address space.
    GenerateStoredKeyRequest gskr;
    gskr.setManager(&cm);
    QSignalSpy gskrss(&gskr, &GenerateStoredKeyRequest::statusChanged);
    QSignalSpy gskrks(&gskr, &GenerateStoredKeyRequest::generatedKeyReferenceChanged);
    gskr.setKeyTemplate(keyTemplate);
    QCOMPARE(gskr.keyTemplate(), keyTemplate);
    gskr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    gskr.setStoragePluginName(DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.storagePluginName(), DEFAULT_TEST_CRYPTO_STORAGE_PLUGIN_NAME);
    QCOMPARE(gskr.status(), Request::Inactive);
    gskr.startRequest();
    QCOMPARE(gskrss.count(), 1);
    QCOMPARE(gskr.status(), Request::Active);
    QCOMPARE(gskr.result().code(), Result::Pending);
    QCOMPARE(gskrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskrss.count(), 2);
    QCOMPARE(gskr.status(), Request::Finished);
    QCOMPARE(gskr.result().code(), Result::Succeeded);
    QCOMPARE(gskrks.count(), 1);
    Sailfish::Crypto::Key keyReference = gskr.generatedKeyReference();
    QVERIFY(keyReference.secretKey().isEmpty());
    QVERIFY(keyReference.privateKey().isEmpty());
    QCOMPARE(keyReference.filterData(), keyTemplate.filterData());

    // test encrypting some plaintext with the stored key.
    QByteArray plaintext = "Test plaintext data";
    EncryptRequest er;
    er.setManager(&cm);
    QSignalSpy erss(&er, &EncryptRequest::statusChanged);
    QSignalSpy ercs(&er, &EncryptRequest::ciphertextChanged);
    er.setData(plaintext);
    QCOMPARE(er.data(), plaintext);
    er.setKey(keyReference);
    QCOMPARE(er.key(), keyReference);
    er.setBlockMode(Key::BlockModeCBC);
    QCOMPARE(er.blockMode(), Key::BlockModeCBC);
    er.setPadding(Key::EncryptionPaddingNone);
    QCOMPARE(er.padding(), Key::EncryptionPaddingNone);
    er.setDigest(Key::DigestSha256);
    QCOMPARE(er.digest(), Key::DigestSha256);
    er.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(er.status(), Request::Inactive);
    er.startRequest();
    QCOMPARE(erss.count(), 1);
    QCOMPARE(er.status(), Request::Active);
    QCOMPARE(er.result().code(), Result::Pending);
    QCOMPARE(ercs.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(erss.count(), 2);
    QCOMPARE(er.status(), Request::Finished);
    QCOMPARE(er.result().code(), Result::Succeeded);
    QCOMPARE(ercs.count(), 1);
    QByteArray ciphertext = er.ciphertext();
    QVERIFY(!ciphertext.isEmpty());
    QVERIFY(ciphertext != plaintext);

    // test decrypting the ciphertext, and ensure that the roundtrip works.
    DecryptRequest dr;
    dr.setManager(&cm);
    QSignalSpy drss(&dr, &DecryptRequest::statusChanged);
    QSignalSpy drps(&dr, &DecryptRequest::plaintextChanged);
    dr.setData(ciphertext);
    QCOMPARE(dr.data(), ciphertext);
    dr.setKey(keyReference);
    QCOMPARE(dr.key(), keyReference);
    dr.setBlockMode(Key::BlockModeCBC);
    QCOMPARE(dr.blockMode(), Key::BlockModeCBC);
    dr.setPadding(Key::EncryptionPaddingNone);
    QCOMPARE(dr.padding(), Key::EncryptionPaddingNone);
    dr.setDigest(Key::DigestSha256);
    QCOMPARE(dr.digest(), Key::DigestSha256);
    dr.setCryptoPluginName(DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.cryptoPluginName(), DEFAULT_TEST_CRYPTO_PLUGIN_NAME);
    QCOMPARE(dr.status(), Request::Inactive);
    dr.startRequest();
    QCOMPARE(drss.count(), 1);
    QCOMPARE(dr.status(), Request::Active);
    QCOMPARE(dr.result().code(), Result::Pending);
    QCOMPARE(drps.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(drss.count(), 2);
    QCOMPARE(dr.status(), Request::Finished);
    QCOMPARE(dr.result().code(), Result::Succeeded);
    QCOMPARE(drps.count(), 1);
    QByteArray decrypted = dr.plaintext();
    QVERIFY(!decrypted.isEmpty());
    QCOMPARE(plaintext, decrypted);

    // ensure that we can get a reference to that Key via the Secrets API
    Sailfish::Secrets::Secret::FilterData filter;
    filter.insert(QLatin1String("test"), keyTemplate.filterData(QLatin1String("test")));
    Sailfish::Secrets::FindSecretsRequest fsr;
    fsr.setManager(&sm);
    fsr.setFilter(filter);
    fsr.setFilterOperator(Sailfish::Secrets::SecretManager::OperatorAnd);
    fsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    fsr.setCollectionName(keyTemplate.identifier().collectionName());
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 1);
    QCOMPARE(fsr.identifiers().at(0).name(), keyTemplate.identifier().name());
    QCOMPARE(fsr.identifiers().at(0).collectionName(), keyTemplate.identifier().collectionName());

    // and ensure that the filter operation doesn't return incorrect results
    filter.insert(QLatin1String("test"), QString(QLatin1String("not %1")).arg(keyTemplate.filterData(QLatin1String("test"))));
    fsr.setFilter(filter);
    fsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(fsr);
    QCOMPARE(fsr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(fsr.result().code(), Sailfish::Secrets::Result::Succeeded);
    QCOMPARE(fsr.identifiers().size(), 0);

    // ensure we can get a key reference via a stored key request
    StoredKeyRequest skr;
    skr.setManager(&cm);
    QSignalSpy skrss(&skr, &StoredKeyRequest::statusChanged);
    QSignalSpy skrks(&skr, &StoredKeyRequest::storedKeyChanged);
    skr.setIdentifier(keyReference.identifier());
    QCOMPARE(skr.identifier(), keyReference.identifier());
    skr.setKeyComponents(StoredKeyRequest::MetaData);
    QCOMPARE(skr.keyComponents(), StoredKeyRequest::MetaData);
    QCOMPARE(skr.status(), Request::Inactive);
    skr.startRequest();
    QCOMPARE(skrss.count(), 1);
    QCOMPARE(skr.status(), Request::Active);
    QCOMPARE(skr.result().code(), Result::Pending);
    QCOMPARE(skrks.count(), 0);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skrss.count(), 2);
    QCOMPARE(skr.status(), Request::Finished);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skrks.count(), 1);
    QCOMPARE(skr.storedKey().algorithm(), keyTemplate.algorithm());
    QVERIFY(skr.storedKey().customParameters().isEmpty()); // considered public key data, not fetched
    QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched

    // and that we can get the public key data + custom parameters
    skr.setKeyComponents(StoredKeyRequest::MetaData | StoredKeyRequest::PublicKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(skr.storedKey().secretKey().isEmpty()); // secret key data, not fetched

    // and that we can get the secret key data
    skr.setKeyComponents(StoredKeyRequest::MetaData | StoredKeyRequest::PublicKeyData | StoredKeyRequest::SecretKeyData);
    skr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(skr);
    QCOMPARE(skr.result().code(), Result::Succeeded);
    QCOMPARE(skr.storedKey().customParameters(), keyTemplate.customParameters());
    QVERIFY(!skr.storedKey().secretKey().isEmpty());

    // clean up by deleting the collection in which the secret is stored.
    Sailfish::Secrets::DeleteCollectionRequest dcr;
    dcr.setManager(&sm);
    dcr.setCollectionName(QLatin1String("tstcryptosecretsgcsked"));
    dcr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(dr.result().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // recreate the collection and the key, and encrypt/decrypt again, then delete via deleteStoredKey().
    ccr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(ccr);
    QCOMPARE(ccr.status(), Sailfish::Secrets::Request::Finished);
    QCOMPARE(ccr.result().code(), Sailfish::Secrets::Result::Succeeded);

    gskr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gskr);
    QCOMPARE(gskr.result().code(), Sailfish::Crypto::Result::Succeeded);
    keyReference = gskr.generatedKeyReference();

    er.setKey(keyReference);
    er.setData(plaintext);
    er.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(er);
    QCOMPARE(er.result().code(), Sailfish::Crypto::Result::Succeeded);
    ciphertext = er.ciphertext();

    dr.setKey(keyReference);
    dr.setData(ciphertext);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Succeeded);
    decrypted = dr.plaintext();
    QCOMPARE(decrypted, plaintext);

    // delete the key via deleteStoredKey, and test that the deletion worked.
    DeleteStoredKeyRequest dskr;
    dskr.setManager(&cm);
    QSignalSpy dskrss(&dskr, &DeleteStoredKeyRequest::statusChanged);
    dskr.setIdentifier(keyTemplate.identifier());
    QCOMPARE(dskr.identifier(), keyTemplate.identifier());
    QCOMPARE(dskr.status(), Request::Inactive);
    dskr.startRequest();
    QCOMPARE(dskrss.count(), 1);
    QCOMPARE(dskr.status(), Request::Active);
    QCOMPARE(dskr.result().code(), Result::Pending);
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dskr);
    QCOMPARE(dskrss.count(), 2);
    QCOMPARE(dskr.status(), Request::Finished);
    QCOMPARE(dskr.result().code(), Result::Succeeded);

    // ensure that the deletion was cascaded to the keyEntries internal database table.
    dr.setKey(keyReference);
    dr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dr);
    QCOMPARE(dr.result().code(), Sailfish::Crypto::Result::Failed);
    QCOMPARE(dr.result().errorCode(), Sailfish::Crypto::Result::InvalidKeyIdentifier);

    // ensure that the deletion was cascaded to the Secrets internal database table.
    Sailfish::Secrets::StoredSecretRequest gsr;
    gsr.setManager(&sm);
    gsr.setIdentifier(Sailfish::Secrets::Secret::Identifier(
                          keyReference.identifier().name(),
                          keyReference.identifier().collectionName()));
    gsr.setUserInteractionMode(Sailfish::Secrets::SecretManager::PreventInteraction);
    gsr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(gsr);
    QCOMPARE(gsr.result().code(), Sailfish::Secrets::Result::Failed);
    QCOMPARE(gsr.result().errorCode(), Sailfish::Secrets::Result::InvalidSecretError);

    // clean up by deleting the collection.
    dcr.startRequest();
    WAIT_FOR_FINISHED_WITHOUT_BLOCKING(dcr);
    QCOMPARE(dcr.result().code(), Sailfish::Secrets::Result::Succeeded);
}

#include "tst_cryptorequests.moc"
QTEST_MAIN(tst_cryptorequests)
