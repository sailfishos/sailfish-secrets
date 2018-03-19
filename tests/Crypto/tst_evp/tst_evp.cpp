/*
 * Copyright (C) 2017 Jolla Ltd.
 * Contact: Chris Adams <chris.adams@jollamobile.com>
 * All rights reserved.
 * BSD 3-Clause License, see LICENSE.
 */

#include "tst_evp.h"
#include "evp_p.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/x509.h>

#include <cassert>

/*!
 * Before each test case, generates a new private-public key pair using
 * the OpenSSL command line. Then reads these keys into QByteArrays.
 */
void tst_evp::init()
{
    qDebug() << "creating test private key file";
    QProcess proc1;
    proc1.start("openssl",
               QStringList({"genpkey", "-algorithm", "RSA", "-out", privateKeyFileName, "-pkeyopt", "rsa_keygen_bits:2048" }),
               QIODevice::ReadWrite);
    proc1.waitForFinished(5000);

    qDebug() << "extracting test public key file";
    QProcess proc2;
    proc2.start("openssl",
               QStringList({"rsa", "-pubout", "-in", privateKeyFileName, "-out", publicKeyFileName }),
               QIODevice::ReadWrite);
    proc2.waitForFinished(5000);

    // Read private key
    QFile privateKeyFile(privateKeyFileName);
    bool isopen = privateKeyFile.open(QIODevice::ReadOnly);
    QVERIFY2(isopen, "private key file should be open");
    privateKey = privateKeyFile.readAll();
    privateKeyFile.close();

    // Read public key
    QFile publicKeyFile(publicKeyFileName);
    isopen = publicKeyFile.open(QIODevice::ReadOnly);
    QVERIFY2(isopen, "public key file should be open");
    publicKey = publicKeyFile.readAll();
    publicKeyFile.close();
}

void tst_evp::cleanup()
{
    // Clean up private key file
    QFile privateKeyFile(privateKeyFileName);
    if (privateKeyFile.exists()) {
        qDebug() << "deleting test private key file";
        privateKeyFile.remove();
    }

    // Clean up public key file
    QFile publicKeyFile(publicKeyFileName);
    if (publicKeyFile.exists()) {
        qDebug() << "deleting test public key file";
        publicKeyFile.remove();
    }
}

QByteArray tst_evp::generateTestData(size_t size) {
    QFile file("/dev/urandom");
    file.open(QIODevice::ReadOnly);
    QByteArray result = file.read(size);
    return result;
}

/*!
 * Tests a sign case.
 * Makes sure that our EVP usage is correct and generates correct output.
 */
void tst_evp::testSign()
{
    // Create some test data
    QByteArray testData = generateTestData(512);

    // Use both methods to sign it
    QByteArray s1 = signWithCommandLine(testData);
    QByteArray s2 = signWithEvp(testData);

    // Assert that both signatures are non-zero long, and they are the same
    QVERIFY(s1.length() > 0);
    QVERIFY(s2.length() > 0);
    QCOMPARE(s2, s1);
}

/*!
 * Tests a correct verify case, ie. when the correct signature is
 * used when verifying.
 * Makes sure that our EVP usage is correct and generates correct output.
 */
void tst_evp::testVerifyCorrect()
{
    // Create some test data
    QByteArray testData = generateTestData(512);

    // Use both methods to sign it
    QByteArray s1 = signWithCommandLine(testData);
    QByteArray s2 = signWithEvp(testData);

    // Assert that both signatures are non-zero long, and they are the same
    QVERIFY(s1.length() > 0);
    QVERIFY(s2.length() > 0);
    QCOMPARE(s2, s1);

    // Verify using both methods
    bool ok1 = verifyWithCommandLine(testData, s1);
    bool ok2 = verifyWithEvp(testData, s1);

    // Assert that both are successful
    QVERIFY(ok1);
    QVERIFY(ok2);
    QCOMPARE(ok2, ok1);
}

/*!
 * Tests a correct verify case, ie. when the signature is tampered with
 * before verifying. Expected not to succeed.
 * Makes sure that our EVP usage is correct and generates correct output.
 */
void tst_evp::testVerifyIncorrect()
{
    // Create some test data
    QByteArray testData = generateTestData(512);

    // Use both methods to sign it
    QByteArray s1 = signWithCommandLine(testData);
    QByteArray s2 = signWithEvp(testData);

    // Assert that both signatures are non-zero long, and they are the same
    QVERIFY(s1.length() > 0);
    QVERIFY(s2.length() > 0);
    QCOMPARE(s2, s1);

    // Tamper with the signature
    s1[4] = ~s1[4];

    // Verify using both methods
    bool ok1 = verifyWithCommandLine(testData, s1);
    bool ok2 = verifyWithEvp(testData, s1);

    // Assert that both verifications are unsuccessful
    QVERIFY(!ok1);
    QVERIFY(!ok2);
    QCOMPARE(ok2, ok1);
}

/*!
 * \brief Creates an SHA-256 signature using the OpenSSL command line.
 * \param data The data which needs to be signed.
 * \return Signature.
 */
QByteArray tst_evp::signWithCommandLine(const QByteArray &data) {
    const char *testDataFileName = "testdata.bin";
    const char *testSignatureFileName = "test-signature.sha256";

    QFile file(testDataFileName);
    file.open(QIODevice::WriteOnly);
    file.write(data);
    file.waitForBytesWritten(5000);
    file.close();

    QProcess proc;
    proc.start("openssl",
               QStringList({"dgst", "-sha256", "-sign", privateKeyFileName, "-out", testSignatureFileName, testDataFileName}),
               QIODevice::ReadWrite);
    proc.waitForFinished(5000);

    QFile signatureFile(testSignatureFileName);
    signatureFile.open(QIODevice::ReadOnly);
    QByteArray result = signatureFile.readAll();
    signatureFile.close();

    // Remove test data file and signature file
    file.remove();
    signatureFile.remove();

    return result;
}

/*!
 * \brief Verifies an SHA-256 signature using the OpenSSL command line.
 * \param data The data which was signed.
 * \param signature The signature.
 * \return true if the signature is correct, false otherwise.
 */
bool tst_evp::verifyWithCommandLine(const QByteArray &data, const QByteArray &signature)
{
    const char *testDataFileName = "testdata.bin";
    const char *testSignatureFileName = "test-signature.sha256";

    QFile file(testDataFileName);
    file.open(QIODevice::WriteOnly);
    file.write(data);
    file.waitForBytesWritten(5000);
    file.close();

    QFile signatureFile(testSignatureFileName);
    signatureFile.open(QIODevice::WriteOnly);
    signatureFile.write(signature);
    signatureFile.close();

    QProcess proc;
    proc.start("openssl",
               QStringList({"dgst", "-sha256", "-verify", publicKeyFileName, "-signature", testSignatureFileName, testDataFileName}),
               QIODevice::ReadWrite);
    proc.waitForFinished(5000);
    QString result = proc.readAll();

    // Remove test data file and signature file
    file.remove();
    signatureFile.remove();

    return result == "Verified OK\n";
}

/*!
 * \brief Creates an SHA-256 signature using the sailfish-crypto EVP code.
 * \param data The data which needs to be signed.
 * \return Signature.
 */
QByteArray tst_evp::signWithEvp(const QByteArray &data) {
    BIO *bio = BIO_new(BIO_s_mem());
    EVP_PKEY *pkey = EVP_PKEY_new();
    const EVP_MD *digestFunc = EVP_sha256();

    int r = BIO_write(bio, privateKey.data(), privateKey.length());
    assert(r == privateKey.length());
    PEM_read_bio_PrivateKey(bio, &pkey, nullptr, nullptr);

    uint8_t *signature;
    size_t signatureLength;

    r = osslevp_sign(digestFunc, pkey, data.data(), data.length(), &signature, &signatureLength);
    assert(r == 1);
    BIO_free(bio);
    EVP_PKEY_free(pkey);

    QByteArray result((const char*) signature, (int) signatureLength);
    OPENSSL_free(signature);

    return result;
}

/*!
 * \brief Verifies an SHA-256 signature using the sailfish-crypto EVP code.
 * \param data The data which was signed.
 * \param signature The signature.
 * \return true if the signature is correct, false otherwise.
 */
bool tst_evp::verifyWithEvp(const QByteArray &data, const QByteArray &signature)
{
    BIO *bio = BIO_new(BIO_s_mem());
    EVP_PKEY *pkey = EVP_PKEY_new();
    const EVP_MD *digestFunc = EVP_sha256();

    int r = BIO_write(bio, publicKey.data(), publicKey.length());
    assert(r == publicKey.length());
    PEM_read_bio_PUBKEY(bio, &pkey, nullptr, nullptr);

    r = osslevp_verify(digestFunc, pkey, data.data(), data.length(), reinterpret_cast<const uint8_t*>(signature.data()), signature.length());
    assert(r >= 0);
    BIO_free(bio);
    EVP_PKEY_free(pkey);

    return r == 1;
}

QTEST_MAIN(tst_evp)
