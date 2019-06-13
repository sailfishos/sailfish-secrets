#include <QtCore/QCoreApplication>
#include <QtCore/QVariantMap>
#include <QtCore/QString>
#include <QtCore/QObject>
#include <QtCore/QUuid>
#include <QtCore/QDataStream>
#include <QtCore/QFile>
#include <QtCore/QTextStream>

#include <QtDebug>

#include <Secrets/interactionparameters.h>
#include <Secrets/createcollectionrequest.h>
#include <Secrets/storesecretrequest.h>
#include <Secrets/storedsecretrequest.h>
#include <Secrets/result.h>

#include <Crypto/interactionparameters.h>
#include <Crypto/keyderivationparameters.h>
#include <Crypto/generatekeyrequest.h>
#include <Crypto/encryptrequest.h>
#include <Crypto/decryptrequest.h>
#include <Crypto/generateinitializationvectorrequest.h>
#include <Crypto/result.h>

#include "helper.h"

Helper::Helper(Helper::Operation op, Helper::Mode mode, QObject *parent)
    : QObject(parent)
    , m_encryptOperation(op == Encrypt)
    , m_testMode(mode == TestMode)
    , m_exitCode(0)
{
    // This is the identifier of the license code we will store as a secret.
    // It specifies that the secret is called "LicenseCode" and is
    // stored in a collection (wallet) called "sailfishcryptoexample".
    // The secret will be stored in the default encrypted storage plugin.
    m_licenseCodeIdent = Sailfish::Secrets::Secret::Identifier(
            QStringLiteral("LicenseCode"),
            QStringLiteral("sailfishcryptoexample"),
            Sailfish::Secrets::SecretManager::DefaultEncryptedStoragePluginName
                + (m_testMode ? QStringLiteral(".test") : QString()));
}

Helper::~Helper()
{
}

int Helper::exitCode() const
{
    return m_exitCode;
}

void Helper::getLicenseCode()
{
    // attempt to retrieve this application's license code.
    Sailfish::Secrets::StoredSecretRequest fetchCode;
    fetchCode.setManager(&m_secretManager);
    fetchCode.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    fetchCode.setIdentifier(m_licenseCodeIdent);
    fetchCode.startRequest();
    fetchCode.waitForFinished();

    if (fetchCode.result().code() == Sailfish::Secrets::Result::Succeeded) {
        // we were able to retrieve our license code from the secrets storage.
        // use that to create a symmetric key which we will encrypt/decrypt data with.
        createKey(fetchCode.secret().data());
    } else if (fetchCode.result().errorCode() == Sailfish::Secrets::Result::InvalidCollectionError
            || fetchCode.result().errorCode() == Sailfish::Secrets::Result::InvalidSecretError
            || fetchCode.result().errorCode() == Sailfish::Secrets::Result::InvalidSecretIdentifierError) {
        // this is the first run of the application, and we have not yet
        // stored our license code to the secrets storage.
        storeLicenseCode(QUuid::createUuid().toString().toUtf8());
    } else {
        qWarning() << "Failed to retrieve license code!";
        qWarning() << "Error:" << fetchCode.result().errorCode()
                               << fetchCode.result().errorMessage();
        m_exitCode = 1;
        emit finished();
        return;
    }
}

void Helper::storeLicenseCode(const QByteArray &licenseCode)
{
    // create a secret which we will store to the secrets storage.
    Sailfish::Secrets::Secret secret(m_licenseCodeIdent);
    secret.setData(licenseCode);

    // create a collection (wallet) to store our application's secrets in.
    // it will be protected by the device lock, and only this application
    // will be allowed to access it.
    Sailfish::Secrets::CreateCollectionRequest createCollection;
    createCollection.setManager(&m_secretManager);
    createCollection.setCollectionLockType(Sailfish::Secrets::CreateCollectionRequest::DeviceLock);
    createCollection.setDeviceLockUnlockSemantic(Sailfish::Secrets::SecretManager::DeviceLockKeepUnlocked);
    createCollection.setAccessControlMode(Sailfish::Secrets::SecretManager::OwnerOnlyMode);
    createCollection.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    createCollection.setCollectionName(m_licenseCodeIdent.collectionName());
    createCollection.setStoragePluginName(m_licenseCodeIdent.storagePluginName());
    createCollection.setEncryptionPluginName(m_licenseCodeIdent.storagePluginName());
    createCollection.startRequest();
    createCollection.waitForFinished();

    if (createCollection.result().code() != Sailfish::Secrets::Result::Succeeded) {
        qWarning() << "Failed to create collection in which to store the license code!";
        qWarning() << "Error:" << createCollection.result().errorCode()
                               << createCollection.result().errorMessage();
        m_exitCode = 1;
        emit finished();
        return;
    }

    // store the given license code to secrets storage
    Sailfish::Secrets::StoreSecretRequest storeCode;
    storeCode.setManager(&m_secretManager);
    storeCode.setSecretStorageType(Sailfish::Secrets::StoreSecretRequest::CollectionSecret);
    storeCode.setUserInteractionMode(Sailfish::Secrets::SecretManager::SystemInteraction);
    storeCode.setSecret(secret);
    storeCode.startRequest();
    storeCode.waitForFinished();

    if (storeCode.result().code() != Sailfish::Secrets::Result::Succeeded) {
        qWarning() << "Failed to store the license code!";
        qWarning() << "Error:" << storeCode.result().errorCode()
                               << storeCode.result().errorMessage();
        m_exitCode = 1;
        emit finished();
        return;
    }

    // we were able to store our license code to the secrets storage.
    // use the license code to create a symmetric key which we will encrypt/decrypt data with.
    createKey(licenseCode);
}

void Helper::createKey(const QByteArray &licenseCode)
{
    // Define the key metadata via a template.
    Sailfish::Crypto::Key keyTemplate;
    keyTemplate.setOrigin(Sailfish::Crypto::Key::OriginDevice);
    keyTemplate.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    keyTemplate.setOperations(Sailfish::Crypto::CryptoManager::OperationEncrypt | Sailfish::Crypto::CryptoManager::OperationDecrypt);

    // We will derive the key from the license code using PBKDF2.
    // Use a static salt to ensure we can generate an identical key in future runs.
    Sailfish::Crypto::KeyDerivationParameters kdfParams;
    kdfParams.setKeyDerivationFunction(Sailfish::Crypto::CryptoManager::KdfPkcs5Pbkdf2);
    kdfParams.setKeyDerivationMac(Sailfish::Crypto::CryptoManager::MacHmac);
    kdfParams.setKeyDerivationDigestFunction(Sailfish::Crypto::CryptoManager::DigestSha512);
    kdfParams.setIterations(16384);
    kdfParams.setOutputKeySize(256);
    kdfParams.setSalt(QByteArray("org.sailfishos.cryptoexample"));
    kdfParams.setInputData(licenseCode);

    // Applications will probably want to use a stored key (i.e. managed by secrets daemon)
    // to avoid leaking key data into client processes.  However, in this example,
    // we use GenerateKeyRequest() instead of GenerateStoredKeyRequest() purely for
    // the sake of showing how it can be done (e.g. if the client needs to be able
    // to transmit the key data to another party via socket, etc).
    Sailfish::Crypto::GenerateKeyRequest generateKey;
    generateKey.setManager(&m_cryptoManager);
    generateKey.setKeyTemplate(keyTemplate);
    generateKey.setKeyDerivationParameters(kdfParams);
    generateKey.setCryptoPluginName(m_licenseCodeIdent.storagePluginName());
    generateKey.startRequest();
    generateKey.waitForFinished();
    if (generateKey.result().code() != Sailfish::Crypto::Result::Succeeded) {
        qWarning() << "Failed to generate symmetric key!";
        qWarning() << "Error:" << generateKey.result().errorCode()
                               << generateKey.result().errorMessage();
        m_exitCode = 1;
        emit finished();
        return;
    }

    // Use the generated key to encrypt or decrypt the data.
    Sailfish::Crypto::Key key = generateKey.generatedKey();
    if (m_encryptOperation) {
        encryptData(key);
    } else {
        decryptData(key);
    }
}

void Helper::encryptData(const Sailfish::Crypto::Key &key)
{
    // read the data to encrypt from the specified file.
    QFile file(QStringLiteral("./plaintext.dat"));
    if (!file.open(QFile::ReadOnly)) {
        qWarning() << "Failed to open plaintext.dat file for reading!";
        m_exitCode = 1;
        emit finished();
        return;
    }

    const QByteArray data = file.readAll();

    if (data.isEmpty()) {
        qWarning() << "Unable to read data from file!";
        m_exitCode = 1;
        emit finished();
        return;
    }

    // generate an initialization vector use during encryption.
    Sailfish::Crypto::GenerateInitializationVectorRequest initVector;
    initVector.setManager(&m_cryptoManager);
    initVector.setAlgorithm(Sailfish::Crypto::CryptoManager::AlgorithmAes);
    initVector.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
    initVector.setCryptoPluginName(m_licenseCodeIdent.storagePluginName());
    initVector.setKeySize(256); // for AES the IV size is 16 bytes, independent of key size.
    initVector.startRequest();
    initVector.waitForFinished();

    if (initVector.result().code() != Sailfish::Crypto::Result::Succeeded) {
        qWarning() << "Failed to generate initialization vector!";
        qWarning() << "Error:" << initVector.result().errorCode()
                               << initVector.result().errorMessage();
        m_exitCode = 1;
        emit finished();
        return;
    }

    // encrypt it with our generated key.
    Sailfish::Crypto::EncryptRequest encrypt;
    encrypt.setManager(&m_cryptoManager);
    encrypt.setData(data);
    encrypt.setInitializationVector(initVector.generatedInitializationVector());
    encrypt.setKey(key);
    encrypt.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
    encrypt.setPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    encrypt.setCryptoPluginName(m_licenseCodeIdent.storagePluginName());
    encrypt.startRequest();
    encrypt.waitForFinished();

    if (encrypt.result().code() != Sailfish::Crypto::Result::Succeeded) {
        qWarning() << "Failed to encrypt the data!";
        qWarning() << "Error:" << encrypt.result().errorCode()
                               << encrypt.result().errorMessage();
        m_exitCode = 1;
        emit finished();
        return;
    }

    QFile encryptedFile(QStringLiteral("./ciphertext.dat"));
    encryptedFile.open(QIODevice::WriteOnly);
    encryptedFile.write(QByteArray("IV:") + encrypt.initializationVector().toBase64() + QByteArray("\n"));
    int handled = 0;
    const QByteArray ciphertext = encrypt.ciphertext();
    while (handled < ciphertext.size()) {
        const QByteArray chunk = ciphertext.mid(handled, 32);
        const QByteArray encoded = chunk.toBase64() + QByteArray("\n");
        encryptedFile.write(encoded);
        handled += 32;
    }

    m_exitCode = 0;
    emit finished();
}

void Helper::decryptData(const Sailfish::Crypto::Key &key)
{
    // read the data to decrypt from the specified file.
    QFile file(QStringLiteral("./ciphertext.dat"));
    if (!file.open(QFile::ReadOnly)) {
        qWarning() << "Failed to open ciphertext.dat file for reading!";
        m_exitCode = 1;
        emit finished();
        return;
    }

    const QByteArray encodedData = file.readAll();

    if (encodedData.isEmpty()) {
        qWarning() << "Unable to read data from file!";
        m_exitCode = 1;
        emit finished();
        return;
    }

    const QList<QByteArray> chunks = encodedData.split('\n');
    if (chunks.size() < 2 || !chunks.first().startsWith("IV:")) {
        qWarning() << "Encrypted data file has unknown format!";
        m_exitCode = 1;
        emit finished();
        return;
    }

    const QByteArray iv = QByteArray::fromBase64(chunks.first().mid(3, -1));
    QByteArray decryptData;
    for (int i = 1; i < chunks.size(); ++i) {
        decryptData.append(QByteArray::fromBase64(chunks.at(i)));
    }

    Sailfish::Crypto::DecryptRequest decrypt;
    decrypt.setManager(&m_cryptoManager);
    decrypt.setData(decryptData);
    decrypt.setInitializationVector(iv);
    decrypt.setKey(key);
    decrypt.setPadding(Sailfish::Crypto::CryptoManager::EncryptionPaddingNone);
    decrypt.setBlockMode(Sailfish::Crypto::CryptoManager::BlockModeCbc);
    decrypt.setCryptoPluginName(m_licenseCodeIdent.storagePluginName());
    decrypt.startRequest();
    decrypt.waitForFinished();

    if (decrypt.result().code() != Sailfish::Crypto::Result::Succeeded) {
        qWarning() << "Failed to decrypt the data!";
        qWarning() << "Error:" << decrypt.result().errorCode()
                               << decrypt.result().errorMessage();
        m_exitCode = 1;
        emit finished();
        return;
    }

    QFile decryptedFile(QStringLiteral("./plaintext.dat"));
    decryptedFile.open(QIODevice::WriteOnly);
    decryptedFile.write(decrypt.plaintext());

    m_exitCode = 0;
    emit finished();
}

// -------------------------------------------

Q_DECL_EXPORT int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    const QStringList args = app.arguments();
    if (args.size() > 2) {
        qWarning() << "Usage: cryptoexample [--test]\n";
        qWarning() << "If the optional --test argument is provided, the daemon must be started in --test mode.";
        qWarning() << "It will encrypt plaintext.dat from the current working directory";
        qWarning() << "or it will decrypt ciphertext.dat from the current working directory";
        return 0;
    }

    bool isTest = args.size() == 2 && args[1] == QStringLiteral("--test");
    bool decrypt = QFile::exists(QStringLiteral("./ciphertext.dat"));
    bool encrypt = QFile::exists(QStringLiteral("./plaintext.dat"));
    if (!decrypt && !encrypt) {
        qWarning() << "No plaintext.dat and no ciphertext.dat exists - aborting";
        return 1;
    }

    Helper helper(decrypt ? Helper::Decrypt : Helper::Encrypt,
                  isTest ? Helper::TestMode : Helper::NormalMode);
    QObject::connect(&helper, &Helper::finished,
                     &app, &QCoreApplication::quit);
    QMetaObject::invokeMethod(&helper, "getLicenseCode", Qt::QueuedConnection);
    app.exec();
    return helper.exitCode();
}
