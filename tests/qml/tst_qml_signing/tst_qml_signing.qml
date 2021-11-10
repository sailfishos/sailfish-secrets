import QtQuick 2.0
import QtTest 1.1
import Sailfish.Secrets 1.0
import Sailfish.Crypto 1.0

TestCase {
    name: "QmlSigningTests"
    property string testCaseCollectionName: "TestSignCollection"
    property string testKeyName: "MyAwesomeTestKey"

    function initTestCase() {
        // Query collection names
        collectionNamesRequest.startRequest()
        collectionNamesRequest.waitForFinished()
        compare(collectionNamesRequest.result.code, 0, "CollectionNamesRequest failed")

        // Check if our collection exists
        var names = collectionNamesRequest.collectionNames
        var i = names.indexOf(testCaseCollectionName)

        if (i >= 0) {
            // Delete collection
            deleteCollectionRequest.startRequest()
            deleteCollectionRequest.waitForFinished()
            compare(collectionNamesRequest.result.code, 0, "DeleteCollectionRequest failed")

            // Query collection names
            collectionNamesRequest.startRequest()
            collectionNamesRequest.waitForFinished()
            compare(collectionNamesRequest.result.code, 0, "CollectionNamesRequest failed")

            // Check if our collection exists
            names = collectionNamesRequest.collectionNames
            i = names.indexOf(testCaseCollectionName)
        }

        compare(i, -1, "Collection names MUST NOT contain the desired collection")

        // Create collection
        createCollectionRequest.startRequest()
        createCollectionRequest.waitForFinished()
        compare(collectionNamesRequest.result.code, 0, "CreateCollectionRequest failed")

        // Query collection names
        collectionNamesRequest.startRequest()
        collectionNamesRequest.waitForFinished()
        console.log(collectionNamesRequest.result)
        compare(collectionNamesRequest.result.code, 0, "CollectionNamesRequest failed")

        // Assert that our collection exists now
        names = collectionNamesRequest.collectionNames
        console.log(names)
        i = names.indexOf(testCaseCollectionName)
        compare(i >= 0, true, "Collection names MUST contain the desired collection")
    }

    function cleanupTestCase() {
        deleteCollectionRequest.startRequest()
        deleteCollectionRequest.waitForFinished()
    }

    function test_createKey() {
        testKeyName = "KeyCreationTest"

        // Generate the key
        generateStoredKeyRequest.startRequest()
        generateStoredKeyRequest.waitForFinished()
        compare(generateStoredKeyRequest.result.code, 0, "GenerateStoredKeyRequest failed:" + String(generateStoredKeyRequest.result))

        // Query available keys
        storedKeyIdentifiersRequest.startRequest()
        storedKeyIdentifiersRequest.waitForFinished()
        compare(storedKeyIdentifiersRequest.result.code, 0, "StoredKeyIdentifiersRequest failed")

        // Assert that the key is present
        var keyids = storedKeyIdentifiersRequest.identifiers
        var matchingKeyIds = keyids.filter(function(id) { return id.name === testKeyName })
        compare(matchingKeyIds.length, 1, "The newly generated key must be present in the result from the StoredKeyIdentifiersRequest exactly once")
    }

    function test_createKeyAndSign() {
        testKeyName = "KeyCreationAndSigningTest"

        // Generate the key
        generateStoredKeyRequest.startRequest()
        generateStoredKeyRequest.waitForFinished()
        compare(generateStoredKeyRequest.result.code, 0, "GenerateStoredKeyRequest failed:" + String(generateStoredKeyRequest.result))

        // Create data that will be signed
        var str = "Hello world! Good morning Captain, are we awesome yet?"
        var buffer = new ArrayBuffer(str.length)
        var view   = new Uint8Array(buffer)
        for (var i = 0; i < str.length; i++) {
            view[i] = str.charCodeAt(i)
        }

        // Sign the data
        signRequest.data = buffer
        signRequest.startRequest()
        signRequest.waitForFinished()
        compare(signRequest.result.code, 0, "SignRequest failed:" + String(signRequest.result))
        compare(signRequest.signatureLength > 0, true, "The signature MUST have a non-zero length")

        // NOTE: signRequest.signature is a QByteArray, which is only accessible from QML as of Qt 5.8 (so not on Sailfish 2.1.x)

        // Verify signature
        verifyRequest.data = buffer
        verifyRequest.signature = signRequest.signature
        verifyRequest.startRequest()
        verifyRequest.waitForFinished()
        compare(verifyRequest.result.code, 0, "VerifyRequest failed:" + String(verifyRequest.result))

        compare(verifyRequest.verified, CryptoManager.VerificationSuccess, "The signature MUST be verified successfully")
    }

    SecretManager {
        id: secretManager
    }

    CollectionNamesRequest {
        id: collectionNamesRequest
        manager: secretManager
        storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
    }

    CreateCollectionRequest {
        id: createCollectionRequest
        manager: secretManager
        encryptionPluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        accessControlMode: SecretManager.NoAccessControlMode
        collectionName: testCaseCollectionName
    }

    DeleteCollectionRequest {
        id: deleteCollectionRequest
        manager: secretManager
        storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        userInteractionMode: SecretManager.PreventInteraction
        collectionName: testCaseCollectionName
    }

    CryptoManager {
        id: cryptoManager
    }

    StoredKeyIdentifiersRequest {
        id: storedKeyIdentifiersRequest
        manager: cryptoManager
        storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
    }

    GenerateStoredKeyRequest {
        id: generateStoredKeyRequest
        manager: cryptoManager
        cryptoPluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        keyTemplate {
            size: 4096
            origin: Key.OriginDevice
            algorithm: CryptoManager.AlgorithmRsa
            name: testKeyName
            collectionName: testCaseCollectionName
            storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        }
        keyPairGenerationParameters: cryptoManager.constructRsaKeygenParams()
    }

    SignRequest {
        id: signRequest
        manager: cryptoManager
        cryptoPluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        key {
            algorithm: CryptoManager.AlgorithmRsa
            name: testKeyName
            collectionName: testCaseCollectionName
            storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        }
        digestFunction: CryptoManager.DigestSha512
        padding: CryptoManager.SignaturePaddingNone
    }

    VerifyRequest {
        id: verifyRequest
        manager: cryptoManager
        cryptoPluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        key {
            algorithm: CryptoManager.AlgorithmRsa
            name: testKeyName
            collectionName: testCaseCollectionName
            storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        }
        digestFunction: CryptoManager.DigestSha512
        padding: CryptoManager.SignaturePaddingNone
    }
}
