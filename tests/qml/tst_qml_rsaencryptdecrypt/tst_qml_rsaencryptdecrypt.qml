import QtQuick 2.0
import QtTest 1.1
import Sailfish.Secrets 1.0
import Sailfish.Crypto 1.0

TestCase {
    name: "QmlRsaEncryptDecryptTests"
    property string testCaseCollectionName: "TestRsaEncryptDecryptCollection"
    property string testKeyName: "TestRsaEncryptDecryptKey"

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
        testKeyName = "CreateKeyTest"

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

    function test_createKeyAndEncryptDecrypt() {
        testKeyName = "CreateKeyAndEncryptDecryptTest"

        // Generate the key
        generateStoredKeyRequest.startRequest()
        generateStoredKeyRequest.waitForFinished()
        compare(generateStoredKeyRequest.result.code, 0, "GenerateStoredKeyRequest failed:" + String(generateStoredKeyRequest.result))

        // Create plaintext data
        var str = "Plain text test data which will be encrypted and then decrypted"
        var buffer = new ArrayBuffer(str.length)
        var view   = new Uint8Array(buffer)
        for (var i = 0; i < str.length; i++) {
            view[i] = str.charCodeAt(i)
        }

        // Encrypt the data
        encryptRequest.data = buffer
        encryptRequest.startRequest()
        encryptRequest.waitForFinished()
        compare(encryptRequest.result.code, 0, "EncryptRequest failed:" + String(encryptRequest.result))
        compare(secretManager.toBase64(encryptRequest.ciphertext).length >= str.length, true, "The ciphertext MUST have a non-zero length")

        // Decrypt the data
        decryptRequest.data = encryptRequest.ciphertext
        decryptRequest.startRequest()
        decryptRequest.waitForFinished()
        compare(decryptRequest.result.code, 0, "DecryptRequest failed:" + String(decryptRequest.result))

        // using trick to work around QML QByteArray support (in Qt < 5.8)
        // note that Qt.atob(Qt.btoa(data)) isn't round trip stable in some cases (URL-encoded data), so should not be used!
        // if the data is not valid UTF-8 data, use secretManager.toBase64() first.
        compare(secretManager.stringFromBytes(decryptRequest.plaintext) == str, true,
                "The round-trip was NOT equal! " + str + " != " + secretManager.stringFromBytes(decryptRequest.plaintext))
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
            operations: CryptoManager.OperationEncrypt | CryptoManager.OperationDecrypt
            name: testKeyName
            collectionName: testCaseCollectionName
            storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        }
        keyPairGenerationParameters: cryptoManager.constructRsaKeygenParams()
    }

    EncryptRequest {
        id: encryptRequest
        manager: cryptoManager
        cryptoPluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        key {
            algorithm: CryptoManager.AlgorithmRsa
            name: testKeyName
            collectionName: testCaseCollectionName
            storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        }
        padding: CryptoManager.EncryptionPaddingRsaPkcs1
        blockMode: CryptoManager.BlockModeUnknown
    }

    DecryptRequest {
        id: decryptRequest
        manager: cryptoManager
        cryptoPluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        key {
            algorithm: CryptoManager.AlgorithmRsa
            name: testKeyName
            collectionName: testCaseCollectionName
            storagePluginName: cryptoManager.defaultCryptoStoragePluginName + ".test"
        }
        padding: CryptoManager.EncryptionPaddingRsaPkcs1
        blockMode: CryptoManager.BlockModeUnknown
    }
}
