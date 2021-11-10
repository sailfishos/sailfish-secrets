import QtQuick 2.0
import Sailfish.Silica 1.0
import Sailfish.Secrets 1.0 as Secrets
import Sailfish.Crypto 1.0 as Crypto

ApplicationWindow {
    id: root

    initialPage: Page {
        id: page

        property var text: "example data which will be encrypted and then decrypted"
        property var ciphertext: er.ciphertext
        property var plaintext: dr.plaintext

        Component.onCompleted: gkr.startRequest()

        Rectangle {
            id: rect
            anchors.fill: parent
            color: "lightsteelblue"

            Column {
                width: parent.width
                Text {
                    width: rect.width
                    height: rect.height / 3
                    text: "Input:  " + page.text
                    wrapMode: Text.Wrap
                }
                Text {
                    width: rect.width
                    height: rect.height / 3
                    text: "Cipher: " + Qt.btoa(page.ciphertext)
                    wrapMode: Text.Wrap
                }
                Text {
                    width: rect.width
                    height: rect.height / 3
                    text: "Plain:  " + page.plaintext
                    wrapMode: Text.Wrap
                }
            }
        }

        Crypto.CryptoManager {
            id: crypto
        }

        Crypto.GenerateKeyRequest {
            id: gkr
            manager: crypto
            cryptoPluginName: crypto.defaultCryptoPluginName
            keyTemplate: crypto.constructKeyTemplate(Crypto.CryptoManager.AlgorithmAes,
                                                     Crypto.CryptoManager.OperationEncrypt | Crypto.CryptoManager.OperationDecrypt)
            keyDerivationParameters: crypto.constructPbkdf2Params("password", "salt")
            onResultChanged: {
                if (result.code == Crypto.Result.Failed) {
                    console.log("GKR: error: " + result.errorMessage)
                } else if (result.code == Crypto.Result.Succeeded) {
                    console.log("GKR: succeeded: now triggering encryption")
                    er.key = gkr.generatedKey
                    er.startRequest()
                }
            }
        }

        Crypto.EncryptRequest {
            id: er
            manager: crypto
            cryptoPluginName: crypto.defaultCryptoPluginName
            key: gkr.generatedKey
            blockMode: Crypto.CryptoManager.BlockModeCbc
            padding: Crypto.CryptoManager.EncryptionPaddingNone
            data: page.text
            initializationVector: "0123456789abcdef" // should generate with GenerateInitializationVectorRequest...
            onResultChanged: {
                if (result.code == Crypto.Result.Failed) {
                    console.log("ER: error: " + result.errorMessage)
                } else if (result.code == Crypto.Result.Succeeded) {
                    console.log("ER: succeeded: now triggering decryption on ciphertext: " + Qt.btoa(er.ciphertext))
                    dr.data = er.ciphertext
                    dr.startRequest()
                }
            }
        }

        Crypto.DecryptRequest {
            id: dr
            manager: crypto
            cryptoPluginName: crypto.defaultCryptoPluginName
            key: gkr.generatedKey
            blockMode: Crypto.CryptoManager.BlockModeCbc
            padding: Crypto.CryptoManager.EncryptionPaddingNone
            data: er.ciphertext
            initializationVector: er.initializationVector
            onResultChanged: {
                if (result.code == Crypto.Result.Failed) {
                    console.log("DR: error: " + result.errorMessage)
                } else if (result.code == Crypto.Result.Succeeded) {
                    console.log("DR: succeeded: have plaintext: " + dr.plaintext)
                }
            }
        }
    }
}

