#!/bin/sh

# This script must be run within a devel-su -p shell
# The daemon must be running in autotest mode (with --test option)

# Create a collection and test key store/use/delete
echo "Creating customlock access-relock collection MyCollection, user passphrase required..."
secrets-tool --test --create-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection

# Create an RSA key, and test sign/verify
echo "Generating 2048-bit RSA key within MyCollection..."
secrets-tool --test --generate-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyRsaKey RSA 2048
echo "Listing keys from MyCollection to ensure key generation succeeded..."
secrets-tool --test --list-keys org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test
echo "Generating test document to sign..."
echo "This is a text document containing some plain text data which I would like signed or encrypted." > document.txt
echo "Signing test document with RSA key..."
secrets-tool --test --sign org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyRsaKey SHA256 document.txt > document.txt.sig
echo "Verifying signature with RSA key..."
secrets-tool --test --verify org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyRsaKey SHA256 document.txt document.txt.sig

# Create an AES key, and test encrypt/decrypt
echo "Generating salt data for AES key generation..."
head -c 16 /dev/urandom > salt.data
echo "Generating 256-bit AES key from passphrase..."
secrets-tool --test --derive-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyAesKey AES 256 salt.data
echo "Listing keys from MyCollection to ensure key generation succeeded..."
secrets-tool --test --list-keys org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test
echo "Encrypting test document with AES key..."
secrets-tool --test --encrypt org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyAesKey document.txt > document.txt.enc
echo "Decrypting ciphertext with AES key..."
secrets-tool --test --decrypt org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyAesKey document.txt.enc

# Import an EC key, and test encrypt/decrypt
echo "Generating a SECG curve over a 256 bit prime field..."
openssl ecparam -name secp256k1 -genkey -noout -out secp256k1-key.pem
openssl ec -in secp256k1-key.pem -pubout -out secp256k1-key.pem.public
secrets-tool --test --import-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyImportedEcKey secp256k1-key.pem
echo "Signing test document with imported EC key..."
secrets-tool --test --sign org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyImportedEcKey SHA256 document.txt > document.txt.sig2
echo "Signing test document with openssl CLI tool..."
openssl dgst -sha256 -sign secp256k1-key.pem -out document.txt.sha256 document.txt

echo "Verifying secrets-tool generated signature with imported EC key..."
secrets-tool --test --verify org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyImportedEcKey SHA256 document.txt document.txt.sig2
echo "Verifying openssl generated signature with imported EC key..."
secrets-tool --test --verify org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyImportedEcKey SHA256 document.txt document.txt.sha256
echo "Verifying openssl generated signature with openssl..."
openssl dgst -sha256 -verify secp256k1-key.pem.public -signature document.txt.sha256 document.txt
echo "Verifying secrets-tool generated signature with openssl..."
openssl dgst -sha256 -verify secp256k1-key.pem.public -signature document.txt.sig2 document.txt

# Import an RSA key, and test sign/verify
echo "Using ssh-keygen to generate RSA key to import..."
ssh-keygen -t rsa -b 2048 -N abcde -f importfile.pem
echo "Importing generated RSA key from file..."
secrets-tool --test --import-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyImportedKey importfile.pem
echo "Signing test document with imported RSA key..."
secrets-tool --test --sign org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyImportedKey SHA256 document.txt > document.txt.sig3
echo "Verifying signature with imported RSA key..."
secrets-tool --test --verify org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyImportedKey SHA256 document.txt document.txt.sig3

# Clean up by deleting the collection
echo "Cleaning up - deleting MyCollection..."
secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection
