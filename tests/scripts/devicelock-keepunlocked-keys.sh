#!/bin/sh

# The daemon must be running in autotest mode (with --test option)

# run the security UI in this console session
/usr/libexec/lipstick-security-ui &
SECURITY_UI_PID=$!

# Create a collection
echo "Creating devicelock keep-unlocked collection MyDLCollection with device lock protection"
secrets-tool --test --create-collection --devicelock --keep-unlocked org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection

# Create an RSA key, and test sign/verify
echo "Generating 2048-bit RSA key within MyDLCollection..."
secrets-tool --test --generate-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyRsaKey RSA 2048
echo "Listing keys from MyDLCollection to ensure key generation succeeded..."
secrets-tool --test --list-keys org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test
echo "Generating test document to sign..."
echo "This is a text document containing some plain text data which I would like signed or encrypted." > document.txt
echo "Signing test document with RSA key..."
secrets-tool --test --sign org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyRsaKey SHA256 document.txt > document.txt.sig
echo "Verifying signature with RSA key..."
secrets-tool --test --verify org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyRsaKey SHA256 document.txt document.txt.sig

# Create an AES key, and test encrypt/decrypt
echo "Generating salt data for AES key generation..."
head -c 16 /dev/urandom > salt.data
echo "Generating 256-bit AES key from passphrase..."
secrets-tool --test --derive-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyAesKey AES 256 salt.data
echo "Listing keys from MyDLCollection to ensure key generation succeeded..."
secrets-tool --test --list-keys org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test
echo "Encrypting test document with AES key..."
secrets-tool --test --encrypt org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyAesKey document.txt > document.txt.enc
echo "Decrypting ciphertext with AES key..."
secrets-tool --test --decrypt org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyAesKey document.txt.enc

# Import an RSA key, and test sign/verify
echo "Using ssh-keygen to generate RSA key to import..."
ssh-keygen -t rsa -b 2048 -N abcde -f importfile.pem
echo "Importing generated RSA key from file..."
secrets-tool --test --import-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyImportedKey importfile.pem
echo "Signing test document with imported RSA key..."
secrets-tool --test --sign org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyImportedKey SHA256 document.txt > document.txt.sig2
echo "Verifying signature with imported RSA key..."
secrets-tool --test --verify org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyImportedKey SHA256 document.txt document.txt.sig2

echo "Deleting collection, device lock confirmation required"
secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection

# clean up by killing the security UI
kill -9 $SECURITY_UI_PID
