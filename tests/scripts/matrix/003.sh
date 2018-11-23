#!/bin/bash
# Matrix Test 3: Key + GSVR + CustomLock + KeepUnlocked + NoAccessControl + Non-privileged-Store + Non-privileged-Access + ImmediateAccess
# Requires: daemon to be running in --test mode, this test should be run in non-privileged terminal
groupname=$(id -gn)
if [ "$groupname" == "privileged" ]; then
    echo "        SKIP: Script is being run in privileged terminal!"
    exit 1
else
    if ! secrets-tool --test --create-collection --keep-unlocked org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection ; then
        echo "        FAIL: Unable to create collection!"
        exit 2
    fi
    if ! secrets-tool --test --generate-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection MyRsaKey RSA 2048 ; then
        echo "        FAIL: Unable to generate stored key!"
        exit 3
    fi
    mkdir -p /tmp/sailfish-secrets/matrix/
    echo "This is a text document containing some plain text data which I would like signed or encrypted." > /tmp/sailfish-secrets/matrix/document.txt
    if ! secrets-tool --test --sign org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection MyRsaKey SHA256 /tmp/sailfish-secrets/matrix/document.txt > /tmp/sailfish-secrets/matrix/document.txt.sig ; then
        echo "        FAIL: Unable to sign document!"
        exit 4
    fi
    if ! secrets-tool --test --verify org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection MyRsaKey SHA256 /tmp/sailfish-secrets/matrix/document.txt /tmp/sailfish-secrets/matrix/document.txt.sig ; then
        echo "        FAIL: Unable to verify document!"
        exit 5
    fi
    rm /tmp/sailfish-secrets/matrix/document.txt
    rm /tmp/sailfish-secrets/matrix/document.txt.sig
    if ! secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection ; then
        echo "        FAIL: Unable to delete collection!"
        exit 6
    fi
fi
echo "        PASS"
exit 0
