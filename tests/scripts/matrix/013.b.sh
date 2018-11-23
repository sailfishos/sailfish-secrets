#!/bin/bash
# Matrix Test 13.b: Key + GSVR + CustomLock + AccessRelock + NoAccessControl + Non-Privileged-Store + Non-privileged-Access + RestartAccess
# Requires: daemon to be running in --test mode, this test should be run in a non-privileged terminal
groupname=$(id -gn)
if [ "$groupname" == "privileged" ]; then
    echo "        SKIP: Script is being run in privileged terminal!"
    exit 1
else
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
fi
echo "        PASS"
exit 0
