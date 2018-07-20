#!/bin/bash
# Matrix Test 12.a: Key + GSVR + DeviceLock + KeepUnlocked + NoAccessControl + Non-privileged-Store + Privileged-Access + ImmediateAccess
# Requires: daemon to be running in --test mode, this test should be run in a non-privileged terminal
groupname=$(id -gn)
if [ "$groupname" == "privileged" ]; then
    echo "        SKIP: Script is being run in privileged terminal!"
    exit 1
else
    if ! secrets-tool --test --create-collection --devicelock --keep-unlocked org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection ; then
        echo "        FAIL: Unable to create collection!"
        exit 2
    fi
    if ! secrets-tool --test --generate-stored-key org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection MyRsaKey RSA 2048 ; then
        echo "        FAIL: Unable to generate stored key!"
        exit 3
    fi
fi
echo "        PASS"
exit 0
