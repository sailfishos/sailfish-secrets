#!/bin/bash
# Matrix Test 27.c: CollectionSecret + GQR + CustomLock + KeepUnlocked + NoAccessControl + Non-Privileged-Store + Non-privileged-Access + InstantAccess
# Requires: daemon to be running in --test mode, this test should be run in a privileged terminal
groupname=$(id -gn)
if [ "$groupname" == "privileged" ]; then
    echo "        SKIP: Script is being run in privileged terminal!"
    exit 1
else
    if ! secrets-tool --test --delete-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection TestSecret ; then
       echo "         FAIL: Unable to delete collection secret!"
       exit 6
    fi
    
    if ! secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection ; then
        echo "        FAIL: Unable to delete collection!"
        exit 6
    fi
fi
echo "        PASS"
exit 0
