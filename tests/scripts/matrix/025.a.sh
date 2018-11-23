#!/bin/bash
# Matrix Test 25.a: CollectionSecret + GQR + CustomLock + AccessRelock + NoAccessControl + Non-Privileged-Store + Non-privileged-Access + InstantAccess
# Requires: daemon to be running in --test mode, this test should be run in a privileged terminal
groupname=$(id -gn)
if [ "$groupname" == "privileged" ]; then
    echo "        SKIP: Script is being run in privileged terminal!"
    exit 1
else
    if ! secrets-tool --test --create-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection ; then
        echo "        FAIL: Unable to create collection!"
        exit 2
    fi
    if ! secrets-tool --test --store-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection TestSecret "This is secret data." ; then
        echo "        FAIL: Unable to generate stored key!"
        exit 3
    fi
fi
echo "        PASS"
exit 0
