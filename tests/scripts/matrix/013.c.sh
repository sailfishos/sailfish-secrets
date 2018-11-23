#!/bin/bash
# Matrix Test 13.c: Key + GSVR + CustomLock + AccessRelock + NoAccessControl + Non-Privileged-Store + Non-privileged-Access + RestartAccess
# Requires: daemon to be running in --test mode, this test should be run in a privileged terminal
groupname=$(id -gn)
if [ "$groupname" == "privileged" ]; then
    echo "        SKIP: Script is being run in privileged terminal!"
    exit 1
else
    rm /tmp/sailfish-secrets/matrix/document.txt
    rm /tmp/sailfish-secrets/matrix/document.txt.sig
    if ! secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test TestCollection ; then
        echo "        FAIL: Unable to delete collection!"
        exit 6
    fi
fi
echo "        PASS"
exit 0
