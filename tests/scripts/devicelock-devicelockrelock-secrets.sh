#!/bin/sh

# The daemon must be running in autotest mode (with --test option)

# run the security UI in this console session
/usr/libexec/lipstick-security-ui &
SECURITY_UI_PID=$!

# Create a collection
echo "Creating devicelock relocked collection MyDLCollection with device lock protection"
secrets-tool --test --create-collection --devicelock org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection
echo "Storing normal secret, user input then device lock confirmation required"
secrets-tool --test --store-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyDLCollectionSecret
echo "Retrieving normal secret, device lock confirmation required"
secrets-tool --test --get-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyDLCollectionSecret
echo "Deleting normal secret, device lock confirmation required"
secrets-tool --test --delete-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyDLCollectionSecret
echo "Deleting collection, device lock confirmation required"
secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection

# clean up by killing the security UI
kill -9 $SECURITY_UI_PID
