#!/bin/sh

# The daemon must be running in autotest mode (with --test option)

# Create a collection
echo "Creating collection MyDLCollection with device lock protection"
secrets-tool --test --create-collection --devicelock org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection
echo "Storing normal secret, user input then device lock confirmation required"
secrets-tool --test --store-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyDLCollectionSecret
echo "Retrieving normal secret, device lock confirmation required"
secrets-tool --test --get-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyDLCollectionSecret
echo "Deleting normal secret, device lock confirmation required"
secrets-tool --test --delete-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection MyDLCollectionSecret
echo "Deleting collection, device lock confirmation required"
secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyDLCollection
