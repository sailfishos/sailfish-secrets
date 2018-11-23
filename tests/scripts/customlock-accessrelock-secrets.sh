#!/bin/sh

# This script must be run within a devel-su -p shell
# The daemon must be running in autotest mode (with --test option)

# Create a collection and test secret store/read/delete
echo "Creating customlock access-relock collection MyCollection, user passphrase required..."
secrets-tool --test --create-collection --keep-unlocked org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection
echo "Storing normal secret, user input required..."
secrets-tool --test --store-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyCollectionSecret secretdata
echo "Reading normal secret"
secrets-tool --test --get-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyCollectionSecret
echo "Deleting normal secret"
secrets-tool --test --delete-collection-secret org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection MyCollectionSecret

# Clean up by deleting the collection
echo "Cleaning up - deleting MyCollection..."
secrets-tool --test --delete-collection org.sailfishos.secrets.plugin.encryptedstorage.sqlcipher.test MyCollection
