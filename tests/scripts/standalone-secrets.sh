#!/bin/sh

# This script must be run within a devel-su -p shell
# The daemon must be running in autotest mode (with --test option)

# Create standalone secrets
echo "Creating a standalone secret, user input required..."
secrets-tool --test --store-standalone-secret $1 org.sailfishos.secrets.plugin.storage.sqlite.test org.sailfishos.secrets.plugin.encryption.openssl.test BasicStandaloneSecret
# Create a standalone secret with predefined data
echo "Creating a standalone secret with predefined data..."
secrets-tool --test --store-standalone-secret $1 org.sailfishos.secrets.plugin.storage.sqlite.test org.sailfishos.secrets.plugin.encryption.openssl.test WithDataStandaloneSecret "This is data I'd like encrypted"

# List secrets <-- NOT YET IMPLEMENTED -->
# echo "Listing secrets..."
# secrets-tool --test --list-secrets org.sailfishos.secrets.plugin.storage.sqlite.test

# Read data in the secrets
echo "Reading data in standalone secret..."
secrets-tool --test --get-standalone-secret org.sailfishos.secrets.plugin.storage.sqlite.test BasicStandaloneSecret
echo "Reading pre-defined data in standalone secret..."
secrets-tool --test --get-standalone-secret org.sailfishos.secrets.plugin.storage.sqlite.test WithDataStandaloneSecret 

# Delete the secrets
echo "Deleting standalone secret..."
secrets-tool --test --delete-standalone-secret org.sailfishos.secrets.plugin.storage.sqlite.test BasicStandaloneSecret
echo "Deleting standalone secret with predefined data..."
secrets-tool --test --delete-standalone-secret org.sailfishos.secrets.plugin.storage.sqlite.test WithDataStandaloneSecret 
