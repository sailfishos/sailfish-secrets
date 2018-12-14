TEMPLATE = subdirs

SUBDIRS += \
    Secrets \
    SecretsPluginApi \
    SecretsDocs \
    Crypto \
    CryptoPluginApi \
    CryptoDocs \
    SecretsCrypto # C-API

Secrets.subdir = $$PWD/Secrets
SecretsPluginApi.subdir = $$PWD/Secrets/Plugins
SecretsDocs.subdir = $$PWD/Secrets/doc

Crypto.subdir = $$PWD/Crypto
CryptoPluginApi.subdir = $$PWD/Crypto/Plugins
CryptoDocs.subdir = $$PWD/Crypto/doc

SecretsPluginApi.depends = Secrets
CryptoPluginApi.depends = Crypto
CryptoPluginApi.depends = SecretsPluginApi
