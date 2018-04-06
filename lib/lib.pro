TEMPLATE = subdirs
SUBDIRS += \
    Secrets SecretsPluginApi $$PWD/Secrets/doc \
    Crypto CryptoPluginApi $$PWD/Crypto/doc

SecretsPluginApi.depends = Secrets
CryptoPluginApi.depends = Crypto
CryptoPluginApi.depends = SecretsPluginApi
