TEMPLATE=subdirs

STORAGE_PLUGINS = \
    sqliteplugin

ENCRYPTION_PLUGINS = \
    opensslplugin

ENCRYPTEDSTORAGE_PLUGINS = \
    sqlcipherplugin

AUTHENTICATION_PLUGINS = \
    systemauthplugin \
    inappauthplugin

CRYPTO_PLUGINS = \
    opensslcryptoplugin \
    cryptokiplugin

SUBDIRS+=\
    $$STORAGE_PLUGINS \
    $$ENCRYPTION_PLUGINS \
    $$ENCRYPTEDSTORAGE_PLUGINS \
    $$AUTHENTICATION_PLUGINS \
    $$CRYPTO_PLUGINS \
    $$CRYPTOKI_PLUGINS \
    testplugins
