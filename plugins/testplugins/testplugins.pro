TEMPLATE=subdirs

STORAGE_PLUGINS = \
    testsqliteplugin

ENCRYPTION_PLUGINS = \
    testopensslplugin

ENCRYPTEDSTORAGE_PLUGINS = \
    testsqlcipherplugin

AUTHENTICATION_PLUGINS = \
    testinappauthplugin

CRYPTO_PLUGINS = \
    testopensslcryptoplugin

SUBDIRS+=\
    $$STORAGE_PLUGINS \
    $$ENCRYPTION_PLUGINS \
    $$ENCRYPTEDSTORAGE_PLUGINS \
    $$AUTHENTICATION_PLUGINS \
    $$CRYPTO_PLUGINS
