TEMPLATE = subdirs
SUBDIRS = api daemon plugins tests

daemon.depends = api
plugins.depends = api
tests.depends = api

OTHER_FILES += \
    $$PWD/LICENSE \
    $$PWD/README \
    $$PWD/rpm/sailfish-secrets.spec
