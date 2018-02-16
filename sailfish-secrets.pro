TEMPLATE = subdirs
SUBDIRS = lib qml daemon plugins tests 3rdparty

qml.depends = lib
daemon.depends = lib
plugins.depends = lib
tests.depends = lib

OTHER_FILES += \
    $$PWD/LICENSE \
    $$PWD/README \
    $$PWD/rpm/sailfish-secrets.spec
