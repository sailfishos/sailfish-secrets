TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-testopenssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/secrets/libsailfishsecrets.pri)

DEFINES += SAILFISH_SECRETS_BUILD_TEST_PLUGIN
HEADERS += $$PWD/../../opensslplugin/evp_p.h $$PWD/../../opensslplugin/plugin.h
SOURCES += $$PWD/../../opensslplugin/plugin.cpp

target.path=/usr/lib/sailfish/secrets/
INSTALLS += target
