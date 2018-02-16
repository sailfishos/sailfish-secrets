TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-testopenssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../../common.pri)
include($$PWD/../../../lib/libsailfishsecrets.pri)

DEFINES += SAILFISHSECRETS_TESTPLUGIN

HEADERS += \
    $$PWD/../../../plugins/opensslplugin/evp_p.h \
    $$PWD/../../../plugins/opensslplugin/plugin.h

SOURCES += \
    $$PWD/../../../plugins/opensslplugin/plugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
