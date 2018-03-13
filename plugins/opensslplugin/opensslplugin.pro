TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishsecrets-openssl
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)

HEADERS += \
    $$PWD/../opensslcryptoplugin/evp_p.h \
    $$PWD/plugin.h
SOURCES += $$PWD/plugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
