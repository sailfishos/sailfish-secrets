TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishsecrets-polkitauth
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)

HEADERS += \
    polkitplugin.h
SOURCES += \
    polkitplugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
