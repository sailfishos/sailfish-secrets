TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishsecrets-inappauth
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecretspluginapi.pri)

HEADERS += $$PWD/plugin.h
SOURCES += $$PWD/plugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
