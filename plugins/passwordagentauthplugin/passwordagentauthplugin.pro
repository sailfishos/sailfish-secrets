TEMPLATE = lib
CONFIG += plugin hide_symbols
TARGET = sailfishsecrets-passwordagentauth
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/libsailfishsecrets.pri)

HEADERS += \
    passwordagentplugin.h
SOURCES += \
    passwordagentplugin.cpp

target.path=/usr/lib/Sailfish/Secrets/
INSTALLS += target
