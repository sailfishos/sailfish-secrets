TEMPLATE = lib
CONFIG += plugin
TARGET = sailfishsecrets-inappauth
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../lib/secrets/libsailfishsecrets.pri)

HEADERS += $$PWD/plugin.h
SOURCES += $$PWD/plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
