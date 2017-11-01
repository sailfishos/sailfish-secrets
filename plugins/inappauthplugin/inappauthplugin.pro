TEMPLATE=lib
CONFIG+=plugin
TARGET=sailfishsecrets-inappauth
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../api/libsailfishsecrets/libsailfishsecrets.pri)

HEADERS+=plugin.h
SOURCES+=plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
