TEMPLATE=lib
CONFIG+=plugin
TARGET=sailfishsecrets-sqlite
TARGET = $$qtLibraryTarget($$TARGET)

include($$PWD/../../common.pri)
include($$PWD/../../api/libsailfishsecrets/libsailfishsecrets.pri)

HEADERS+=database_p.h plugin.h
SOURCES+=database.cpp plugin.cpp

target.path=/usr/lib/sailfishsecrets/
INSTALLS += target
